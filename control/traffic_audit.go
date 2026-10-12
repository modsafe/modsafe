package main

// 流量审计（#70/#71）：回答"某用户访问了哪些 IP/端口/服务/域名"。
// 数据源 = 双节点 /proc/net/nf_conntrack（agent 转发）中 VPN 源（10.8/16 ∪ fdaa:2026:192::/48）
// 的活跃连接流；控制面每 30s 轮询一次，按流键 (src,dst,proto,port) 做字节增量，
// 经 sessions.virtual_ip→username 归属后写入 flow_daily 聚合表；flow_live 保存最近一次快照。
// 域名维度（#71，用户批准推送 DNS）：双节点 dnsmasq（隧道网关）查询日志 → dns_queries 表
// + ip→domain 映射，连接流按目的 IP 标注最近查询的域名。

import (
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type flowEntry struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Bytes int64  `json:"bytes"`
}

type flowSnapshot map[string]int64 // key = node|src|dst|proto|port → bytes 累计值

var (
	flowMu       sync.Mutex
	flowPrev     flowSnapshot
	flowLastPoll time.Time

	// 流首现/最近活动（#73：内存追踪；控制面重启后首现时间重置为重启后首次可见）
	flowMeta = map[string]flowMetaInfo{}

	// DNS 域名维度（#71）：dnsmasq 查询/应答日志 → ip→domain 最近映射（供连接流标注）
	dnsMu   sync.Mutex
	ip2dom  = map[string]domEntry{}
	dnsSeen = map[string]bool{} // (ts|src|domain|qtype) 去重
)

type flowMetaInfo struct {
	First time.Time
	Last  time.Time
}

type domEntry struct {
	domain string
	at     time.Time
}

func rememberIPDomain(ip, domain string) {
	if ip == "" || domain == "" || strings.HasPrefix(domain, "_") {
		return
	}
	dnsMu.Lock()
	ip2dom[ip] = domEntry{domain: domain, at: time.Now()}
	// 惰性清理 24h 前的旧映射
	if len(ip2dom) > 20000 {
		cut := time.Now().Add(-24 * time.Hour)
		for k, v := range ip2dom {
			if v.at.Before(cut) {
				delete(ip2dom, k)
			}
		}
	}
	dnsMu.Unlock()
}

func domainForIP(ip string) string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if e, ok := ip2dom[ip]; ok {
		return e.domain
	}
	return ""
}

func flowKey(node string, f flowEntry) string {
	return node + "|" + f.Src + "|" + f.Dst + "|" + f.Proto + "|" + strconv.Itoa(f.Port)
}

// parseProcConntrack：直接解析本机 /proc/net/nf_conntrack（180 本地路径）
func parseProcConntrack() []flowEntry {
	raw, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		return nil
	}
	return parseConntrackLines(string(raw))
}

func parseConntrackLines(text string) []flowEntry {
	out := []flowEntry{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, " src=") {
			continue
		}
		isV6 := strings.HasPrefix(line, "ipv6")
		var src, dst, proto string
		var dport int
		var total int64
		firstSrc := false
		for _, kv := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(kv, "src="):
				if !firstSrc {
					src = kv[4:]
					firstSrc = true
				}
			case strings.HasPrefix(kv, "dst=") && dst == "":
				dst = kv[4:]
			case strings.HasPrefix(kv, "dport=") && dport == 0:
				dport, _ = strconv.Atoi(kv[6:])
			case strings.HasPrefix(kv, "bytes="):
				if v, err := strconv.ParseInt(kv[6:], 10, 64); err == nil {
					total += v
				}
			case strings.HasPrefix(kv, "protocol=") && isV6:
				proto = kv[9:]
			}
		}
		if src == "" || dst == "" {
			continue
		}
		if !strings.HasPrefix(src, "10.8.") && !strings.HasPrefix(src, "fdaa:2026:192:") {
			continue
		}
		if proto == "" {
			fields := strings.Fields(line)
			if len(fields) > 2 {
				proto = fields[2]
			}
		}
		out = append(out, flowEntry{Src: src, Dst: dst, Proto: proto, Port: dport, Bytes: total})
	}
	return out
}

// parseDNSLogLines：解析 dnsmasq 查询日志行 → (ts, src, domain, qtype) + ip→domain 映射。
// 行格式：Oct  2 13:21:39 dnsmasq[672786]: query[A] qq.com from 10.8.0.1
//        Oct  2 13:21:39 dnsmasq[672786]: reply qq.com is 113.108.81.189（cached 前缀同构）
func parseDNSLogLines(text string) [][4]string {
	out := [][4]string{}
	year := strconv.Itoa(time.Now().Year())
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, "dnsmasq")
		if i < 0 {
			continue
		}
		body := line[i:]
		tsRaw := ""
		if m := reDnsTs.FindStringSubmatch(line[:i]); m != nil {
			tsRaw = m[1]
		}
		var ts string
		if t, err := time.Parse("Jan _2 15:04:05", tsRaw); err == nil {
			ts = year + "-" + t.Format("01-02 15:04:05")
		} else {
			ts = time.Now().Format("2006-01-02 15:04:05")
		}
		if m := reDnsQuery.FindStringSubmatch(body); m != nil {
			qtype, domain, src := m[1], m[2], m[3]
			if !strings.HasPrefix(src, "10.8.") && !strings.HasPrefix(src, "fdaa:2026:192:") {
				continue
			}
			out = append(out, [4]string{ts, src, domain, qtype})
		}
		if m := reDnsReply.FindStringSubmatch(body); m != nil {
			domain, ip := m[1], m[2]
			if net.ParseIP(ip) != nil {
				rememberIPDomain(ip, domain)
			}
		}
	}
	return out
}

var (
	reDnsTs    = regexp.MustCompile(`([A-Z][a-z]{2}\s+\d?\d \d\d:\d\d:\d\d)`)
	reDnsQuery = regexp.MustCompile(`query\[([A-Za-z]*)\]\s+(\S+)\s+from\s+(\S+)`)
	reDnsReply = regexp.MustCompile(`(?:reply|cached)\s+(\S+)\s+is\s+([0-9a-fA-F:.]+)$`)
)

// pollDNSLog：一轮 DNS 日志采集（本地直读 + agent /dnslog）→ 去重入库
func (a *App) pollDNSLog() {
	text := ""
	if raw, err := os.ReadFile(envOr("MODSAFE_DNSMASQ_LOG", "/var/log/dnsmasq-queries.log")); err == nil {
		text = string(raw)
	}
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		out, err := agentRequest(nodes[i], "GET", "/dnslog?n=800", nil)
		if err != nil {
			log.Printf("[flow-audit] agent /dnslog 失败: %v", err)
			continue
		}
		if lines, ok := out["lines"].([]interface{}); ok {
			for _, l := range lines {
				text += s(l) + "\n"
			}
		}
	}
	rows := parseDNSLogLines(text)
	if len(rows) == 0 {
		return
	}
	dnsMu.Lock()
	newRows := [][4]string{}
	for _, r := range rows {
		dk := r[0] + "|" + r[1] + "|" + r[2] + "|" + r[3]
		if !dnsSeen[dk] {
			dnsSeen[dk] = true
			newRows = append(newRows, r)
		}
	}
	// 去重表防膨胀（保留最近 20 万键）
	if len(dnsSeen) > 200000 {
		dnsSeen = map[string]bool{}
		for _, r := range rows {
			dnsSeen[r[0]+"|"+r[1]+"|"+r[2]+"|"+r[3]] = true
		}
	}
	dnsMu.Unlock()
	for _, r := range newRows {
		_, _ = a.db.Exec(`INSERT OR IGNORE INTO dns_queries(ts, src, domain, qtype) VALUES(?,?,?,?)`,
			r[0], r[1], r[2], r[3])
	}
}
// srcInfo：virtual_ip → 用户名 + 接入来源 IP（一次查询双字段；在线会话优先）
func (a *App) srcInfo(src string) (string, string) {
	if strings.Contains(src, ":") {
		return "(IPv6)", ""
	}
	var username, trusted string
	err := a.db.QueryRow(`SELECT username, COALESCE(trusted_ip,'') FROM sessions WHERE virtual_ip=?
		ORDER BY settled ASC, cid DESC LIMIT 1`, src).Scan(&username, &trusted)
	if err != nil || username == "" {
		return "(" + src + ")", ""
	}
	return username, trusted
}

// collectFlowsOnce：一轮采集（本地 /proc + agent /flows）→ 增量聚合入 flow_daily + 刷新 flow_live
func (a *App) collectFlowsOnce() {
	flowMu.Lock()
	defer flowMu.Unlock()

	cur := flowSnapshot{}
	live := []map[string]interface{}{}
	now := time.Now().Format("2006-01-02 15:04:05")

	appendFlows := func(node string, flows []flowEntry) {
		for _, f := range flows {
			k := flowKey(node, f)
			cur[k] = f.Bytes
			// 流首现/最近活动追踪（#73：回答"什么时候访问的"）
			nowT := time.Now()
			if meta, ok := flowMeta[k]; ok {
				flowMeta[k] = flowMetaInfo{First: meta.First, Last: nowT}
			} else {
				flowMeta[k] = flowMetaInfo{First: nowT, Last: nowT}
			}
			meta := flowMeta[k]
			user, trusted := a.srcInfo(f.Src)
			live = append(live, map[string]interface{}{
				"node": node, "src": f.Src, "dst": f.Dst, "proto": f.Proto,
				"port": f.Port, "bytes": f.Bytes,
				"username": user, "trusted_ip": trusted,
				"domain": domainForIP(f.Dst),
				"first_seen": meta.First.Format("2006-01-02 15:04:05"),
				"last_seen":  meta.Last.Format("2006-01-02 15:04:05"),
			})
		}
	}
	appendFlows("node-1", parseProcConntrack())
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		out, err := agentRequest(nodes[i], "GET", "/flows", nil)
		if err != nil {
			log.Printf("[flow-audit] agent /flows 失败: %v", err)
			continue
		}
		var arr []flowEntry
		if raw, ok := out["flows"].([]interface{}); ok {
			for _, it := range raw {
				m, ok := it.(map[string]interface{})
				if !ok {
					continue
				}
				p, _ := m["port"].(float64)
				b, _ := m["bytes"].(float64)
				arr = append(arr, flowEntry{
					Src: s(m["src"]), Dst: s(m["dst"]), Proto: s(m["proto"]),
					Port: int(p), Bytes: int64(b),
				})
			}
		}
		appendFlows(nodes[i].Name, arr)
	}

	// 增量：cur - prev（负数=新条目/计数重置，按当前值计）
	day := time.Now().Format("2006-01-02")
	type aggKey struct {
		user, dst, proto string
		port             int
	}
	agg := map[aggKey]int64{}
	for k, curBytes := range cur {
		parts := strings.SplitN(k, "|", 5)
		if len(parts) != 5 {
			continue
		}
		src := parts[1]
		var delta int64
		if prevBytes, ok := flowPrev[k]; ok && curBytes >= prevBytes {
			delta = curBytes - prevBytes
		} else {
			delta = curBytes
		}
		if delta <= 0 {
			continue
		}
		port := 0
		if p, err := strconv.Atoi(parts[4]); err == nil {
			port = p
		}
		user, _ := a.srcInfo(src)
		ak := aggKey{user: user, dst: parts[2], proto: parts[3], port: port}
		agg[ak] += delta
	}
	for ak, bytes := range agg {
		dom := domainForIP(ak.dst)
		_, _ = a.db.Exec(`INSERT INTO flow_daily(username, day, dst, port, proto, bytes, conns, domain, last_seen)
			VALUES(?,?,?,?,?,?,1,?,?)
			ON CONFLICT(username,day,dst,port,proto)
			DO UPDATE SET bytes=bytes+?, conns=conns+1,
				domain=CASE WHEN excluded.domain!='' THEN excluded.domain ELSE flow_daily.domain END,
				last_seen=excluded.last_seen`,
			ak.user, day, ak.dst, ak.port, ak.proto, bytes, dom, now, bytes, now)
	}

	// flow_live 全量替换（连接流按目的 IP 标注最近查询的域名——#71 域名维度；时间列 #73）
	_, _ = a.db.Exec(`DELETE FROM flow_live`)
	for _, r := range live {
		b, _ := r["bytes"].(int64)
		p, _ := r["port"].(int)
		g, _ := r["domain"].(string)
		fs, _ := r["first_seen"].(string)
		ls, _ := r["last_seen"].(string)
		tp, _ := r["trusted_ip"].(string)
		_, _ = a.db.Exec(`INSERT INTO flow_live(node, src, dst, proto, port, bytes, username, domain, first_seen, last_seen, trusted_ip)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			r["node"], r["src"], r["dst"], r["proto"], p, b, r["username"], g, fs, ls, tp)
	}

	a.pollDNSLog() // DNS 查询日志采集（每轮顺带）
	flowPrev = cur
	flowLastPoll = time.Now()
}

func s(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// startFlowCollector：30s 周期采集（随控制面启动；flowMu 保证串行）
func (a *App) startFlowCollector() {
	go func() {
		time.Sleep(10 * time.Second) // 等网络/agent 就绪
		for {
			a.collectFlowsOnce()
			time.Sleep(30 * time.Second)
		}
	}()
	log.Printf("[flow-audit] 采集器已启动（30s 周期）")
}

// handleAuditFlows：GET /api/v1/monitor/audit/flows —— 实时连接（flow_live，含域名/时间/接入来源）
func (a *App) handleAuditFlows(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT node, src, dst, proto, port, bytes, username,
		COALESCE(domain,''), COALESCE(first_seen,''), COALESCE(last_seen,''), COALESCE(trusted_ip,'')
		FROM flow_live ORDER BY bytes DESC LIMIT 500`)
	if err != nil {
		failSystem(w, r, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var node, src, dst, proto, username, domain, firstSeen, lastSeen, trusted string
		var port int
		var bytes int64
		if rows.Scan(&node, &src, &dst, &proto, &port, &bytes, &username, &domain, &firstSeen, &lastSeen, &trusted) == nil {
			list = append(list, map[string]interface{}{
				"node": node, "src": src, "dst": dst, "proto": proto,
				"port": port, "bytes": bytes, "username": username, "domain": domain,
				"first_seen": firstSeen, "last_seen": lastSeen, "trusted_ip": trusted,
			})
		}
	}
	writeOK(w, r, map[string]interface{}{"list": list, "polled_at": flowLastPoll.Format("15:04:05")})
}

// handleAuditDNS：GET /api/v1/monitor/audit/dns?username=&limit= —— 最近 DNS 查询（含用户归属）
func (a *App) handleAuditDNS(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	limit := 80
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	q := `SELECT d.ts, d.src, d.domain, d.qtype, COALESCE(u.username, '') FROM dns_queries d
		LEFT JOIN users u ON u.username = (SELECT username FROM sessions WHERE virtual_ip = d.src
			ORDER BY settled ASC, cid DESC LIMIT 1)
		ORDER BY d.ts DESC, d.rowid DESC LIMIT ?`
	args := []interface{}{limit}
	if username != "" {
		q = `SELECT d.ts, d.src, d.domain, d.qtype, COALESCE(u.username, '') FROM dns_queries d
			LEFT JOIN users u ON u.username = (SELECT username FROM sessions WHERE virtual_ip = d.src
				ORDER BY settled ASC, cid DESC LIMIT 1)
			WHERE u.username = ?
			ORDER BY d.ts DESC, d.rowid DESC LIMIT ?`
		args = []interface{}{username, limit}
	}
	rows, err := a.db.Query(q, args...)
	if err != nil {
		failSystem(w, r, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var ts, src, domain, qtype, user string
		if rows.Scan(&ts, &src, &domain, &qtype, &user) == nil {
			list = append(list, map[string]interface{}{
				"ts": ts, "src": src, "domain": domain, "qtype": qtype, "username": user,
			})
		}
	}
	writeOK(w, r, map[string]interface{}{"list": list})
}

// handleAuditHistory：GET /api/v1/monitor/audit/history?range=today|7d&username=&limit=
// 按目的聚合（flow_daily）；顺带返回 Top 用户
func (a *App) handleAuditHistory(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng != "7d" {
		rng = "today"
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	dayCond := "day = ?"
	arg := time.Now().Format("2006-01-02")
	if rng == "7d" {
		dayCond = "day >= ?"
		arg = time.Now().AddDate(0, 0, -6).Format("2006-01-02")
	}

	where := "WHERE " + dayCond
	args := []interface{}{arg}
	if username != "" {
		where += " AND username = ?"
		args = append(args, username)
	}

	rows, err := a.db.Query(`SELECT username, dst, port, proto, SUM(bytes) b, SUM(conns) c,
		MAX(COALESCE(domain,'')), MAX(COALESCE(last_seen,''))
		FROM flow_daily `+where+` GROUP BY username, dst, port, proto ORDER BY b DESC LIMIT `+strconv.Itoa(limit), args...)
	if err != nil {
		failSystem(w, r, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var user, dst, proto, domain, lastSeen string
		var port int
		var b, ccount int64
		if rows.Scan(&user, &dst, &port, &proto, &b, &ccount, &domain, &lastSeen) == nil {
			list = append(list, map[string]interface{}{
				"username": user, "dst": dst, "port": port, "proto": proto,
				"bytes": b, "conns": ccount, "domain": domain, "last_seen": lastSeen,
			})
		}
	}

	// Top 用户
	rows2, err := a.db.Query(`SELECT username, SUM(bytes) FROM flow_daily `+where+`
		GROUP BY username ORDER BY 2 DESC LIMIT 10`, args...)
	if err == nil {
		defer rows2.Close()
		top := []map[string]interface{}{}
		for rows2.Next() {
			var u string
			var b int64
			if rows2.Scan(&u, &b) == nil {
				top = append(top, map[string]interface{}{"username": u, "bytes": b})
			}
		}
		writeOK(w, r, map[string]interface{}{"list": list, "top_users": top, "range": rng})
		return
	}
	writeOK(w, r, map[string]interface{}{"list": list, "range": rng})
}

// portService：常见端口→服务名（前端展示辅助；此处提供后端统一映射）
var wellKnownPorts = map[int]string{
	22: "SSH", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
	445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
	3389: "RDP", 5228: "Google Push", 5432: "PostgreSQL", 6379: "Redis",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9092: "Kafka", 27017: "MongoDB",
}

func portServiceName(port int) string {
	if n, ok := wellKnownPorts[port]; ok {
		return n
	}
	return ""
}
