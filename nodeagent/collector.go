package main

// collector 角色：modsafe-monitor-collector.py 的 Go 移植（180, :7505）。
// 每 30s 采集 node-1（本机 status log）/ node-2（193 agent /metrics）/ nginx / 证书到期，
// 写 SQLite monitor.db（metrics/alerts/sessions，schema 与 Python 版一致），
// 告警（节点宕机连续 3 次 / 证书 <30 天 / nginx 宕机，同 key 冷却 60min），
// 会话结算：tail /var/log/modsafe-session.log 的 DISCONNECT 行（inode+size 双判轮转）。
// API：GET /summary、GET /history?hours=、GET /sessions（modsafe-control collector.go 代理消费）。

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// 测试可覆盖的路径（生产值；安装器 v2 经 modsafe.env 注入归一布局）
var (
	monitorDB   = envPath("MODSAFE_MONITOR_DB", "/opt/modsafe/monitor.db")
	sessionLog  = envPath("MODSAFE_SESSION_LOG", "/var/log/modsafe-session.log")
	statusLog1  = envPath("MODSAFE_STATUS_LOG1", "/var/log/status-node1.log")
	agent193    = envOr("NODE_AGENT_193", "")
	// MODSAFE_CLUSTER_MODE=0 → 单机版：不探测 node-2（免每 30s agent error 噪音）；缺省 1=集群
	// clusterMode=1 但未配置 NODE_AGENT_193 时同样跳过（未配置≠故障，不制造噪音）
	clusterMode = envOr("MODSAFE_CLUSTER_MODE", "1") == "1" && agent193 != ""
)

const (
	collectSecs = 30
)

var collectorCerts = []string{
	envPath("MODSAFE_SERVER_CERT", "/root/modsafe-pki2/server.crt"),
	envPath("MODSAFE_CA_CERT", "/root/modsafe-pki2/ca.crt"),
}

var (
	cdb     *sql.DB
	alertMu sync.Mutex
	// key -> 最近一次实际通知时间（同 key 冷却 60min，防重复轰炸；重启归零与 Python 一致）
	alertLast = map[string]int64{}
)

func initDB() error {
	var err error
	cdb, err = sql.Open("sqlite", monitorDB)
	if err != nil {
		return err
	}
	cdb.SetMaxOpenConns(1) // SQLite 单写者：串行化避免 API 读与采集写互撞 SQLITE_BUSY
	schema := `
CREATE TABLE IF NOT EXISTS metrics(
  ts INTEGER, node TEXT, active INTEGER, online INTEGER,
  bytes_rx INTEGER, bytes_tx INTEGER);
CREATE TABLE IF NOT EXISTS alerts(
  ts INTEGER, level TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS sessions(
  ts INTEGER, common_name TEXT, trusted_ip TEXT, vpn_ip TEXT,
  bytes_received INTEGER, bytes_sent INTEGER, duration INTEGER);
`
	_, err = cdb.Exec(schema)
	return err
}

func dbExec(sql_ string, args ...any) error {
	_, err := cdb.Exec(sql_, args...)
	return err
}

// ---- 告警（落库 + 冷却后 notify_all） ----

func alert(level, message string, key ...string) {
	k := message
	if len(key) > 0 && key[0] != "" {
		k = key[0]
	}
	_ = dbExec("INSERT INTO alerts(ts,level,message) VALUES(?,?,?)", nowUnix(), level, message)
	alertMu.Lock()
	defer alertMu.Unlock()
	if nowUnix()-alertLast[k] < 3600 {
		logf("ALERT-SUPPRESSED[%s]: %s", level, message) // 已通知过，仅落库
		return
	}
	alertLast[k] = nowUnix()
	logf("ALERT[%s]: %s", level, message)
	results := notifyAll(level, message, nowUnix())
	logf("告警投递[%s]: %v", level, results)
}

// certDaysLeft：直接 x509 解析（替代 Python 的 openssl 子进程），delta.days 语义=向下取整
func certDaysLeft(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return -1
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return -1
	}
	d := time.Until(crt.NotAfter).Hours() / 24
	days := int(d)
	if d < 0 && float64(days) != d {
		days-- // 向下取整（Python timedelta.days 语义）
	}
	return days
}

// ---- 采集 ----

// parseStatusFile：与 Python 版同口径——CLIENT_LIST 行取第 6/7 列（tab 分隔）为 rx/tx
func parseStatusFile(path string) (online, rx, tx int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CLIENT_LIST\t") {
			continue
		}
		p := strings.Split(line, "\t")
		online++
		if len(p) > 6 {
			if v, err := strconv.Atoi(strings.TrimSpace(p[5])); err == nil {
				rx += v
			}
			if v, err := strconv.Atoi(strings.TrimSpace(p[6])); err == nil {
				tx += v
			}
		}
	}
	return
}

func certAlerts() {
	for _, cert := range collectorCerts {
		days := certDaysLeft(cert)
		base := cert[strings.LastIndex(cert, "/")+1:]
		key := "cert:" + base
		var prev string
		_ = cdb.QueryRow("SELECT message FROM alerts WHERE message LIKE ? ORDER BY ts DESC LIMIT 1",
			"%"+key+"%").Scan(&prev)
		if days >= 0 && days < 30 && !strings.Contains(prev, fmt.Sprintf("剩余%d天", days)) {
			alert("warn", fmt.Sprintf("%s 即将到期：剩余%d天（%s）", key, days, cert))
		}
	}
}

func collectOnce() map[string]map[string]any {
	ts := nowUnix()
	states := map[string]map[string]any{}

	// node-1（本机）
	st1 := svcActive("openvpn-modsafe@1")
	active1 := 0
	if st1 == "active" {
		active1 = 1
	}
	on1, rx1, tx1 := parseStatusFile(statusLog1)
	states["node-1@180"] = map[string]any{"active": active1, "online": on1, "bytes_rx": rx1, "bytes_tx": tx1}
	_ = dbExec("INSERT INTO metrics(ts,node,active,online,bytes_rx,bytes_tx) VALUES(?,?,?,?,?,?)",
		ts, "node-1@180", active1, on1, rx1, tx1)

	// node-2（193 agent；单机模式 MODSAFE_CLUSTER_MODE=0 跳过）
	active2, on2, rx2, tx2 := 0, 0, 0, 0
	if clusterMode {
		if m, err := httpGetJSON(agent193+"/metrics", 8*time.Second); err == nil {
			if mStr(m, "service") == "active" {
				active2 = 1
			}
			on2, rx2, tx2 = int(mF64(m, "online")), int(mF64(m, "bytes_rx")), int(mF64(m, "bytes_tx"))
			// #166（2026-10-11）：node-2 的 dnsmasq 远端活性（新版 agent /metrics 带 dns 字段；
			// 旧版 agent 无此字段=跳过，不误告警）
			if dns, ok := m["dns"].(string); ok && dns != "active" {
				alert("critical", "node-2 DNS（dnsmasq）不可用：VPN 客户端域名解析断供", "down:dnsmasq-node2")
			}
		} else {
			logf("node-2 agent error: %v", err)
		}
	}
	states["node-2@193"] = map[string]any{"active": active2, "online": on2, "bytes_rx": rx2, "bytes_tx": tx2}
	_ = dbExec("INSERT INTO metrics(ts,node,active,online,bytes_rx,bytes_tx) VALUES(?,?,?,?,?,?)",
		ts, "node-2@193", active2, on2, rx2, tx2)

	// 节点宕机告警（连续 3 次 = 90s；node-2 仅集群模式）
	var down1, down2 int
	_ = cdb.QueryRow("SELECT COUNT(*) FROM metrics WHERE node='node-1@180' AND active=0 AND ts>?",
		ts-100).Scan(&down1)
	_ = cdb.QueryRow("SELECT COUNT(*) FROM metrics WHERE node='node-2@193' AND active=0 AND ts>?",
		ts-100).Scan(&down2)
	if down1 >= 3 {
		alert("critical", fmt.Sprintf("节点 node-1@180 不可用（连续 %d 次探测失败）", down1), "down:node-1")
	}
	if down2 >= 3 && clusterMode {
		alert("critical", fmt.Sprintf("节点 node-2@193 不可用（连续 %d 次探测失败）", down2), "down:node-2")
	}
	if svcActive("nginx") != "active" {
		alert("critical", "LB（nginx）不可用", "down:nginx")
	}
	// #166（2026-10-11）：dnsmasq 宕机曾静默五天（VPN 客户端全部域名解析断供而零告警），
	// 与 nginx 同级的关键路径，纳入采集告警
	if svcActive("dnsmasq") != "active" {
		alert("critical", "DNS（dnsmasq）不可用：VPN 客户端域名解析断供", "down:dnsmasq")
	}
	certAlerts() // 证书 <30 天到期告警（头注释承诺的职责，此前定义后从未被调用）
	return states
}

// ---- 会话结算 tail（断开结算；轮转按 inode+size 双判） ----

var sessionLineRe = regexp.MustCompile(
	`(?:username=(\S*) )?common_name=(\S*) trusted_ip=(\S*) .*` +
		`bytes_received=(\d+) bytes_sent=(\d+) duration=(\d+)`)

func collectSessionsLoop() {
	pos, ino := map[string]int64{}, map[string]uint64{}
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logf("[session-loop] panic: %v", r)
				}
			}()
			st, err := os.Stat(sessionLog)
			if err != nil {
				return
			}
			size, fino := st.Size(), fileIno(st)
			p := pos[sessionLog]
			prevIno, hasIno := ino[sessionLog]
			if size < p || (hasIno && fino != prevIno) {
				p = 0 // 日志轮转（rotate/copytruncate）
			}
			ino[sessionLog] = fino
			f, err := os.Open(sessionLog)
			if err != nil {
				return
			}
			if _, err := f.Seek(p, 0); err != nil {
				f.Close()
				return
			}
			var rows [][]any
			buf := make([]byte, 0, 1<<16)
			chunk := make([]byte, 8192)
			for {
				n, err := f.Read(chunk)
				if n > 0 {
					buf = append(buf, chunk[:n]...)
				}
				if err != nil || n == 0 {
					break
				}
			}
			f.Close()
			for _, line := range strings.Split(string(buf), "\n") {
				if !strings.Contains(line, "DISCONNECT") {
					continue
				}
				if mm := sessionLineRe.FindStringSubmatch(line); mm != nil {
					user := mm[1]
					if user == "" {
						user = mm[2]
					}
					rx, _ := strconv.Atoi(mm[4])
					tx, _ := strconv.Atoi(mm[5])
					dur, _ := strconv.Atoi(mm[6])
					rows = append(rows, []any{nowUnix(), user, mm[3], "", rx, tx, dur})
				}
			}
			pos[sessionLog] = p + int64(len(buf))
			for _, row := range rows { // 批量入库
				_ = dbExec("INSERT INTO sessions(ts,common_name,trusted_ip,vpn_ip,"+
					"bytes_received,bytes_sent,duration) VALUES(?,?,?,?,?,?,?)", row...)
			}
		}()
		time.Sleep(30 * time.Second)
	}
}

func collectLoop() {
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logf("collect panic: %v", r)
				}
			}()
			collectOnce()
		}()
		time.Sleep(collectSecs * time.Second)
	}
}

// ---- HTTP API（:7505） ----

func collectorAPI() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /summary", func(w http.ResponseWriter, r *http.Request) {
		latest := map[string]any{}
		for _, node := range []string{"node-1@180", "node-2@193"} {
			var ts, active, online, brx, btx int64
			row := cdb.QueryRow("SELECT ts,active,online,bytes_rx,bytes_tx FROM metrics "+
				"WHERE node=? ORDER BY ts DESC LIMIT 1", node)
			if err := row.Scan(&ts, &active, &online, &brx, &btx); err == nil {
				latest[node] = map[string]any{
					"ts": ts, "active": active, "online": online,
					"bytes_rx": brx, "bytes_tx": btx,
					"bytes_rx_h": fmt.Sprintf("%.1fMB", float64(brx)/1048576),
					"bytes_tx_h": fmt.Sprintf("%.1fMB", float64(btx)/1048576),
				}
			}
		}
		alerts := []map[string]any{}
		rows, err := cdb.Query("SELECT ts,level,message FROM alerts ORDER BY ts DESC LIMIT 20")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ts int64
				var level, message string
				if rows.Scan(&ts, &level, &message) == nil {
					alerts = append(alerts, map[string]any{"ts": ts, "level": level, "message": message})
				}
			}
		}
		certs := []map[string]any{}
		for _, cert := range collectorCerts {
			days := certDaysLeft(cert)
			status := "ok"
			if days <= 30 {
				status = "expiring"
			}
			if days < 0 {
				status = "error"
			}
			certs = append(certs, map[string]any{
				"file": cert[strings.LastIndex(cert, "/")+1:], "days_left": days, "status": status})
		}
		writeJSON(w, 200, map[string]any{
			"ts": nowUnix(), "nodes": latest, "nginx_active": svcActive("nginx"),
			"certs": certs, "recent_alerts": alerts})
	})
	mux.HandleFunc("GET /history", func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if v := r.URL.Query().Get("hours"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				hours = n
			}
		}
		if hours < 1 || hours > 24*30 {
			hours = 24
		}
		points := []map[string]any{}
		rows, err := cdb.Query("SELECT ts,node,active,online,bytes_rx,bytes_tx FROM metrics "+
			"WHERE ts>? ORDER BY ts", nowUnix()-int64(hours)*3600)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ts, active, online, brx, btx int64
				var node string
				if rows.Scan(&ts, &node, &active, &online, &brx, &btx) == nil {
					points = append(points, map[string]any{"ts": ts, "node": node,
						"active": active, "online": online, "bytes_rx": brx, "bytes_tx": btx})
				}
			}
		}
		writeJSON(w, 200, map[string]any{"points": points})
	})
	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		sessions := []map[string]any{}
		rows, err := cdb.Query("SELECT ts,common_name,trusted_ip,vpn_ip,bytes_received,bytes_sent,duration " +
			"FROM sessions ORDER BY ts DESC LIMIT 100")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ts, brx, btx, dur int64
				var cn, tip, vip string
				if rows.Scan(&ts, &cn, &tip, &vip, &brx, &btx, &dur) == nil {
					sessions = append(sessions, map[string]any{"ts": ts, "user": cn,
						"real_ip": tip, "vpn_ip": vip, "bytes_rx": brx, "bytes_tx": btx, "duration_s": dur})
				}
			}
		}
		writeJSON(w, 200, map[string]any{"sessions": sessions})
	})
	return mux
}

func runCollector() {
	NOTIFY_ALLOW_PRIV = os.Getenv("MODSAFE_NOTIFY_ALLOW_PRIVATE") == "1"
	if err := initDB(); err != nil {
		logf("monitor.db init FAILED: %v", err)
		os.Exit(1)
	}
	logf("modsafe-monitor-collector starting (interval %ds, API :7505)", collectSecs)
	go collectSessionsLoop()
	go collectLoop()
	srv := &http.Server{Addr: ":7505", Handler: collectorAPI(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logf("listen: %v", err)
	}
}
