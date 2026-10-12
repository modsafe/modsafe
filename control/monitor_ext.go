package main

// 监控中心扩展（§12.2）：节点状态 + 流量看板。
// 数据源：collector /summary+/history（附录A 采集器）、liveSessions 实时快照、sessions 台账。
// collector 不可用时节点骨架仍返回（liveSessions 不依赖 collector），并置 collector_alive=false 供前端提示。

import (
	"math"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// directorVIP：keepalived 管理的虚拟服务地址；经 env 配置（不内置部署地址），
// 未配置时 VIP 视角探测返回"未配置"而非误判
var directorVIP = envOr("MODSAFE_DIRECTOR_VIP", "")

// handleMonitorNodes：节点状态页（快照 + 实时会话数 + 本机 director 视角）
func (a *App) handleMonitorNodes(w http.ResponseWriter, r *http.Request) {
	liveByNode := map[string]int{}
	for _, s := range liveSessions() {
		if n, _ := s["node"].(string); n != "" {
			liveByNode[n]++
		}
	}

	type nodeState struct {
		Name       string `json:"name"`
		Host       string `json:"host"`
		Active     bool   `json:"active"`
		Online     int    `json:"online"`
		LiveOnline int    `json:"live_online"`
		BytesRx    int64  `json:"bytes_rx"`
		BytesTx    int64  `json:"bytes_tx"`
		DataAgeSec int64  `json:"data_age_seconds"`
	}
	outNodes := []nodeState{}
	alerts := []map[string]interface{}{}
	certs := []map[string]interface{}{}
	collectorOK := false
	if summ, err := collectorGet("/summary"); err == nil {
		collectorOK = true
		if m, _ := summ["nodes"].(map[string]interface{}); m != nil {
			for key, raw := range m {
				nm, _ := raw.(map[string]interface{})
				name, host := key, ""
				if i := strings.Index(key, "@"); i > 0 {
					name, host = key[:i], key[i+1:]
				}
				ts, _ := nm["ts"].(float64)
				act, _ := nm["active"].(float64)
				online, _ := nm["online"].(float64)
				rx, _ := nm["bytes_rx"].(float64)
				tx, _ := nm["bytes_tx"].(float64)
				outNodes = append(outNodes, nodeState{
					Name: name, Host: host, Active: int(act) == 1,
					Online: int(online), LiveOnline: liveByNode[name],
					BytesRx: int64(rx), BytesTx: int64(tx),
					DataAgeSec: time.Now().Unix() - int64(ts),
				})
			}
		}
		for _, key := range []string{"recent_alerts", "certs"} {
			arr, _ := summ[key].([]interface{})
			for _, raw := range arr {
				if m, ok := raw.(map[string]interface{}); ok {
					if key == "recent_alerts" {
						alerts = append(alerts, m)
					} else {
						certs = append(certs, m)
					}
				}
			}
		}
	}
	if len(outNodes) == 0 {
		for _, n := range nodes {
			outNodes = append(outNodes, nodeState{Name: n.Name, LiveOnline: liveByNode[n.Name]})
		}
	}
	sort.Slice(outNodes, func(i, j int) bool { return outNodes[i].Name < outNodes[j].Name })

	writeOK(w, r, map[string]interface{}{
		"collector_alive": collectorOK,
		"nodes":           outNodes,
		"certs":           certs,
		"alerts":          alerts,
		"vip":             vipStatus(),
	})
}

// vipStatus：本机（控制平面部署在 director .180）的 VIP 持有视角。
// DR 模式下双机 lo 常驻 .140/32（RS 角色需要），只有 keepalived 把 VIP 配到物理接口才是真持有。
func vipStatus() map[string]interface{} {
	if directorVIP == "" {
		return map[string]interface{}{
			"address":           "未配置（MODSAFE_DIRECTOR_VIP）",
			"held_by_local":     false,
			"interface":         "",
			"keepalived_active": false,
		}
	}
	held := false
	iface := ""
	cur := ""
	ipOut, err := exec.Command("ip", "-4", "addr", "show").Output()
	ipLines := []string{}
	if err == nil {
		ipLines = strings.Split(string(ipOut), "\n")
	}
	for _, line := range ipLines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "inet ") {
			// 形如 "2: ens18: <BROADCAST...>" 的接口头行，更新当前接口名
			if i := strings.Index(line, ": "); i >= 0 {
				cur = strings.TrimSpace(strings.SplitN(line[i+2:], ":", 2)[0])
			}
			continue
		}
		if strings.Contains(trimmed, directorVIP+"/") {
			iface = cur
			if cur != "lo" {
				held = true
			}
		}
	}
	return map[string]interface{}{
		"address":           directorVIP + ":1194 (udp)",
		"held_by_local":     held,
		"interface":         iface,
		"keepalived_active": strings.TrimSpace(systemctlIsActive("keepalived")) == "active",
	}
}

// systemctlIsActive / systemctlRestart：程序位固定 "systemctl" 字面量，
// 仅单元名作参数（exec.Command 不经 shell，单元名经白名单/常量约束）——
// 不得恢复成接收任意程序名的通用 exec helper（动态可执行路径会被安全门拒绝）
func systemctlIsActive(unit string) string {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func systemctlRestart(unit string) {
	_, _ = exec.Command("systemctl", "restart", unit).Output()
}

// handleMonitorTraffic：流量看板（range=today|7d|30d，默认 today）
func (a *App) handleMonitorTraffic(w http.ResponseWriter, r *http.Request) {
	rg := r.URL.Query().Get("range")
	switch rg {
	case "today", "7d", "30d", "":
		if rg == "" {
			rg = "today"
		}
	default:
		failParam(w, r, "range 仅支持 today/7d/30d")
		return
	}
	dayCond := rangeDayCond(rg)

	// 流量口径（2026-09-30）：与门户一致读 traffic_daily 按日台账（跨天会话按实际发生日拆分）；
	// 会话数仍取 sessions 台账（语义=连接次数）
	var totalIn, totalOut int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM traffic_daily WHERE `+dayCond).Scan(&totalIn, &totalOut)

	var sessCount int64
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM sessions` + rangeWhere(rg)).Scan(&sessCount)

	rows, err := a.db.Query(`SELECT username, COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM traffic_daily WHERE `+dayCond+`
		GROUP BY username ORDER BY (SUM(bytes_in)+SUM(bytes_out)) DESC LIMIT 20`)
	if err != nil {
		failSystem(w, r, fmtErr("traffic top", err))
		return
	}
	top := []map[string]interface{}{}
	for rows.Next() {
		var name string
		var bi, bo int64
		if rows.Scan(&name, &bi, &bo) == nil {
			top = append(top, map[string]interface{}{
				"username": name, "bytes_in": bi, "bytes_out": bo,
			})
		}
	}
	rows.Close()

	// 每用户会话次数（语义=连接次数，取自 sessions 台账），合并进排行
	sessByUser := map[string]int64{}
	srows, serr := a.db.Query(`SELECT username, COUNT(*) FROM sessions` + rangeWhere(rg) + ` GROUP BY username`)
	if serr == nil {
		for srows.Next() {
			var name string
			var cnt int64
			if srows.Scan(&name, &cnt) == nil {
				sessByUser[name] = cnt
			}
		}
		srows.Close()
	}
	for _, t := range top {
		name, _ := t["username"].(string)
		t["sessions"] = sessByUser[name]
	}

	trafficSeries, onlineSeries := trafficSeries()

	writeOK(w, r, map[string]interface{}{
		"range":          rg,
		"total_in":       totalIn,
		"total_out":      totalOut,
		"sessions":       sessCount,
		"top_users":      top,
		"traffic_series": trafficSeries, // 24h 双节点字节差分聚合，30min 桶（MB）
		"online_series":  onlineSeries,  // 24h 集群在线数峰值，30min 桶
	})
}

// rangeWhere：台账时间为本地时区文本（datetime('now','localtime') 写入），过滤条件同口径
func rangeWhere(rg string) string {
	switch rg {
	case "7d":
		return ` WHERE COALESCE(NULLIF(last_seen,''), connected_at) >= datetime('now','-6 days','localtime')`
	case "30d":
		return ` WHERE COALESCE(NULLIF(last_seen,''), connected_at) >= datetime('now','-29 days','localtime')`
	default:
		return ` WHERE date(COALESCE(NULLIF(last_seen,''), connected_at)) = date('now','localtime')`
	}
}

// rangeDayCond：traffic_daily 的日期过滤（day 列 = 'YYYY-MM-DD' 本地日期）
func rangeDayCond(rg string) string {
	switch rg {
	case "7d":
		return ` day >= date('now','-6 days','localtime')`
	case "30d":
		return ` day >= date('now','-29 days','localtime')`
	default:
		return ` day = date('now','localtime')`
	}
}

// trafficSeries：collector /history 的字节快照按节点差分（负增量=会话结束回落，跳过），
// 聚合为 30 分钟桶的集群总流量（MB）；在线数取桶内峰值
func trafficSeries() ([]map[string]interface{}, []map[string]interface{}) {
	hist, err := collectorGet("/history?hours=24")
	if err != nil {
		return []map[string]interface{}{}, []map[string]interface{}{}
	}
	points, _ := hist["points"].([]interface{})
	type pt struct {
		ts             int64
		rx, tx, online int64
	}
	byNode := map[string][]pt{}
	for _, raw := range points {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		node, _ := m["node"].(string)
		ts, _ := m["ts"].(float64)
		rx, _ := m["bytes_rx"].(float64)
		tx, _ := m["bytes_tx"].(float64)
		on, _ := m["online"].(float64)
		byNode[node] = append(byNode[node], pt{int64(ts), int64(rx), int64(tx), int64(on)})
	}
	traffic := map[int64]*[2]float64{}
	onlineMax := map[int64]int64{}
	for _, pts := range byNode {
		for i := 1; i < len(pts); i++ {
			b := pts[i].ts - pts[i].ts%1800
			if dRx, dTx := pts[i].rx-pts[i-1].rx, pts[i].tx-pts[i-1].tx; dRx > 0 || dTx > 0 {
				bk, ok := traffic[b]
				if !ok {
					bk = &[2]float64{}
					traffic[b] = bk
				}
				bk[0] += float64(dRx)
				bk[1] += float64(dTx)
			}
			if pts[i].online > onlineMax[b] {
				onlineMax[b] = pts[i].online
			}
		}
	}
	buckets := map[int64]bool{}
	for k := range traffic {
		buckets[k] = true
	}
	for k := range onlineMax {
		buckets[k] = true
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	ser := []map[string]interface{}{}
	onl := []map[string]interface{}{}
	for _, k := range keys {
		label := time.Unix(k, 0).Format("15:04")
		var rx, tx float64
		if bk, ok := traffic[k]; ok {
			rx, tx = bk[0], bk[1]
		}
		ser = append(ser, map[string]interface{}{
			"time": label,
			"rx_mb": math.Round(rx/1048576*10) / 10,
			"tx_mb": math.Round(tx/1048576*10) / 10,
		})
		onl = append(onl, map[string]interface{}{"time": label, "online": onlineMax[k]})
	}
	return ser, onl
}
