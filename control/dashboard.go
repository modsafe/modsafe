package main

import (
	"net/http"
	"sort"
	"time"
)

func (a *App) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	var totalUsers, activeUsers int
	_ = a.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(status='active'),0) FROM users`).Scan(&totalUsers, &activeUsers)
	online := len(liveSessions()) // 实时在线 = 各节点 status 汇总

	// 今日连接 = 控制平面会话台账（session_tracker，username 归属准确）
	var todayConnections int
	_ = a.db.QueryRow(`SELECT COUNT(DISTINCT username) FROM sessions
		WHERE date(COALESCE(connected_at,last_seen))=date('now','localtime')`).Scan(&todayConnections)

	certDaysLeft, pendingAlerts := 0, 0
	// #133：待处理告警与告警中心「活动告警」同源（alert_state 全量）——
	// 此前取采集器 recent_alerts 快照（时间窗语义），两处数字对不上
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM alert_state`).Scan(&pendingAlerts)

	certs := []map[string]interface{}{}
	if summ, err := collectorGet("/summary"); err == nil {
		if raws, ok := summ["certs"].([]interface{}); ok {
			for _, raw := range raws {
				m, _ := raw.(map[string]interface{})
				d, _ := m["days_left"].(float64)
				file, _ := m["file"].(string)
				if certDaysLeft == 0 || int(d) < certDaysLeft {
					certDaysLeft = int(d)
				}
				certs = append(certs, map[string]interface{}{"file": file, "days_left": int(d)})
			}
		}
	}
	writeOK(w, r, map[string]interface{}{
		"online_users":      online,
		"today_connections": todayConnections,
		"total_users":       totalUsers,
		"active_users":      activeUsers,
		"pending_alerts":    pendingAlerts,
		"cert_days_left":    certDaysLeft,
		"certs":             certs,
		"collector":         collectorAlive(),
	})
}

// handleDashboardTrend：collector /history 聚合为 30 分钟桶的全集群在线数
func (a *App) handleDashboardTrend(w http.ResponseWriter, r *http.Request) {
	hist, err := collectorGet("/history?hours=24")
	if err != nil {
		// collector 不可用：返回空序列（前端显示暂无数据）
		writeOK(w, r, []map[string]interface{}{})
		return
	}
	points, _ := hist["points"].([]interface{})
	type bucket struct {
		online int
	}
	buckets := map[int64]*bucket{}
	for _, raw := range points {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		ts, _ := m["ts"].(float64)
		online, _ := m["online"].(float64)
		b := int64(ts) - int64(ts)%1800 // 30 分钟桶
		bk, ok := buckets[b]
		if !ok {
			bk = &bucket{}
			buckets[b] = bk
		}
		// 桶内取峰值：30s 一个采集点、多节点各一条，sum 会把在线数放大百倍
		if int(online) > bk.online {
			bk.online = int(online)
		}
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := []map[string]interface{}{}
	for _, k := range keys {
		out = append(out, map[string]interface{}{
			"time":   time.Unix(k, 0).Format("15:04"),
			"online": buckets[k].online,
		})
	}
	writeOK(w, r, out)
}
