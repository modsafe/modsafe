package main

// 告警规则引擎（§20）：生命周期（触发→去重→冷却→恢复）+ 规则目录 + 渠道路由。
// 数据模型：alert_rules（配置）/ alert_state（活动告警）/ alert_history_YYYYMM（历史分月）。
// 集成：collector 的 3 条既有规则（node.down/lb.down/cert.expiring）改走本引擎；
//       auth.bruteforce 数据源=audit_auth 月表；License 到期通知走本引擎。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// unitNumRe：local 节点 openvpn 实例号白名单（openvpn-modsafe@<n>，n=纯数字）
var unitNumRe = regexp.MustCompile(`^[0-9]{1,4}$`)

// ── 数据模型 ──

func initAlertTables() {
	// 在 store.go 的 mustExec 中调用
}

// AlertRule：规则配置（种子数据在 initSeedAlertRules）
type AlertRule struct {
	ID              string `json:"id"`
	Level           string `json:"level"`
	Description     string `json:"description"`
	Enabled         bool   `json:"enabled"`
	CooldownMinutes int    `json:"cooldown_minutes"`
	Threshold       map[string]interface{} `json:"threshold,omitempty"`
}

// seedAlertRules：规则目录（§20.2）
var seedAlertRules = []AlertRule{
	{ID: "node.down", Level: "critical", Description: "数据面节点连续探测失败", CooldownMinutes: 60},
	{ID: "lb.down", Level: "critical", Description: "负载均衡器不可达", CooldownMinutes: 60},
	{ID: "cert.expiring", Level: "warn", Description: "证书剩余天数不足", CooldownMinutes: 1440},
	{ID: "process.down", Level: "critical", Description: "关键进程 systemd inactive", CooldownMinutes: 30},
	{ID: "auth.bruteforce", Level: "warn", Description: "同源IP短时认证失败过多", CooldownMinutes: 120},
	{ID: "concurrent.near", Level: "warn", Description: "在线数接近授权上限", CooldownMinutes: 240},
	{ID: "users.near", Level: "warn", Description: "启用用户数接近授权上限", CooldownMinutes: 240},
	{ID: "license.expiring", Level: "warn", Description: "License 即将到期", CooldownMinutes: 10080},
}

func (a *App) initSeedAlertRules() {
	for _, r := range seedAlertRules {
		a.db.Exec(`INSERT OR IGNORE INTO alert_rules(id, level, description, enabled, cooldown_minutes)
			VALUES(?,?,?,1,?)`, r.ID, r.Level, r.Description, r.CooldownMinutes)
	}
}

// ── 告警生命周期 ──

// FireAlert：触发告警（去重+冷却逻辑）。detail 传入上下文（node/ip/reason 等）。
func (a *App) FireAlert(ruleID, dedupKey, detail string) {
	var enabled int
	var level string
	var cooldown int
	err := a.db.QueryRow(`SELECT enabled, level, cooldown_minutes FROM alert_rules WHERE id=?`, ruleID).
		Scan(&enabled, &level, &cooldown)
	if err != nil || enabled == 0 {
		return // 规则不存在或已禁用
	}

	// 维护模式：全局静默，只记历史
	if getSetting(a, "alert_maintenance_until", "") != "" {
		until := getSetting(a, "alert_maintenance_until", "")
		if t, e := time.Parse(time.RFC3339, until); e == nil && time.Now().Before(t) {
			a.recordAlertHistory(ruleID, dedupKey, level, "muted", detail, "")
			return
		}
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	var firedAt, lastNotified string
	err = a.db.QueryRow(`SELECT fired_at, last_notified_at FROM alert_state WHERE dedup_key=?`, dedupKey).
		Scan(&firedAt, &lastNotified)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return // DB 异常（非"无此告警"）：跳过本轮，防止冷却状态缺失导致通知风暴
	}

	if errors.Is(err, sql.ErrNoRows) {
		// 新告警：写状态 + 发通知（落库失败则本轮放弃通知）
		if _, e := a.db.Exec(`INSERT INTO alert_state(dedup_key, rule_id, level, fired_at, last_notified_at, detail_json)
			VALUES(?,?,?,?,?,?)`, dedupKey, ruleID, level, now, now, detail); e != nil {
			log.Printf("[alert] state insert %s: %v", dedupKey, e)
			return
		}
		msg := formatAlertMessage(ruleID, level, detail, false)
		channels := a.sendToChannels(level, msg)
		a.recordAlertHistory(ruleID, dedupKey, level, "fired", detail, channels)
		return
	}

	// 已存在：检查冷却（时间戳为东八区墙上时间，必须按固定时区解析——
	// 此前 time.Parse 按 UTC 解析导致冷却实际拉长 8 小时，2026-09-29 修复）
	if lastNotified != "" {
		if t, e := time.ParseInLocation("2006-01-02 15:04:05", lastNotified, cstZone); e == nil {
			if time.Since(t) < time.Duration(cooldown)*time.Minute {
				return // 冷却期内，静默
			}
		}
	}
	// 冷却期满：重提醒
	a.db.Exec(`UPDATE alert_state SET last_notified_at=? WHERE dedup_key=?`, now, dedupKey)
	msg := formatAlertMessage(ruleID, level, detail+"（持续中）", false)
	channels := a.sendToChannels(level, msg)
	a.recordAlertHistory(ruleID, dedupKey, level, "renotified", detail, channels)
}

// ResolveAlert：条件消除 → 发恢复通知 + 删状态
func (a *App) ResolveAlert(dedupKey string) {
	var ruleID, level, firedAt, detail string
	err := a.db.QueryRow(`SELECT rule_id, level, fired_at, detail_json FROM alert_state WHERE dedup_key=?`, dedupKey).
		Scan(&ruleID, &level, &firedAt, &detail)
	if err != nil {
		return // 无活动告警
	}
	a.db.Exec(`DELETE FROM alert_state WHERE dedup_key=?`, dedupKey)

	// 计算持续时长（东八区墙上时间按固定时区解析）
	duration := ""
	if t, e := time.ParseInLocation("2006-01-02 15:04:05", firedAt, cstZone); e == nil {
		d := time.Since(t)
		if d.Hours() >= 1 {
			duration = fmt.Sprintf("（持续 %.0f 小时）", d.Hours())
		} else {
			duration = fmt.Sprintf("（持续 %.0f 分钟）", d.Minutes())
		}
	}
	msg := formatAlertMessage(ruleID, level, detail+duration, true)
	channels := a.sendToChannels(level, msg)
	a.recordAlertHistory(ruleID, dedupKey, level, "resolved", detail, channels)
}

// formatAlertMessage：统一通知格式
func formatAlertMessage(ruleID, level, detail string, resolved bool) string {
	status := "触发"
	if resolved {
		status = "已恢复"
	}
	icon := "⚠️"
	if level == "critical" {
		icon = "🔴"
	}
	if resolved {
		icon = "✅"
	}
	return fmt.Sprintf("%s【%s】%s\n规则：%s\n详情：%s\n时间：%s\n处理：登录管理台 → 监控中心查看",
		icon, strings.ToUpper(level), status, ruleID, detail, time.Now().Format("2006-01-02 15:04:05"))
}

// sendToChannels：按级别路由发送
func (a *App) sendToChannels(level, message string) string {
	out, err := adapterAdmin("POST", "/admin/alerts/send", map[string]interface{}{
		"level": level, "message": message,
	})
	if err != nil {
		return "send_error"
	}
	if ch, ok := out["sent_to"].(string); ok {
		return ch
	}
	return "unknown"
}

// recordAlertHistory：写历史分月表
func (a *App) recordAlertHistory(ruleID, dedupKey, level, event, detail, channels string) {
	table := "alert_history_" + time.Now().Format("200601")
	a.db.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id TEXT, dedup_key TEXT, level TEXT, event TEXT,
		detail TEXT, notified_channels TEXT,
		event_time TEXT DEFAULT (datetime('now','localtime'))
	)`)
	a.db.Exec(`INSERT INTO `+table+`(rule_id, dedup_key, level, event, detail, notified_channels)
		VALUES(?,?,?,?,?,?)`, ruleID, dedupKey, level, event, detail, channels)
}

// ── API ──

// GET /api/v1/alerts/rules：规则目录
func (a *App) handleAlertRulesGet(w http.ResponseWriter, r *http.Request) {
	rules := []map[string]interface{}{}
	rows, err := a.db.Query(`SELECT id, level, description, enabled, cooldown_minutes FROM alert_rules ORDER BY id`)
	if err != nil {
		failSystem(w, r, "查询规则失败")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, level, desc string
		var enabled, cooldown int
		if rows.Scan(&id, &level, &desc, &enabled, &cooldown) == nil {
			rules = append(rules, map[string]interface{}{
				"id": id, "level": level, "description": desc,
				"enabled": enabled == 1, "cooldown_minutes": cooldown,
			})
		}
	}
	writeOK(w, r, rules)
}

// PUT /api/v1/alerts/rules/{id}：启用/禁用/调冷却
func (a *App) handleAlertRulePut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Enabled         *bool `json:"enabled"`
		CooldownMinutes *int  `json:"cooldown_minutes"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if req.Enabled != nil {
		v := 0
		if *req.Enabled {
			v = 1
		}
		a.db.Exec(`UPDATE alert_rules SET enabled=? WHERE id=?`, v, id)
	}
	if req.CooldownMinutes != nil {
		if *req.CooldownMinutes < 1 || *req.CooldownMinutes > 10080 {
			failParam(w, r, "cooldown_minutes 须在 1~10080 之间")
			return
		}
		a.db.Exec(`UPDATE alert_rules SET cooldown_minutes=? WHERE id=?`, *req.CooldownMinutes, id)
	}
	writeOK(w, r, nil)
}

// GET /api/v1/alerts/active：当前活动告警
func (a *App) handleAlertsActiveGet(w http.ResponseWriter, r *http.Request) {
	list := []map[string]interface{}{}
	rows, err := a.db.Query(`SELECT dedup_key, rule_id, level, fired_at, last_notified_at, detail_json
		FROM alert_state ORDER BY fired_at DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dk, rid, level, fired, notified, detail string
			if rows.Scan(&dk, &rid, &level, &fired, &notified, &detail) == nil {
				list = append(list, map[string]interface{}{
					"dedup_key": dk, "rule_id": rid, "level": level,
					"fired_at": fired, "last_notified_at": notified, "detail": detail,
				})
			}
		}
	}
	writeOK(w, r, list)
}

// GET /api/v1/alerts/history：历史（分页，近 12 个月分表 UNION——月初新表未建时不再"归零"）
func (a *App) handleAlertsHistoryGet(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	tables := a.existingAuditTables("alert_history",
		time.Now().AddDate(0, -11, 0), time.Now())
	if len(tables) == 0 {
		writeOK(w, r, pageData([]map[string]interface{}{}, 0, page, pageSize))
		return
	}
	unions := make([]string, len(tables))
	for i, t := range tables {
		unions[i] = fmt.Sprintf(`SELECT rule_id, dedup_key, level, event, detail, notified_channels, event_time FROM %s`, t)
	}
	unionSQL := strings.Join(unions, " UNION ALL ")
	var total int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM (` + unionSQL + `)`).Scan(&total)
	rows, err := a.db.Query(unionSQL + ` ORDER BY event_time DESC LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		writeOK(w, r, pageData([]map[string]interface{}{}, 0, page, pageSize))
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var rid, dk, level, event, detail, channels, ts string
		if rows.Scan(&rid, &dk, &level, &event, &detail, &channels, &ts) == nil {
			list = append(list, map[string]interface{}{
				"rule_id": rid, "dedup_key": dk, "level": level, "event": event,
				"detail": detail, "notified_channels": channels, "event_time": ts,
			})
		}
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// POST /api/v1/alerts/maintenance：维护模式（全局静默 N 小时）
func (a *App) handleAlertMaintenancePost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours int `json:"hours"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Hours < 1 || req.Hours > 72 {
		failParam(w, r, "hours 须在 1~72 之间")
		return
	}
	until := time.Now().Add(time.Duration(req.Hours) * time.Hour).Format(time.RFC3339)
	setSetting(a, "alert_maintenance_until", until)
	writeOK(w, r, map[string]interface{}{"until": until, "hours": req.Hours})
}

// DELETE /api/v1/alerts/maintenance：取消维护模式
func (a *App) handleAlertMaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	setSetting(a, "alert_maintenance_until", "")
	writeOK(w, r, nil)
}

// ── 规则检测（集成既有采集）──

// RunAlertChecks：定期检查（collector tick / 控制平面 5min 调用）
func (a *App) RunAlertChecks() {
	a.checkNodes()
	a.checkBruteForce()
	a.checkLicenseCapacity()
}

// checkNodes：node.down / process.down / license.expiring
func (a *App) checkNodes() {
	for _, node := range nodes {
		switch node.Kind {
		case "agent":
			_, err := agentRequest(node, "GET", "/healthz", nil)
			if err != nil {
				a.FireAlert("node.down", "node.down:"+node.Name,
					fmt.Sprintf("节点 %s 不可达", node.Name))
			} else {
				a.ResolveAlert("node.down:" + node.Name)
			}
		case "local":
			// local 节点此前从不探测（node-1 宕机无告警，2026-09-29 补齐）：
			// 探测本机各 openvpn 实例 systemd 状态
			unit := "openvpn-modsafe@" + strings.TrimPrefix(node.Name, "node-")
			// exec 前白名单实例号（node.Name 来自节点配置）：非纯数字实例名不进 systemctl
			if !unitNumRe.MatchString(strings.TrimPrefix(node.Name, "node-")) {
				a.FireAlert("node.down", "node.down:"+node.Name,
					fmt.Sprintf("节点 %s 实例名不合法，跳过 systemd 探测", node.Name))
				continue
			}
			st := strings.TrimSpace(systemctlIsActive(unit))
			if st != "active" {
				a.FireAlert("node.down", "node.down:"+node.Name,
					fmt.Sprintf("节点 %s 服务状态 %q（systemctl is-active %s）", node.Name, st, unit))
			} else {
				a.ResolveAlert("node.down:" + node.Name)
			}
		}
	}
	// license.expiring：正式授权到期前 30 天提醒（§20 承诺能力补齐）
	st := a.licenseState()
	if dr, ok := st["days_remaining"].(int); ok {
		if expiring, isLic := st["edition"].(string); isLic && expiring != "trial" && dr >= 0 && dr <= licenseWarnDays {
			a.FireAlert("license.expiring", "license.expiring:cluster",
				fmt.Sprintf("授权剩余 %d 天（客户：%v），请及时续费", dr, st["customer"]))
		} else {
			a.ResolveAlert("license.expiring:cluster")
		}
	}
}

// checkBruteForce：auth.bruteforce（audit_auth 5min 窗口）
func (a *App) checkBruteForce() {
	table := "audit_auth_" + time.Now().Format("200601")
	var threshold int = 10
	rows, err := a.db.Query(`SELECT trusted_ip, COUNT(*) as cnt FROM ` + table +
		` WHERE result='fail' AND event_time >= datetime('now','-5 minutes','localtime')
		GROUP BY trusted_ip HAVING cnt >= ?`, threshold)
	if err != nil {
		return
	}
	defer rows.Close()
	type hit struct {
		ip  string
		cnt int
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if rows.Scan(&h.ip, &h.cnt) == nil {
			hits = append(hits, h)
		}
	}
	for _, h := range hits {
		a.FireAlert("auth.bruteforce", "auth.bruteforce:"+h.ip,
			fmt.Sprintf("源 IP %s 5分钟内认证失败 %d 次", h.ip, h.cnt))
	}
	// 本窗口无命中的历史 bruteforce 告警自动恢复（此前触发后永久挂"活动"，2026-09-29 修复）
	if len(hits) > 0 {
		cur := map[string]bool{}
		for _, h := range hits {
			cur[h.ip] = true
		}
		srows, serr := a.db.Query(`SELECT dedup_key FROM alert_state WHERE dedup_key LIKE 'auth.bruteforce:%'`)
		if serr == nil {
			var stale []string
			for srows.Next() {
				var dk string
				if srows.Scan(&dk) == nil {
					ip := strings.TrimPrefix(dk, "auth.bruteforce:")
					if !cur[ip] {
						stale = append(stale, dk)
					}
				}
			}
			srows.Close()
			for _, dk := range stale {
				a.ResolveAlert(dk)
			}
		}
	}
}

// checkLicenseCapacity：concurrent.near / users.near
func (a *App) checkLicenseCapacity() {
	lic := a.loadInstalledLicense()
	if lic == nil {
		return
	}
	online := len(liveSessions())
	// 先乘后除防整数截断（max=1 时 1*90/100=0 曾导致永久触发，2026-09-29 修复）
	if lic.MaxConcurrent > 0 && online*100 >= lic.MaxConcurrent*90 {
		a.FireAlert("concurrent.near", "concurrent.near:cluster",
			fmt.Sprintf("在线 %d 已达授权上限 %d 的 90%%", online, lic.MaxConcurrent))
	} else {
		a.ResolveAlert("concurrent.near:cluster")
	}
	var activeUsers int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE status='active'`).Scan(&activeUsers)
	if lic.MaxUsers > 0 && activeUsers*100 >= lic.MaxUsers*90 {
		a.FireAlert("users.near", "users.near:cluster",
			fmt.Sprintf("用户 %d 已达授权上限 %d 的 90%%", activeUsers, lic.MaxUsers))
	} else {
		a.ResolveAlert("users.near:cluster")
	}
}

var _ = json.Marshal
