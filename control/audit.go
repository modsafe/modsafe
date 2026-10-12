package main

// 审计查询（§9.9/§19 的读路径）：月表 UNION + 过滤 + 分页。
// 写操作审计由 requireRoles 钩子写入 audit_admin_YYYYMM。

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// existingAuditTables：返回 SQLite 中实际存在的审计月表（避免 UNION 不存在的表报错）。
// 按月首日枚举（对齐到当月 1 号再逐月 +1），修复两个边界：to 之后一个月被误包含、
// from 为 29-31 日时 AddDate 规范化跳过 2 月表（2026-09-29 修复）
func (a *App) existingAuditTables(prefix string, from, to time.Time) []string {
	var names []string
	f := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, from.Location())
	t := time.Date(to.Year(), to.Month(), 1, 0, 0, 0, 0, to.Location())
	for cur := f; !cur.After(t); cur = cur.AddDate(0, 1, 0) {
		name := fmt.Sprintf("%s_%s", prefix, cur.Format("200601"))
		var cnt int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&cnt)
		if cnt > 0 {
			names = append(names, name)
		}
	}
	return names
}

// auditRangeCond：月表内的日期过滤（此前 from/to 只用于选表，行级不过滤——整月混入，2026-09-29 修复）
func auditRangeCond(from, to time.Time) (string, string, string) {
	return "event_time >= ? AND event_time < ?",
		from.Format("2006-01-02") + " 00:00:00",
		to.AddDate(0, 0, 1).Format("2006-01-02") + " 00:00:00"
}

func (a *App) handleAuditAuthLogs(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	q := r.URL.Query()
	from := parseDateOr(q.Get("from"), time.Now().AddDate(0, -1, 0))
	to := parseDateOr(q.Get("to"), time.Now())

	where := []string{"1=1"}
	var args []interface{}
	if v := normalizeKeyword(q.Get("username")); v != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if v := q.Get("source"); v != "" {
		where = append(where, "idp_source=?")
		args = append(args, v)
	}
	if v := q.Get("result"); v != "" {
		where = append(where, "result=?")
		args = append(args, v)
	}
	cond, fArg, tArg := auditRangeCond(from, to)
	where = append(where, cond)
	args = append(args, fArg, tArg)

	tables := a.existingAuditTables("audit_auth", from, to)
	if len(tables) == 0 {
		writeOK(w, r, pageData([]map[string]interface{}{}, 0, page, pageSize))
		return
	}
	whereSQL := strings.Join(where, " AND ")
	unions := make([]string, len(tables))
	for i, t := range tables {
		unions[i] = fmt.Sprintf(
			`SELECT event_time, username, idp_source, result, reason, trusted_ip FROM %s WHERE %s`, t, whereSQL)
	}
	unionSQL := strings.Join(unions, " UNION ALL ")

	// 2026-10-04 修复：UNION 中 whereSQL 出现 N 次（N=月表数）而参数只传一组——
	// 单月表恰好匹配不报错，跨月（from~to 横跨两个月表）参数数不足必报错 500；
	// 参数必须按表数整组复制（2026-10-01 跨入 10 月后两月表必现）
	tableArgs := make([]interface{}, 0, len(args)*len(tables))
	for range tables {
		tableArgs = append(tableArgs, args...)
	}

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM (`+unionSQL+`)`, tableArgs...).Scan(&total); err != nil {
		failSystem(w, r, "统计审计失败")
		return
	}
	pageArgs := append(append([]interface{}{}, tableArgs...), pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(unionSQL+` ORDER BY event_time DESC LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		failSystem(w, r, "查询审计失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var et, username, source, result, reason, trustedIP string
		if err := rows.Scan(&et, &username, &source, &result, &reason, &trustedIP); err != nil {
			continue
		}
		list = append(list, map[string]interface{}{
			"event_time": et, "username": username, "idp_source": source,
			"result": result, "reason": reason, "trusted_ip": trustedIP,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) handleAuditSessionLogs(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	q := r.URL.Query()
	where := []string{"1=1"}
	var args []interface{}
	if v := normalizeKeyword(q.Get("username")); v != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+v+"%")
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE `+whereSQL, args...).Scan(&total); err != nil {
		failSystem(w, r, "统计失败")
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(`SELECT connected_at, username, virtual_ip, trusted_ip, bytes_in, bytes_out,
		COALESCE(last_seen,''), settled, node
		FROM sessions WHERE `+whereSQL+` ORDER BY connected_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		failSystem(w, r, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var ca, vip, rip, node, lastSeen, username string
		var bi, bo, settled int64
		if err := rows.Scan(&ca, &username, &vip, &rip, &bi, &bo, &lastSeen, &settled, &node); err != nil {
			continue
		}
		st := "已结束"
		if settled == 0 {
			st = "在线"
		}
		list = append(list, map[string]interface{}{
			"connected_at": ca, "username": username, "virtual_ip": vip, "trusted_ip": rip,
			"bytes_in": bi, "bytes_out": bo, "last_seen": lastSeen, "state": st, "node": node,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) handleAuditAdminLogs(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	q := r.URL.Query()
	from := parseDateOr(q.Get("from"), time.Now().AddDate(0, -1, 0))
	to := parseDateOr(q.Get("to"), time.Now())
	tables := a.existingAuditTables("audit_admin", from, to)
	if len(tables) == 0 {
		writeOK(w, r, pageData([]map[string]interface{}{}, 0, page, pageSize))
		return
	}
	unions := make([]string, len(tables))
	cond, fArg, tArg := auditRangeCond(from, to)
	for i, t := range tables {
		unions[i] = fmt.Sprintf(`SELECT event_time, admin_name, method, path, client_ip FROM %s WHERE %s`, t, cond)
	}
	unionSQL := strings.Join(unions, " UNION ALL ")
	// 2026-10-04 修复：与 handleAuditAuthLogs 同根因——cond 每表 2 个占位符，
	// 参数需按表数复制（此前只传一组，跨月 500）
	tableArgs := make([]interface{}, 0, 2*len(tables))
	for range tables {
		tableArgs = append(tableArgs, fArg, tArg)
	}
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM (` + unionSQL + `)`, tableArgs...).Scan(&total); err != nil {
		failSystem(w, r, "统计失败")
		return
	}
	pageArgs := append(append([]interface{}{}, tableArgs...), pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(unionSQL+` ORDER BY event_time DESC LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		failSystem(w, r, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var et, admin, method, path, ip string
		if err := rows.Scan(&et, &admin, &method, &path, &ip); err != nil {
			continue
		}
		list = append(list, map[string]interface{}{
			"event_time": et, "admin": admin, "method": method, "path": path, "client_ip": ip,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// auditAdminWrite：写操作审计钩子（requireRoles 对写方法调用）
func (a *App) auditAdminWrite(r *http.Request, claims *adminClaims) {
	table := "audit_admin_" + time.Now().Format("200601")
	a.ensureAdminTable(table)
	_, _ = a.db.Exec(`INSERT INTO `+table+`(admin_name, method, path, client_ip)
		VALUES(?, ?, ?, ?)`,
		claims.Username, r.Method, r.URL.Path, remoteIP(r))
}

// auditAdminAction：不经 requireRoles 的管理动作审计（如改密；method 字段附结果，不含密码本体）
func (a *App) auditAdminAction(r *http.Request, admin, method, path, result, reason string) {
	table := "audit_admin_" + time.Now().Format("200601")
	a.ensureAdminTable(table)
	_, _ = a.db.Exec(`INSERT INTO `+table+`(admin_name, method, path, client_ip)
		VALUES(?, ?, ?, ?)`, admin, method+" "+result+" "+reason, path, remoteIP(r))
}

func (a *App) ensureAdminTable(table string) {
	_, _ = a.db.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time TEXT DEFAULT (datetime('now','localtime')),
		admin_name TEXT, method TEXT, path TEXT, client_ip TEXT)`)
}

// handleDevices：设备/来源聚合（sessions 台账按 用户+来源IP 去重）
func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	rows, err := a.db.Query(`SELECT username, trusted_ip, MAX(virtual_ip), MAX(node),
		MAX(connected_at), COALESCE(MAX(last_seen),''), MAX(settled), SUM(bytes_in), SUM(bytes_out),
		COUNT(*)
		FROM sessions GROUP BY username, trusted_ip ORDER BY MAX(last_seen) DESC`)
	if err != nil {
		failSystem(w, r, "查询设备失败")
		return
	}
	defer rows.Close()
	all := []map[string]interface{}{}
	for rows.Next() {
		var username, trustedIP, vip, node, connectedAt, lastSeen string
		var settled, bi, bo, cnt int64
		if err := rows.Scan(&username, &trustedIP, &vip, &node, &connectedAt, &lastSeen, &settled, &bi, &bo, &cnt); err != nil {
			continue
		}
		online := settled == 0
		all = append(all, map[string]interface{}{
			"username": username, "trusted_ip": trustedIP, "last_virtual_ip": vip,
			"node": node, "first_seen": connectedAt, "last_seen": lastSeen,
			"online": online, "total_bytes_in": bi, "total_bytes_out": bo, "session_count": cnt,
		})
	}
	total := len(all)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	writeOK(w, r, pageData(all[start:end], total, page, pageSize))
}

func parseDateOr(s string, def time.Time) time.Time {
	if s == "" {
		return def
	}
	if t, err := time.ParseInLocation("2006-01-02", s, cstZone); err == nil {
		return t
	}
	return def
}
