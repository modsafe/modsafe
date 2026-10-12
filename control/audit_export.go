package main

// 合规报表 CSV 导出（P1-a）：审计认证/管理操作/会话台账/DNS 查询四维度。
// 复用 audit.go 的月表 UNION 逻辑（跨月参数已修复——#86 tableArgs 按表数复制）。
// 权限与对应查询端点一致（admin-logs 仅 auditor/super；导出动作走 requireRoles 审计钩子）。

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func writeCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", contentDisposition(filename)) // #125：RFC5987 双参数（当前文件名 ASCII，防未来中文名复现同病）
	var b strings.Builder
	// UTF-8 BOM：Excel 直接打开中文不乱码
	b.WriteString("\xEF\xBB\xBF")
	b.WriteString(strings.Join(header, ",") + "\r\n")
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = `"` + strings.ReplaceAll(strings.ReplaceAll(c, `"`, `""`), "\r", " ") + `"`
		}
		b.WriteString(strings.Join(cells, ",") + "\r\n")
	}
	_, _ = w.Write([]byte(b.String()))
}

func (a *App) handleExportAuthLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from := parseDateOr(q.Get("from"), time.Now().AddDate(0, -1, 0))
	to := parseDateOr(q.Get("to"), time.Now())
	tables := a.existingAuditTables("audit_auth", from, to)
	cond, fArg, tArg := auditRangeCond(from, to)
	args := []interface{}{fArg, tArg}
	if v := normalizeKeyword(q.Get("username")); v != "" {
		args = append(args, "%"+v+"%")
		cond += " AND username LIKE ?"
	}
	unions := make([]string, len(tables))
	for i, t := range tables {
		unions[i] = fmt.Sprintf(`SELECT event_time, username, idp_source, result, reason, trusted_ip FROM %s WHERE %s`, t, cond)
	}
	rows := [][]string{}
	if len(tables) > 0 {
		qArgs := make([]interface{}, 0, len(args)*len(tables))
		for range tables {
			qArgs = append(qArgs, args...)
		}
		rs, err := a.db.Query(strings.Join(unions, " UNION ALL ")+` ORDER BY event_time DESC LIMIT 100000`, qArgs...)
		if err == nil {
			defer rs.Close()
			for rs.Next() {
				var et, u, src, res, reason, ip string
				if rs.Scan(&et, &u, &src, &res, &reason, &ip) == nil {
					rows = append(rows, []string{et, u, src, res, reason, ip})
				}
			}
		}
	}
	writeCSV(w, "auth-logs-"+from.Format("20060102")+"-"+to.Format("20060102")+".csv",
		[]string{"时间", "用户", "认证源", "结果", "原因", "来源IP"}, rows)
}

func (a *App) handleExportSessionLogs(w http.ResponseWriter, r *http.Request) {
	rows := [][]string{}
	rs, err := a.db.Query(`SELECT connected_at, username, virtual_ip, trusted_ip, bytes_in, bytes_out,
		COALESCE(last_seen,''), settled, node FROM sessions ORDER BY connected_at DESC LIMIT 100000`)
	if err == nil {
		defer rs.Close()
		for rs.Next() {
			var ca, u, vip, rip, lastSeen, node string
			var bi, bo, settled int64
			if rs.Scan(&ca, &u, &vip, &rip, &bi, &bo, &lastSeen, &settled, &node) == nil {
				st := "已结束"
				if settled == 0 {
					st = "在线"
				}
				rows = append(rows, []string{ca, u, vip, rip, fmt.Sprint(bi), fmt.Sprint(bo), lastSeen, st, node})
			}
		}
	}
	writeCSV(w, "session-logs.csv",
		[]string{"连接时间", "用户", "虚拟IP", "来源IP", "下行字节", "上行字节", "最后活跃", "状态", "节点"}, rows)
}

func (a *App) handleExportAdminLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from := parseDateOr(q.Get("from"), time.Now().AddDate(0, -1, 0))
	to := parseDateOr(q.Get("to"), time.Now())
	tables := a.existingAuditTables("audit_admin", from, to)
	cond, fArg, tArg := auditRangeCond(from, to)
	rows := [][]string{}
	unions := make([]string, len(tables))
	for i, t := range tables {
		unions[i] = fmt.Sprintf(`SELECT event_time, admin_name, method, path, client_ip FROM %s WHERE %s`, t, cond)
	}
	if len(tables) > 0 {
		qArgs := make([]interface{}, 0, 2*len(tables))
		for range tables {
			qArgs = append(qArgs, fArg, tArg)
		}
		rs, err := a.db.Query(strings.Join(unions, " UNION ALL ")+` ORDER BY event_time DESC LIMIT 100000`, qArgs...)
		if err == nil {
			defer rs.Close()
			for rs.Next() {
				var et, admin, method, path, ip string
				if rs.Scan(&et, &admin, &method, &path, &ip) == nil {
					rows = append(rows, []string{et, admin, method, path, ip})
				}
			}
		}
	}
	writeCSV(w, "admin-logs-"+from.Format("20060102")+"-"+to.Format("20060102")+".csv",
		[]string{"时间", "管理员", "操作", "路径", "来源IP"}, rows)
}

func (a *App) handleExportDNS(w http.ResponseWriter, r *http.Request) {
	rows := [][]string{}
	rs, err := a.db.Query(`SELECT ts, src, domain, qtype FROM dns_queries ORDER BY ts DESC LIMIT 100000`)
	if err == nil {
		defer rs.Close()
		for rs.Next() {
			var ts, src, domain, qtype string
			if rs.Scan(&ts, &src, &domain, &qtype) == nil {
				rows = append(rows, []string{ts, src, domain, qtype})
			}
		}
	}
	writeCSV(w, "dns-queries.csv", []string{"时间", "客户端", "域名", "类型"}, rows)
}
