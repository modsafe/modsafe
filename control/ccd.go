package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

var ccdTypes = map[string]bool{
	"route": true, "dns": true, "redirect_gateway": true, "iroute": true, "route_metric": true,
}

type ccdRule struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Priority  int    `json:"priority"`
	GroupID   *int64 `json:"group_id"`
	UserID    *int64 `json:"user_id"`
	Enabled   bool   `json:"enabled"`
	UpdatedAt string `json:"updated_at"`
	Scope     string `json:"scope"`
	BindName  string `json:"bind_name"`
}

func scopeOf(groupID, userID *int64) string {
	switch {
	case userID != nil:
		return "user"
	case groupID != nil:
		return "group"
	default:
		return "global"
	}
}

func (a *App) handleCcdList(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	q := r.URL.Query()
	where := []string{"1=1"}
	var args []interface{}
	if t := q.Get("type"); t != "" {
		where = append(where, "type=?")
		args = append(args, t)
	}
	if s := q.Get("scope"); s == "global" || s == "group" || s == "user" {
		switch s {
		case "global":
			where = append(where, "group_id IS NULL AND user_id IS NULL")
		case "group":
			where = append(where, "group_id IS NOT NULL")
		case "user":
			where = append(where, "user_id IS NOT NULL")
		}
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM ccd_rules WHERE `+whereSQL, args...).Scan(&total); err != nil {
		failSystem(w, r, "统计规则失败")
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(`SELECT id,name,type,value,priority,group_id,user_id,enabled,updated_at
		FROM ccd_rules WHERE `+whereSQL+` ORDER BY priority DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		failSystem(w, r, "查询规则失败")
		return
	}
	defer rows.Close()
	list := []ccdRule{}
	for rows.Next() {
		var c ccdRule
		var enabled int
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.Value, &c.Priority, &c.GroupID, &c.UserID, &enabled, &c.UpdatedAt); err != nil {
			failSystem(w, r, "读取规则失败")
			return
		}
		c.Enabled = enabled == 1
		c.Scope = scopeOf(c.GroupID, c.UserID)
		c.BindName = a.bindName(c)
		list = append(list, c)
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) bindName(c ccdRule) string {
	switch {
	case c.UserID != nil:
		var name string
		_ = a.db.QueryRow(`SELECT COALESCE(NULLIF(display_name,''), username) FROM users WHERE id=?`, *c.UserID).Scan(&name)
		return name
	case c.GroupID != nil:
		var name string
		_ = a.db.QueryRow(`SELECT name FROM user_groups WHERE id=?`, *c.GroupID).Scan(&name)
		return name
	default:
		return "全局"
	}
}

type ccdWriteReq struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Priority int    `json:"priority"`
	GroupID  *int64 `json:"group_id"`
	UserID   *int64 `json:"user_id"`
	Enabled  *bool  `json:"enabled"`
}

func validateCcdWrite(a *App, req *ccdWriteReq) string {
	if normalizeKeyword(req.Name) == "" {
		return "name 必填"
	}
	if !ccdTypes[req.Type] {
		return "type 不合法（route|dns|redirect_gateway|iroute|route_metric）"
	}
	req.Value = normalizeKeyword(req.Value)
	if req.Value == "" {
		return "value 必填"
	}
	if req.Type == "route" || req.Type == "iroute" {
		if _, err := netip.ParsePrefix(req.Value); err != nil {
			return "value 必须为合法 CIDR（示例 10.0.1.0/24）"
		}
	}
	if req.Type == "dns" {
		// dns 值渲染进 push "dhcp-option DNS <v>"，必须是合法 IP（防 CCD 指令注入，2026-09-29 修复）
		if _, err := netip.ParseAddr(req.Value); err != nil {
			return "dns 必须为合法 IP 地址（示例 10.0.0.2）"
		}
	}
	if req.Type == "route_metric" {
		if _, err := strconv.Atoi(req.Value); err != nil {
			return "route_metric 必须为整数"
		}
	}
	if req.Type == "redirect_gateway" {
		v := strings.ToLower(req.Value)
		if v != "true" && v != "false" {
			return "redirect_gateway 仅接受 true/false"
		}
	}
	if req.UserID != nil && req.GroupID != nil {
		return "用户规则与组规则不能同时绑定（层级二选一）"
	}
	return ""
}

func (a *App) handleCcdCreate(w http.ResponseWriter, r *http.Request) {
	var req ccdWriteReq
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if msg := validateCcdWrite(a, &req); msg != "" {
		failParam(w, r, msg)
		return
	}
	// 保存前冲突检测：存在阻断项则拒绝（§14.4）
	blockers, _ := a.ccdConflicts(&req, 0)
	if len(blockers) > 0 {
		failBiz(w, r, 20003, blockers[0]["reason"].(string))
		return
	}
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}
	res, err := a.db.Exec(`INSERT INTO ccd_rules(name,type,value,priority,group_id,user_id,enabled,created_by)
		VALUES(?,?,?,?,?,?,?,?)`,
		req.Name, req.Type, req.Value, req.Priority, req.GroupID, req.UserID, enabled, claimsOf(r).Username)
	if err != nil {
		failSystem(w, r, "创建规则失败")
		return
	}
	a.syncCCDAsync()
	id, _ := res.LastInsertId()
	writeOK(w, r, map[string]interface{}{"id": id})
}

func (a *App) handleCcdUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req ccdWriteReq
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if msg := validateCcdWrite(a, &req); msg != "" {
		failParam(w, r, msg)
		return
	}
	blockers, _ := a.ccdConflicts(&req, id)
	if len(blockers) > 0 {
		failBiz(w, r, 20003, blockers[0]["reason"].(string))
		return
	}
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}
	res, err := a.db.Exec(`UPDATE ccd_rules SET name=?,type=?,value=?,priority=?,group_id=?,user_id=?,enabled=?,
		updated_at=datetime('now','localtime') WHERE id=?`,
		req.Name, req.Type, req.Value, req.Priority, req.GroupID, req.UserID, enabled, id)
	if err != nil {
		failSystem(w, r, "更新规则失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "规则")
		return
	}
	a.syncCCDAsync()
	writeOK(w, r, nil)
}

func (a *App) handleCcdDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	res, err := a.db.Exec(`DELETE FROM ccd_rules WHERE id=?`, id)
	if err != nil {
		failSystem(w, r, "删除规则失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "规则")
		return
	}
	a.syncCCDAsync()
	writeOK(w, r, nil)
}

// ccdConflicts：§14.3/§14.4 —— 同绑定对象完全重复=阻断；同绑定对象部分重叠=警告
func (a *App) ccdConflicts(req *ccdWriteReq, excludeID int64) (blockers, warnings []map[string]interface{}) {
	blockers, warnings = []map[string]interface{}{}, []map[string]interface{}{}
	reqPrefix := parseCIDROrNil(req.Type, req.Value)
	if reqPrefix == nil {
		// 非 CIDR 类型：同绑定同类型同值 = 重复
		if req.Type == "dns" || req.Type == "redirect_gateway" || req.Type == "route_metric" {
			n := a.countSameRule(req, excludeID)
			if n > 0 {
				blockers = append(blockers, map[string]interface{}{"reason": "同层级已存在相同配置（后写覆盖前写）"})
			}
		}
		return blockers, warnings
	}
	rows, err := a.db.Query(`SELECT id,name,type,value FROM ccd_rules WHERE id<>? AND enabled=1
		AND (group_id IS ? AND user_id IS ?)`, excludeID, req.GroupID, req.UserID)
	if err != nil {
		return blockers, warnings
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name, typ, val string
		if err := rows.Scan(&id, &name, &typ, &val); err != nil {
			continue
		}
		other := parseCIDROrNil(typ, val)
		if other == nil {
			continue
		}
		switch relation(*reqPrefix, *other) {
		case "SAME":
			blockers = append(blockers, map[string]interface{}{
				"rule_id": id, "name": name, "reason": fmt.Sprintf("同层级重复 CIDR %s（规则 #%d）", req.Value, id)})
		case "PARTIAL":
			warnings = append(warnings, map[string]interface{}{
				"rule_id": id, "name": name, "reason": fmt.Sprintf("与 %s（规则 #%d）部分重叠，请确认是否有意", val, id)})
		}
	}
	return blockers, warnings
}

func (a *App) countSameRule(req *ccdWriteReq, excludeID int64) int {
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM ccd_rules WHERE id<>? AND type=? AND value=? AND enabled=1
		AND (group_id IS ? AND user_id IS ?)`, excludeID, req.Type, req.Value, req.GroupID, req.UserID).Scan(&n)
	return n
}

func parseCIDROrNil(typ, val string) *netip.Prefix {
	if typ != "route" && typ != "iroute" {
		return nil
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(val))
	if err != nil {
		return nil
	}
	p = p.Masked()
	return &p
}

func relation(a, b netip.Prefix) string {
	switch {
	case a == b:
		return "SAME"
	case a.Bits() <= b.Bits() && a.Overlaps(b):
		return "A_CONTAINS_B"
	case b.Bits() <= a.Bits() && b.Overlaps(a):
		return "B_CONTAINS_A"
	case a.Overlaps(b):
		return "PARTIAL"
	default:
		return "DISJOINT"
	}
}

func (a *App) handleCcdValidate(w http.ResponseWriter, r *http.Request) {
	var req ccdWriteReq
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	blockers, warnings := a.ccdConflicts(&req, 0)
	writeOK(w, r, map[string]interface{}{"blockers": blockers, "warnings": warnings})
}

func (a *App) handleCcdApply(w http.ResponseWriter, r *http.Request) {
	// 规则已即时落库；重连后即可获取新 push（auth-token 重连也会重新 push，§14.6）。
	// "应用变更" = 跨节点踢全部在线会话，客户端秒级自动重连拿到新路由。
	results := []map[string]interface{}{}
	for i := range nodes {
		res := kickOnNode(nodes[i], "", true)
		results = append(results, map[string]interface{}{"node": nodes[i].Name, "result": res})
	}
	writeOK(w, r, map[string]interface{}{
		"results": results,
		"notice":  "已对全部节点执行踢线，客户端将自动重连并应用新规则；踢线窗口期间新认证短暂失败",
	})
}
