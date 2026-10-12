package main

// 多管理员账号管理（P0-3，§12 三权分立：仅 super_admin 可管理）。
// 写操作经 requireRoles 钩子自动落 audit_admin_YYYYMM。
// 守卫：不能删除自己；不能删除/降级最后一个 super_admin（防锁死）。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var validAdminRoles = map[string]bool{"super_admin": true, "security_admin": true, "auditor": true}

func normalizeRoles(in []string) ([]string, bool) {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range in {
		r = strings.TrimSpace(r)
		if !validAdminRoles[r] || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func (a *App) handleAdminList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT id, username, roles, must_change_password, created_at
		FROM admins ORDER BY id`)
	if err != nil {
		failSystem(w, r, "查询管理员失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var id, mustChange int
		var username, rolesJSON, createdAt string
		if err := rows.Scan(&id, &username, &rolesJSON, &mustChange, &createdAt); err != nil {
			continue
		}
		list = append(list, map[string]interface{}{
			"id": id, "username": username, "roles": jsonDecodeStringSlice(rolesJSON),
			"must_change_password": mustChange == 1, "created_at": createdAt,
		})
	}
	writeOK(w, r, map[string]interface{}{"list": list, "total": len(list)})
}

func (a *App) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Roles    []string `json:"roles"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 64 {
		failParam(w, r, "用户名需 1-64 字符")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 72 {
		failParam(w, r, "密码需 8-72 位")
		return
	}
	roles, ok := normalizeRoles(req.Roles)
	if !ok {
		failParam(w, r, "角色至少包含一项（super_admin/security_admin/auditor）")
		return
	}
	rolesJSON, _ := json.Marshal(roles)
	var cnt int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM admins WHERE username=?`, req.Username).Scan(&cnt)
	if cnt > 0 {
		failBiz(w, r, 20001, "用户名已存在")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		failSystem(w, r, "密码哈希失败")
		return
	}
	res, err := a.db.Exec(`INSERT INTO admins(username, password_hash, roles, must_change_password)
		VALUES(?,?,?,1)`, req.Username, string(hash), string(rolesJSON))
	if err != nil {
		failSystem(w, r, "创建失败")
		return
	}
	id, _ := res.LastInsertId()
	writeOK(w, r, map[string]interface{}{"id": id, "must_change_password": true})
}

// countSuperAdmins：现有 super_admin 数量（不含 excludeID，用于"最后一个"守卫）
func (a *App) countSuperAdmins(excludeID int64) int {
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM admins WHERE roles LIKE '%super_admin%' AND id != ?`,
		excludeID).Scan(&n)
	return n
}

func (a *App) handleAdminUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Roles []string `json:"roles"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	roles, ok := normalizeRoles(req.Roles)
	if !ok {
		failParam(w, r, "角色至少包含一项")
		return
	}
	var cur string
	if err := a.db.QueryRow(`SELECT roles FROM admins WHERE id=?`, id).Scan(&cur); err != nil {
		failBiz(w, r, 20001, "管理员不存在")
		return
	}
	// 最后一个 super_admin 不得移除其 super_admin 角色（防锁死）
	if strings.Contains(cur, "super_admin") && !containsStr(roles, "super_admin") && a.countSuperAdmins(id) == 0 {
		failBiz(w, r, 20003, "系统必须保留至少一个 super_admin")
		return
	}
	rolesJSON, _ := json.Marshal(roles)
	if _, err := a.db.Exec(`UPDATE admins SET roles=? WHERE id=?`, string(rolesJSON), id); err != nil {
		failSystem(w, r, "更新失败")
		return
	}
	writeOK(w, r, map[string]interface{}{"ok": true})
}

func (a *App) handleAdminPasswordReset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Password string `json:"password"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 72 {
		failParam(w, r, "密码需 8-72 位")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		failSystem(w, r, "密码哈希失败")
		return
	}
	res, err := a.db.Exec(`UPDATE admins SET password_hash=?, must_change_password=1 WHERE id=?`,
		string(hash), id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		failBiz(w, r, 20001, "管理员不存在")
		return
	}
	writeOK(w, r, map[string]interface{}{"ok": true, "must_change_password": true})
}

func (a *App) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	claims := claimsOf(r)
	var username, roles string
	if err := a.db.QueryRow(`SELECT username, roles FROM admins WHERE id=?`, id).Scan(&username, &roles); err != nil {
		failBiz(w, r, 20001, "管理员不存在")
		return
	}
	if claims != nil && claims.Username == username {
		failBiz(w, r, 20003, "不能删除当前登录的账号")
		return
	}
	if strings.Contains(roles, "super_admin") && a.countSuperAdmins(id) == 0 {
		failBiz(w, r, 20003, "系统必须保留至少一个 super_admin")
		return
	}
	if _, err := a.db.Exec(`DELETE FROM admins WHERE id=?`, id); err != nil {
		failSystem(w, r, "删除失败")
		return
	}
	writeOK(w, r, map[string]interface{}{"ok": true})
}
