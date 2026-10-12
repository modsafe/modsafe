package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func (a *App) handleGroupList(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	keyword := normalizeKeyword(r.URL.Query().Get("keyword"))

	where := "1=1"
	var args []interface{}
	if keyword != "" {
		where = "g.name LIKE ?"
		args = append(args, "%"+keyword+"%")
	}

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM user_groups g WHERE `+where, args...).Scan(&total); err != nil {
		failSystem(w, r, "统计组失败")
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(`SELECT g.id, g.name, g.idp_ref, g.created_at,
			(SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id),
			(SELECT COUNT(*) FROM group_resources gr WHERE gr.group_id=g.id)
		FROM user_groups g WHERE `+where+` ORDER BY g.id LIMIT ? OFFSET ?`, args...)
	if err != nil {
		failSystem(w, r, "查询组失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var name, idpRef, createdAt string
		var members, resources int
		if err := rows.Scan(&id, &name, &idpRef, &createdAt, &members, &resources); err != nil {
			failSystem(w, r, "读取组失败")
			return
		}
		list = append(list, map[string]interface{}{
			"id": id, "name": name, "idp_ref": idpRef, "created_at": createdAt,
			"member_count": members, "resource_count": resources,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := jsonDecode(r, &req); err != nil || normalizeKeyword(req.Name) == "" {
		failParam(w, r, "name 必填")
		return
	}
	req.Name = normalizeKeyword(req.Name)
	var exists int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE name=?`, req.Name).Scan(&exists)
	if exists > 0 {
		failBiz(w, r, 20001, "组名已存在")
		return
	}
	res, err := a.db.Exec(`INSERT INTO user_groups(name) VALUES(?)`, req.Name)
	if err != nil {
		failSystem(w, r, "创建组失败")
		return
	}
	id, _ := res.LastInsertId()
	writeOK(w, r, map[string]interface{}{"id": id})
}

// handleGroupGet：组详情 + 成员列表（成员管理弹窗用）
func (a *App) handleGroupGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name, idpRef, createdAt string
	err := a.db.QueryRow(`SELECT name, COALESCE(idp_ref,''), created_at FROM user_groups WHERE id=?`, id).
		Scan(&name, &idpRef, &createdAt)
	if err == sql.ErrNoRows {
		notFound(w, r, "组")
		return
	}
	if err != nil {
		failSystem(w, r, "查询组失败")
		return
	}
	members := []map[string]interface{}{}
	rows, qErr := a.db.Query(`SELECT u.id, COALESCE(NULLIF(u.display_name,''), u.username)
		FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? ORDER BY u.id`, id)
	if qErr == nil {
		defer rows.Close()
		for rows.Next() {
			var uid int64
			var uname string
			if rows.Scan(&uid, &uname) == nil {
				members = append(members, map[string]interface{}{"id": uid, "name": uname})
			}
		}
	}
	var resourceCount int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM group_resources WHERE group_id=?`, id).Scan(&resourceCount)
	// resource_ids 必须回显：成员管理弹窗用它做勾选回显与差分（漏回显 = 解绑失效 + 已绑不显示）
	resourceIds := []int64{}
	resRows, rErr := a.db.Query(`SELECT resource_id FROM group_resources WHERE group_id=? ORDER BY resource_id`, id)
	if rErr == nil {
		defer resRows.Close()
		for resRows.Next() {
			var rid int64
			if resRows.Scan(&rid) == nil {
				resourceIds = append(resourceIds, rid)
			}
		}
	}
	writeOK(w, r, map[string]interface{}{
		"id": id, "name": name, "idp_ref": idpRef, "created_at": createdAt,
		"members": members, "resource_count": resourceCount, "resource_ids": resourceIds,
	})
}

// handleGroupResources：组绑定/解绑资源（组详情弹窗"绑定资源"用；变更触发 CCD 重同步）
func (a *App) handleGroupResources(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var exists int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE id=?`, id).Scan(&exists)
	if exists == 0 {
		notFound(w, r, "组")
		return
	}
	var req struct {
		Add    []int64 `json:"add"`
		Remove []int64 `json:"remove"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	// 事务化 + 错误外露（此前逐条自动提交且吞错：部分成功无回滚、绑定不存在资源静默失败）
	tx, err := a.db.Begin()
	if err != nil {
		failSystem(w, r, "开启事务失败")
		return
	}
	defer tx.Rollback()
	for _, rid := range req.Add {
		if _, e := tx.Exec(`INSERT OR IGNORE INTO group_resources(group_id, resource_id) VALUES(?,?)`, id, rid); e != nil {
			failSystem(w, r, "资源绑定失败（有不存在的资源 ID？）")
			return
		}
	}
	for _, rid := range req.Remove {
		if _, e := tx.Exec(`DELETE FROM group_resources WHERE group_id=? AND resource_id=?`, id, rid); e != nil {
			failSystem(w, r, "资源解绑失败")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		failSystem(w, r, "事务提交失败")
		return
	}
	a.syncCCDAsync()
	writeOK(w, r, nil)
}

func (a *App) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var members int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, id).Scan(&members)
	if members > 0 {
		failBiz(w, r, 20004, "组内仍有成员，请先移除")
		return
	}
	res, err := a.db.Exec(`DELETE FROM user_groups WHERE id=?`, id)
	if err != nil {
		failSystem(w, r, "删除组失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "组")
		return
	}
	writeOK(w, r, nil)
}

func (a *App) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var exists int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE id=?`, id).Scan(&exists)
	if exists == 0 {
		notFound(w, r, "组")
		return
	}
	var req struct {
		Add    []int64 `json:"add"`
		Remove []int64 `json:"remove"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		failSystem(w, r, "开启事务失败")
		return
	}
	defer tx.Rollback()
	for _, uid := range req.Add {
		if _, e := tx.Exec(`INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)`, id, uid); e != nil {
			failSystem(w, r, "成员加入失败（有不存在的用户 ID？）")
			return
		}
	}
	for _, uid := range req.Remove {
		if _, e := tx.Exec(`DELETE FROM group_members WHERE group_id=? AND user_id=?`, id, uid); e != nil {
			failSystem(w, r, "成员移除失败")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		failSystem(w, r, "事务提交失败")
		return
	}
	a.syncCCDAsync()
	writeOK(w, r, nil)
}
