package main

import (
	"net/http"
	"net/netip"
	"strconv"
)

func (a *App) handleResourceList(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	keyword := normalizeKeyword(r.URL.Query().Get("keyword"))
	where := "1=1"
	var args []interface{}
	if keyword != "" {
		where = "name LIKE ?"
		args = append(args, "%"+keyword+"%")
	}
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM resources WHERE `+where, args...).Scan(&total); err != nil {
		failSystem(w, r, "统计资源失败")
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(`SELECT id, name, cidr, description,
			(SELECT COUNT(*) FROM group_resources gr WHERE gr.resource_id=resources.id)
		FROM resources WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`, args...)
	if err != nil {
		failSystem(w, r, "查询资源失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var name, cidr, desc string
		var refs int
		if err := rows.Scan(&id, &name, &cidr, &desc, &refs); err != nil {
			failSystem(w, r, "读取资源失败")
			return
		}
		list = append(list, map[string]interface{}{
			"id": id, "name": name, "cidr": cidr, "description": desc, "ref_count": refs,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) handleResourceCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
	}
	if err := jsonDecode(r, &req); err != nil || normalizeKeyword(req.Name) == "" || req.CIDR == "" {
		failParam(w, r, "name 和 cidr 必填")
		return
	}
	if _, err := netip.ParsePrefix(normalizeKeyword(req.CIDR)); err != nil {
		writeFail(w, r, 10002, http.StatusBadRequest, "CIDR 格式不合法（示例 10.0.1.0/24）")
		return
	}
	res, err := a.db.Exec(`INSERT INTO resources(name, cidr, description) VALUES(?,?,?)`,
		normalizeKeyword(req.Name), normalizeKeyword(req.CIDR), req.Description)
	if err != nil {
		failSystem(w, r, "创建资源失败")
		return
	}
	id, _ := res.LastInsertId()
	a.syncCCDAsync()
	writeOK(w, r, map[string]interface{}{"id": id})
}

func (a *App) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var refs int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM group_resources WHERE resource_id=?`, id).Scan(&refs)
	if refs > 0 {
		failBiz(w, r, 20003, "资源仍被组引用，请先解除关联")
		return
	}
	res, err := a.db.Exec(`DELETE FROM resources WHERE id=?`, id)
	if err != nil {
		failSystem(w, r, "删除资源失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "资源")
		return
	}
	writeOK(w, r, nil)
}
