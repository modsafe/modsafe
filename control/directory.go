package main

// §23 目录同步（拉取式）：从 IM 通讯录导入用户/部门→组，预分配权限走组绑资源（§14）。
// adapter 提供统一目录（GET /admin/directory/{idp}），本模块做 diff + 事务式应用。
//
// 同步语义（与 §23 对齐，v1 收敛）：
//   - 匹配键 = username（同 source；与 auth-check 自动建档同键）
//   - 已有用户：只更新 display_name/email/external_id，不动 status（管理员手动禁用不被覆盖）
//   - 通讯录中消失的该源用户 → 禁用（不删，历史/审计保留）
//   - 部门 → 组（idp_ref = "idp:dept_id" 标记同步组）；同步组成员完全对齐目录
//     （手动往同步组加人会下次同步被移除——手工组请用普通组，文档明示）
//   - 权限预分配：同步完成后在管理台给组绑资源/CCD 规则（既有功能）

import (
	"log"
	"net/http"
	"strconv"
)

type dirDepartment struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Parent string `json:"parent"`
}

type dirUser struct {
	ExternalID string   `json:"external_id"`
	UnionID    string   `json:"union_id"` // OAuth sub（扫码登录的 stable 锚点；dingtalk: unionid≠userid）
	Name       string   `json:"name"`
	Email      string   `json:"email"`
	DeptIDs    []string `json:"dept_ids"`
}

type directoryDoc struct {
	IDP         string          `json:"idp"`
	Departments []dirDepartment `json:"departments"`
	Users       []dirUser       `json:"users"`
}

var directoryIDPs = map[string]bool{"dingtalk": true, "wecom": true, "feishu": true}

func (a *App) fetchDirectory(idp string) (*directoryDoc, string) {
	out, err := adapterAdmin("GET", "/admin/directory/"+idp, nil)
	if err != nil {
		return nil, "通讯录拉取失败（adapter 不可达）：" + err.Error()
	}
	if e, ok := out["error"].(string); ok && e != "" {
		return nil, e
	}
	doc := &directoryDoc{}
	doc.IDP, _ = out["idp"].(string)
	if raw, ok := out["departments"].([]interface{}); ok {
		for _, r := range raw {
			if m, ok := r.(map[string]interface{}); ok {
				d := dirDepartment{}
				d.ID, _ = m["id"].(string)
				d.Name, _ = m["name"].(string)
				d.Parent, _ = m["parent"].(string)
				if d.ID != "" && d.Name != "" && d.ID != "1" { // 根部门不建组
					doc.Departments = append(doc.Departments, d)
				}
			}
		}
	}
	if raw, ok := out["users"].([]interface{}); ok {
		for _, r := range raw {
			if m, ok := r.(map[string]interface{}); ok {
				u := dirUser{}
				u.ExternalID, _ = m["external_id"].(string)
				u.UnionID, _ = m["union_id"].(string)
				u.Name, _ = m["name"].(string)
				u.Email, _ = m["email"].(string)
				if ids, ok := m["dept_ids"].([]interface{}); ok {
					for _, i := range ids {
						if s, ok := i.(string); ok {
							u.DeptIDs = append(u.DeptIDs, s)
						}
					}
				}
				if u.Name != "" {
					doc.Users = append(doc.Users, u)
				}
			}
		}
	}
	return doc, ""
}

type dirDiff struct {
	NewUsers    []string `json:"new_users"`
	UpdateUsers []string `json:"update_users"`
	DisableUsers []string `json:"disable_users"`
	NewGroups   []string `json:"new_groups"`
	Warn        string   `json:"warn,omitempty"`
}

// handleDirectoryPreview：拉取 + diff，不落库（dry-run，§23 确认制）
func (a *App) handleDirectoryPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDP string `json:"idp"`
	}
	if err := jsonDecode(r, &req); err != nil || !directoryIDPs[req.IDP] {
		failParam(w, r, "idp 仅支持 dingtalk/wecom/feishu")
		return
	}
	doc, errMsg := a.fetchDirectory(req.IDP)
	if errMsg != "" {
		writeFail(w, r, 50004, http.StatusBadGateway, errMsg)
		return
	}
	diff := a.buildDirectoryDiff(req.IDP, doc)
	writeOK(w, r, map[string]interface{}{
		"idp": req.IDP, "directory_users": len(doc.Users),
		"directory_departments": len(doc.Departments), "diff": diff,
	})
}

func (a *App) buildDirectoryDiff(idp string, doc *directoryDoc) *dirDiff {
	diff := &dirDiff{NewUsers: []string{}, UpdateUsers: []string{}, DisableUsers: []string{}, NewGroups: []string{}}
	dirNames := map[string]bool{}
	for _, u := range doc.Users {
		dirNames[u.Name] = true
	}
	rows, err := a.db.Query(`SELECT username, status FROM users WHERE source=?`, idp)
	if err == nil {
		type exist struct {
			name   string
			status string
		}
		var exists []exist
		for rows.Next() {
			var e exist
			if rows.Scan(&e.name, &e.status) == nil {
				exists = append(exists, e)
			}
		}
		rows.Close()
		for _, e := range exists {
			if !dirNames[e.name] && e.status == "active" {
				diff.DisableUsers = append(diff.DisableUsers, e.name)
			}
		}
	}
	for _, u := range doc.Users {
		var cnt int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE source=? AND username=?`, idp, u.Name).Scan(&cnt)
		if cnt > 0 {
			diff.UpdateUsers = append(diff.UpdateUsers, u.Name)
		} else {
			diff.NewUsers = append(diff.NewUsers, u.Name)
		}
	}
	for _, d := range doc.Departments {
		var cnt int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE idp_ref=?`, idp+":"+d.ID).Scan(&cnt)
		if cnt == 0 {
			diff.NewGroups = append(diff.NewGroups, d.Name)
		}
	}
	return diff
}

// handleDirectorySync：事务式应用（全成功才提交）+ CCD 重同步
func (a *App) handleDirectorySync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDP     string `json:"idp"`
		Disable *bool  `json:"disable_missing"` // nil=默认禁用；显式 false 才跳过（此前被强制 true）
	}
	if err := jsonDecode(r, &req); err != nil || !directoryIDPs[req.IDP] {
		failParam(w, r, "idp 仅支持 dingtalk/wecom/feishu")
		return
	}
	doc, errMsg := a.fetchDirectory(req.IDP)
	if errMsg != "" {
		writeFail(w, r, 50004, http.StatusBadGateway, errMsg)
		return
	}
	disableMissing := req.Disable == nil || *req.Disable
	// 护栏：拉到空目录时禁止执行"消失禁用"（IM 接口分页异常/权限部分成功返回 200 空表，
	// 曾可导致该源全部用户被一键禁用，2026-09-29 修复）
	if disableMissing && len(doc.Users) == 0 {
		writeFail(w, r, 50004, http.StatusBadGateway, "通讯录拉取结果为空，已拒绝执行同步（防止误禁全部用户）；请检查 IdP 权限后重试")
		return
	}

	tx, err := a.db.Begin()
	if err != nil {
		failSystem(w, r, "开启事务失败")
		return
	}
	defer tx.Rollback()

	created, updated, disabled := 0, 0, 0
	// 1) 用户 upsert（2026-09-30 同名支持）：
	//    匹配优先级 union_id → external_id → (source, username)，命中即更新；
	//    全部未命中 = 新用户，username 与既有行同名时加 "-" + external_id 后 6 位消歧
	//    （同企业两人同名：先来者保留原名，后来者消歧；union_id 保证扫码绑定各自身份）
	inDir := map[string]bool{}        // 本轮同步确认在册的 username（disable 判定基线）
	nameByExt := map[string]string{} // doc external_id → 分配/命中的 username（external_id 回填用）
	uidByExt := map[string]int64{}   // doc external_id → 行 id（组对齐用；2026-10-01 #62：
	// 组对齐此前按目录姓名重新查行，与本级三级匹配/消歧脱节——昵称行（扫码先建）与消歧名
	// （张三-x1x2）都会查不到或查错行，导致组员张冠李戴/漏挂）
	for _, u := range doc.Users {
		var uid int64
		var rowName string
		matched := false
		if u.UnionID != "" {
			if e := tx.QueryRow(`SELECT id, username FROM users WHERE source=? AND union_id=?`, req.IDP, u.UnionID).Scan(&uid, &rowName); e == nil {
				matched = true
			}
		}
		if !matched && u.ExternalID != "" {
			if e := tx.QueryRow(`SELECT id, username FROM users WHERE source=? AND external_id=?`, req.IDP, u.ExternalID).Scan(&uid, &rowName); e == nil {
				matched = true
			}
		}
		if !matched {
			if e := tx.QueryRow(`SELECT id, username FROM users WHERE source=? AND username=?`, req.IDP, u.Name).Scan(&uid, &rowName); e == nil {
				matched = true
			}
		}
		if matched {
			if _, e := tx.Exec(`UPDATE users SET display_name=?, email=? WHERE id=?`,
				u.Name, u.Email, uid); e != nil {
				writeFail(w, r, 50001, http.StatusInternalServerError, "用户更新失败（"+u.Name+"）")
				return
			}
			// 回填 union_id（扫码 OAuth sub=unionid，回填后扫码登录按 union_id 精确绑定）
			if u.UnionID != "" {
				if _, e := tx.Exec(`UPDATE users SET union_id=? WHERE id=? AND COALESCE(union_id,'')=''`,
					u.UnionID, uid); e != nil {
					writeFail(w, r, 50001, http.StatusInternalServerError, "union_id 回填失败")
					return
				}
			}
		inDir[rowName] = true
		nameByExt[u.ExternalID] = rowName
		if u.ExternalID != "" {
			uidByExt[u.ExternalID] = uid
		}
		updated++
		continue
	}
		// §17.4 License 控制点：目录导入同样受 max_users 约束（2026-09-29 补齐）
		if ok, reason := a.licenseAllowsNewUser(); !ok {
			writeFail(w, r, 20007, http.StatusBadRequest, "导入中止（已导入 "+strconv.Itoa(created)+" 人）："+reason)
			return
		}
		newName := u.Name
		var taken int
		_ = tx.QueryRow(`SELECT COUNT(*) FROM users WHERE source=? AND username=?`, req.IDP, newName).Scan(&taken)
		if taken > 0 {
			// 同名：username 加 external_id 后 6 位消歧（确定性，跨次同步稳定）
			suffix := u.ExternalID
			if len(suffix) > 6 {
				suffix = suffix[len(suffix)-6:]
			}
			newName = u.Name + "-" + suffix
		}
		res, e := tx.Exec(`INSERT INTO users(username, display_name, email, source, external_id, union_id, status)
			VALUES(?,?,?,?,?,?,'active')`, newName, u.Name, u.Email, req.IDP, u.ExternalID, u.UnionID)
		if e != nil {
			writeFail(w, r, 50001, http.StatusInternalServerError, "用户写入失败（"+u.Name+"）：")
			return
		}
		newUID, _ := res.LastInsertId()
		inDir[newName] = true
		nameByExt[u.ExternalID] = newName
		if u.ExternalID != "" {
			uidByExt[u.ExternalID] = newUID
		}
		created++
	}
	// 1.5) external_id 空值回填（历史行：按 username 对齐补 doc external_id）
	for _, u := range doc.Users {
		if u.ExternalID != "" {
			_, _ = tx.Exec(`UPDATE users SET external_id=? WHERE source=? AND username=? AND COALESCE(external_id,'')=''`,
				u.ExternalID, req.IDP, nameByExt[u.ExternalID])
		}
	}
	// 2) 消失用户禁用（判定基于本轮在册名单 inDir；同名消歧名已含其中）
	var disabledNames []string // 事务提交后跨节点踢线用（BIZ-4：不在事务内做网络 I/O）
	if disableMissing {
		if rows, err := tx.Query(`SELECT id, username, status FROM users WHERE source=?`, req.IDP); err == nil {
			type row struct {
				id   int64
				name string
				st   string
			}
			var all []row
			for rows.Next() {
				var x row
				if rows.Scan(&x.id, &x.name, &x.st) == nil {
					all = append(all, x)
				}
			}
			rows.Close()
			for _, x := range all {
				if !inDir[x.name] && x.st == "active" {
					if _, e := tx.Exec(`UPDATE users SET status='disabled' WHERE id=?`, x.id); e == nil {
						disabled++
						disabledNames = append(disabledNames, x.name)
					}
				}
			}
		}
	}
	// 3) 部门 → 组 + 成员对齐
	groupsBound := 0
	for _, d := range doc.Departments {
		ref := req.IDP + ":" + d.ID
		var gid int64
		err := tx.QueryRow(`SELECT id FROM user_groups WHERE idp_ref=?`, ref).Scan(&gid)
		if err != nil {
			// 仅认领"无同步锚点的纯手工组"（管理员预建）；此前按 name 无条件认领，
			// 同名部门（跨分支/跨 IdP 常见）会互相抢锚点并清空对方成员，2026-09-29 修复
			if e2 := tx.QueryRow(`SELECT id FROM user_groups WHERE name=? AND idp_ref=''`, d.Name).Scan(&gid); e2 == nil {
				if _, e := tx.Exec(`UPDATE user_groups SET idp_ref=? WHERE id=?`, ref, gid); e != nil {
					writeFail(w, r, 50001, http.StatusInternalServerError, "组接管失败（"+d.Name+"）")
					return
				}
			} else {
				// 同名组已被其他锚点占用 → 名称加部门 ID 消歧，避免 UNIQUE 冲突整批失败
				gname := d.Name
				var taken int
				_ = tx.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE name=?`, gname).Scan(&taken)
				if taken > 0 {
					gname = d.Name + "(" + d.ID + ")"
				}
				res, e := tx.Exec(`INSERT INTO user_groups(name, idp_ref) VALUES(?,?)`, gname, ref)
				if e != nil {
					writeFail(w, r, 50001, http.StatusInternalServerError, "组创建失败（"+gname+"）："+e.Error())
					return
				}
				gid, _ = res.LastInsertId()
			}
		}
		// 成员对齐（2026-09-30 修订）：仅对同步源用户按目录对齐；
		// 跨源手工成员（local/portal 等管理员手动挂入的账号）保留——目录不是他们的权威源。
		// 旧实现整组 DELETE 再装回，手工加入同步组的本地账号会在下次同步被清掉。
		cur, cerr := func() (map[int64]string, error) {
			m := map[int64]string{}
			rows, e := tx.Query(`SELECT gm.user_id, COALESCE(u.source,'') FROM group_members gm
				JOIN users u ON u.id=gm.user_id WHERE gm.group_id=?`, gid)
			if e != nil {
				return m, e
			}
			defer rows.Close()
			for rows.Next() {
				var uid int64
				var src string
				if rows.Scan(&uid, &src) == nil {
					m[uid] = src
				}
			}
			return m, rows.Err()
		}()
		if cerr != nil {
			writeFail(w, r, 50001, http.StatusInternalServerError, "成员读取失败（"+d.Name+"）：")
			return
		}
		desired := map[int64]bool{}
		for _, u := range doc.Users {
			if !containsStr(u.DeptIDs, d.ID) {
				continue
			}
			// #62：用主循环三级匹配得到的行 id（含消歧名/昵称行的正确归属），
			// 不再按目录姓名重新查——同名消歧与昵称先行用户曾在此被查错/漏挂
			uid, ok := uidByExt[u.ExternalID]
			if !ok {
				continue
			}
			desired[uid] = true
			if _, already := cur[uid]; !already {
				if _, e := tx.Exec(`INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)`, gid, uid); e == nil {
					groupsBound++
				}
			}
		}
		for uid, src := range cur {
			// 只移除"同步源内、目录已不在该部门"的成员；跨源手工成员不动
			if src == req.IDP && !desired[uid] {
				if _, e := tx.Exec(`DELETE FROM group_members WHERE group_id=? AND user_id=?`, gid, uid); e != nil {
					writeFail(w, r, 50001, http.StatusInternalServerError, "成员移除失败（"+d.Name+"）")
					return
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		failSystem(w, r, "事务提交失败（未产生任何变更）")
		return
	}
	a.syncCCDAsync()
	// BIZ-4（2026-10-11）：通讯录移除而禁用的用户与管理台手动禁用（users.go handleUserStatus）
	// 同效——跨节点踢线，否则离职员工已建立的在线会话可一直保持到自然断开
	//（重连会被认证链路拒绝，但在册会话不受影响）。放在事务提交后执行
	for _, name := range disabledNames {
		for i := range nodes {
			res := kickOnNode(nodes[i], name, false)
			if errs, _ := res["errors"].([]string); len(errs) > 0 {
				log.Printf("[directory] 禁用用户 %s 在 %s 踢线失败: %v", name, nodes[i].Name, errs)
			}
		}
	}
	writeOK(w, r, map[string]interface{}{
		"idp": req.IDP, "created": created, "updated": updated, "disabled": disabled,
		"groups": len(doc.Departments), "members_bound": groupsBound,
		"notice": "导入完成：部门已同步为组；请在组织管理中为组绑定资源以分配访问权限（CCD 已自动重同步）",
	})
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
