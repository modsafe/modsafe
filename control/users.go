package main

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// cstZone：本产品所有时间戳固定为东八区墙上时间（不依赖进程 TZ 环境）
var cstZone = time.FixedZone("CST", 8*3600)

type userRow struct {
	ID           int64    `json:"id"`
	Username     string   `json:"username"`
	DisplayName  string   `json:"display_name"`
	Email        string   `json:"email"`
	Source       string   `json:"source"`
	Status       string   `json:"status"`
	DeviceQuota  int      `json:"device_quota"`
	TotpEnabled  int      `json:"totp_enabled"`
	CreatedAt    string   `json:"created_at"`
	LastLoginAt  *string  `json:"last_login_at"`
	Groups       []idName `json:"groups"`
}

type idName struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (a *App) handleUserList(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	q := r.URL.Query()
	keyword := normalizeKeyword(q.Get("keyword"))
	source, status, groupId := q.Get("source"), q.Get("status"), q.Get("groupId")

	where := []string{"1=1"}
	var args []interface{}
	if keyword != "" {
		where = append(where, "(u.username LIKE ? OR u.display_name LIKE ?)")
		args = append(args, "%"+keyword+"%", "%"+keyword+"%")
	}
	if source != "" {
		where = append(where, "u.source=?")
		args = append(args, source)
	}
	if status != "" {
		where = append(where, "u.status=?")
		args = append(args, status)
	}
	if groupId != "" {
		where = append(where, "u.id IN (SELECT user_id FROM group_members WHERE group_id=?)")
		args = append(args, groupId)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM users u WHERE `+whereSQL, args...).Scan(&total); err != nil {
		failSystem(w, r, "统计用户失败")
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := a.db.Query(`SELECT u.id,u.username,u.display_name,u.email,u.source,u.status,u.device_quota,COALESCE(u.totp_enabled,0),u.created_at,u.last_login_at
		FROM users u WHERE `+whereSQL+` ORDER BY u.id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		failSystem(w, r, "查询用户失败")
		return
	}
	defer rows.Close()

	list := []userRow{}
	var ids []int64
	for rows.Next() {
		var u userRow
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Source, &u.Status,
			&u.DeviceQuota, &u.TotpEnabled, &u.CreatedAt, &u.LastLoginAt); err != nil {
			failSystem(w, r, "读取用户失败")
			return
		}
		u.Groups = []idName{}
		list = append(list, u)
		ids = append(ids, u.ID)
	}
	if len(ids) > 0 {
		a.attachGroups(r, w, list, ids)
		if w.Header().Get("X-Error") == "1" {
			return
		}
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// 批量取组成员（避免 N+1：单条 IN 查询）
func (a *App) attachGroups(r *http.Request, w http.ResponseWriter, list []userRow, ids []int64) {
	ph := strings.Repeat("?,", len(ids))
	ph = ph[:len(ph)-1]
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := a.db.Query(`SELECT gm.user_id, g.id, g.name FROM group_members gm
		JOIN user_groups g ON g.id=gm.group_id WHERE gm.user_id IN (`+ph+`) ORDER BY g.id`, args...)
	if err != nil {
		failSystem(w, r, "查询组成员失败")
		w.Header().Set("X-Error", "1")
		return
	}
	defer rows.Close()
	idx := map[int64]int{}
	for i := range list {
		idx[list[i].ID] = i
	}
	for rows.Next() {
		var uid int64
		var g idName
		if err := rows.Scan(&uid, &g.ID, &g.Name); err == nil {
			if i, ok := idx[uid]; ok {
				list[i].Groups = append(list[i].Groups, g)
			}
		}
	}
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	// §17.4 License 控制点：创建用户 ≤ max_users（expired/grace 满后同样拒绝）
	if ok, reason := a.licenseAllowsNewUser(); !ok {
		failBiz(w, r, 20007, reason)
		return
	}
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
	}
	if err := jsonDecode(r, &req); err != nil || normalizeKeyword(req.Username) == "" {
		failParam(w, r, "username 必填")
		return
	}
	req.Username = normalizeKeyword(req.Username)
	var exists int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE source='local' AND username=?`, req.Username).Scan(&exists); err != nil {
		failSystem(w, r, "查重失败")
		return
	}
	if exists > 0 {
		failBiz(w, r, 20001, "本地用户名已存在")
		return
	}
	var hash interface{}
	if req.Password != "" {
		// 密码策略：本地账号密码最短 8 位（与门户自助改密同口径；2026-09-30 修复
		// 创建用户无策略校验、弱密码静默创建成功的问题）
		if len([]rune(req.Password)) < 8 {
			failParam(w, r, "初始密码长度不能少于 8 位")
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			failSystem(w, r, "密码加密失败")
			return
		}
		hash = string(h)
	}
	res, err := a.db.Exec(`INSERT INTO users(username, display_name, email, source, password_hash) VALUES(?,?,?,?,?)`,
		req.Username, req.DisplayName, req.Email, "local", hash)
	if err != nil {
		failSystem(w, r, "创建用户失败")
		return
	}
	id, _ := res.LastInsertId()
	a.syncCCDAsync()
	writeOK(w, r, map[string]interface{}{"id": id})
}

func (a *App) handleUserGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var u userRow
	var groupsJSON []byte
	err := a.db.QueryRow(`SELECT id,username,display_name,email,source,status,device_quota,COALESCE(totp_enabled,0),created_at,last_login_at
		FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Source, &u.Status, &u.DeviceQuota, &u.TotpEnabled, &u.CreatedAt, &u.LastLoginAt)
	if err == sql.ErrNoRows {
		notFound(w, r, "用户")
		return
	}
	if err != nil {
		failSystem(w, r, "查询用户失败")
		return
	}
	_ = groupsJSON
	u.Groups = []idName{}
	// attachGroups 按 slice 元素回填，必须传共享底层数组的列表再取出（传值拷贝曾导致详情页 groups 恒空）
	list := []userRow{u}
	a.attachGroups(r, w, list, []int64{id})
	u = list[0]
	writeOK(w, r, u)
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	res, err := a.db.Exec(`DELETE FROM users WHERE id=?`, id)
	if err != nil {
		failSystem(w, r, "删除用户失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "用户")
		return
	}
	// 同步清理无外键的关联行，防孤儿数据（ccd_rules 无主规则 / devices 证书台账空用户）
	_, _ = a.db.Exec(`DELETE FROM ccd_rules WHERE user_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM devices WHERE user_id=?`, id)
	a.syncCCDAsync()
	writeOK(w, r, nil)
}

func (a *App) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Action string `json:"action"` // enable|disable
	}
	if err := jsonDecode(r, &req); err != nil || (req.Action != "enable" && req.Action != "disable") {
		failParam(w, r, "action 必须为 enable|disable")
		return
	}
	status := "disabled"
	if req.Action == "enable" {
		status = "active"
		// §17.4 License 控制点：启用 = 计入授权用户数，必须与创建同等受控
		//（否则 disable→create→enable 可绕过 max_users，2026-09-29 修复）
		if ok, reason := a.licenseAllowsNewUser(); !ok {
			failBiz(w, r, 20007, reason)
			return
		}
	}
	res, err := a.db.Exec(`UPDATE users SET status=? WHERE id=?`, status, id)
	if err != nil {
		failSystem(w, r, "更新状态失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		notFound(w, r, "用户")
		return
	}
	results := []map[string]interface{}{}
	a.syncCCDAsync() // 禁用回收 CCD 文件，启用恢复
	if status == "disabled" {
		// 禁用即踢：跨节点断开其在线会话。
		// 注意：auth-token 存活期内客户端自动重连可静默再入境（§8.6），
		// 再入境拦截需认证链路（oa2/adapter → 控制平面状态校验）接入，为下一迭代项。
		var username string
		_ = a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&username)
		for i := range nodes {
			results = append(results, map[string]interface{}{
				"node": nodes[i].Name, "result": kickOnNode(nodes[i], username, false)})
		}
	}
	writeOK(w, r, map[string]interface{}{"kick_results": results})
}

// handleUserDevices：用户设备列表（用户详情页设备 Tab；devices 表即"证书=设备"）
func (a *App) handleUserDevices(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.db.Query(`SELECT id, COALESCE(cert_cn,''), COALESCE(device_name,''), COALESCE(platform,''),
		COALESCE(fingerprint,''), COALESCE(status,'active'), created_at
		FROM devices WHERE user_id=? ORDER BY id DESC`, id)
	if err != nil {
		failSystem(w, r, "查询设备失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var did int64
		var certCN, deviceName, platform, fp, status, created string
		if rows.Scan(&did, &certCN, &deviceName, &platform, &fp, &status, &created) == nil {
			list = append(list, map[string]interface{}{
				"id": did, "cert_cn": certCN, "device_name": deviceName, "platform": platform,
				"fingerprint": fp, "status": status, "created_at": created,
			})
		}
	}
	writeOK(w, r, pageData(list, len(list), 1, len(list)+1))
}

// handleUserSessions：用户历史会话（控制平面会话台账，含进行中未结算会话）
func (a *App) handleUserSessions(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var username string
	err := a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&username)
	if err == sql.ErrNoRows {
		notFound(w, r, "用户")
		return
	}
	page, pageSize := pageParams(r)
	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username=?`, username).Scan(&total); err != nil {
		failSystem(w, r, "统计会话失败")
		return
	}
	rows, err := a.db.Query(`SELECT connected_at, trusted_ip, virtual_ip, bytes_in, bytes_out,
		last_seen, settled, node
		FROM sessions WHERE username=? ORDER BY connected_at DESC LIMIT ? OFFSET ?`,
		username, pageSize, (page-1)*pageSize)
	if err != nil {
		failSystem(w, r, "查询会话失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	now := time.Now()
	for rows.Next() {
		var connectedAt, trustedIP, virtualIP, node string
		var in, out, settled int64
		var lastSeen *string
		if err := rows.Scan(&connectedAt, &trustedIP, &virtualIP, &in, &out, &lastSeen, &settled, &node); err != nil {
			continue
		}
		// 所有时间戳均为东八区墙上时间文本；用固定时区解析（进程 TZ 可能是 UTC）
		st := "已结束"
		duration := int64(0)
		if settled == 0 {
			st = "在线"
		}
		t0parsed := time.Time{}
		t0, pErr := time.ParseInLocation("2006-01-02 15:04:05", connectedAt, cstZone)
		if pErr != nil {
			log.Printf("[sessions] parse connected_at %q: %v", connectedAt, pErr)
		} else {
			t0parsed = t0
		}
		if !t0parsed.IsZero() {
			end := now
			if settled == 1 && lastSeen != nil {
				if t1, p2 := time.ParseInLocation("2006-01-02 15:04:05", *lastSeen, cstZone); p2 == nil {
					end = t1
				}
			}
			duration = int64(end.Sub(t0).Seconds())
			if duration < 0 {
				duration = 0
			}
		}
		list = append(list, map[string]interface{}{
			"connected_at": connectedAt, "trusted_ip": trustedIP, "virtual_ip": virtualIP,
			"bytes_in": in, "bytes_out": out, "duration": duration, "node": node, "state": st,
		})
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// handleUserTraffic：用户流量聚合（控制平面会话台账）
func (a *App) handleUserTraffic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var username string
	err := a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&username)
	if err == sql.ErrNoRows {
		notFound(w, r, "用户")
		return
	}
	var totalIn, totalOut, count int64
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COUNT(*)
		FROM sessions WHERE username=?`, username).Scan(&totalIn, &totalOut, &count)
	rows, err := a.db.Query(`SELECT strftime('%m-%d', connected_at) AS day,
		COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM sessions WHERE username=? GROUP BY day ORDER BY day`, username)
	if err != nil {
		failSystem(w, r, "聚合流量失败")
		return
	}
	defer rows.Close()
	daily := []map[string]interface{}{}
	for rows.Next() {
		var day string
		var bi, bo int64
		if rows.Scan(&day, &bi, &bo) == nil {
			daily = append(daily, map[string]interface{}{"day": day, "bytes_in": bi, "bytes_out": bo})
		}
	}
	writeOK(w, r, map[string]interface{}{
		"total_bytes_in": totalIn, "total_bytes_out": totalOut,
		"session_count": count, "daily": daily,
	})
}

func (a *App) handleUserKick(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var username string
	err := a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&username)
	if err == sql.ErrNoRows {
		notFound(w, r, "用户")
		return
	}
	if err != nil {
		failSystem(w, r, "查询用户失败")
		return
	}
	results := []map[string]interface{}{}
	for i := range nodes {
		results = append(results, map[string]interface{}{
			"node": nodes[i].Name, "result": kickOnNode(nodes[i], username, false)})
	}
	writeOK(w, r, map[string]interface{}{"results": results})
}

// handleUserPasswordReset：管理员重置本地用户密码（2026-09-30）。
// 仅 source=local——IM 账号密码权威在认证源（钉钉/企微/飞书/AD），VPN 走 webauth 不用密码；
// 策略与 handleUserCreate/门户改密同口径（≥8 位）；72 字节显式上限（bcrypt 静默截断防护）。
// 审计由 requireRoles 写方法钩子自动落 audit_admin 月表（密码不入路径/日志）。
func (a *App) handleUserPasswordReset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Password string `json:"password"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Password == "" {
		failParam(w, r, "password 必填")
		return
	}
	if len([]rune(req.Password)) < 8 {
		failParam(w, r, "新密码长度不能少于 8 位")
		return
	}
	if len(req.Password) > 72 {
		failParam(w, r, "密码过长（最多 72 字节）")
		return
	}
	var source string
	err := a.db.QueryRow(`SELECT source FROM users WHERE id=?`, id).Scan(&source)
	if err == sql.ErrNoRows {
		notFound(w, r, "用户")
		return
	}
	if err != nil {
		failSystem(w, r, "查询用户失败")
		return
	}
	if source != "local" {
		failBiz(w, r, 20010, "仅本地账号支持密码重置；该账号密码由企业认证源管理")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		failSystem(w, r, "密码加密失败")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(h), id); err != nil {
		failSystem(w, r, "重置失败")
		return
	}
	writeOK(w, r, map[string]interface{}{"reset": true})
}
