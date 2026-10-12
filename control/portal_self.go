package main

// /api/v1/self/*（§16.3）：员工本人操作端点。
// 红线：全部端点不接受任何 user_id 参数，主体恒取门户 JWT；他人资源一律 404（不暴露存在性）。

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

// GET /api/v1/self/me
func (a *App) handleSelfMe(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	var username, display, email, source string
	var quota int
	err := a.db.QueryRow(`SELECT username, COALESCE(display_name,''), COALESCE(email,''), source, device_quota
		FROM users WHERE id=?`, pc.UserID).Scan(&username, &display, &email, &source, &quota)
	if err != nil {
		notFound(w, r, "用户")
		return
	}
	// 在线状态（当前会话）。#129：virtual_ip 为空的会话是卡在认证等待的僵尸实例
	//（CLIENT_LIST 会列出但未分配地址）——不算在线，否则门户一键连接被
	// 「当前已连接(IP -)」误拦，用户无法发起真正的连接。
	// 2026-10-11（DSF-2）：判定改读 sessions 台账（settled=0 + last_seen 新鲜度，
	// 阈值与 monitor.go 的 onlineFreshTTL 同源），不再遍历 liveSessions()——
	// 监控数据源故障时不再误报在线/离线
	online := false
	vip := ""
	var seenVIP string
	if a.db.QueryRow(`SELECT virtual_ip FROM sessions
		WHERE username=? AND settled=0 AND virtual_ip<>'' AND last_seen>=`+onlineFreshCond()+
		` LIMIT 1`, username).Scan(&seenVIP) == nil {
		online = true
		vip = seenVIP
	}
	var devices int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND status='active'`, pc.UserID).Scan(&devices)
	// 双因素状态（2026-10-06）：绑定态 + 租户策略是否命中（前端据此渲染强制绑定页/我的页开关）
	totpEnabled, _, totpSource := a.userTotpState(pc.UserID)
	// latest_profile：最新设备的 .ovpn 名（§25 一键连接的 GUI 配置名，导入时保持原文件名即匹配）
	latestProfile := ""
	_ = a.db.QueryRow(`SELECT device_name FROM devices WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1`,
		pc.UserID).Scan(&latestProfile)
	if latestProfile != "" {
		// §25.4：profile 名必须 ASCII（launcher 白名单 + GUI 文件名安全）；
		// username 可能是中文（IM 昵称）→ 统一用 u{用户ID} 前缀
		latestProfile = fmt.Sprintf("u%d-%s", pc.UserID, sanitizeCCDName(latestProfile))
	}
	writeOK(w, r, map[string]interface{}{
		"user_id": pc.UserID,
		"username": username, "display_name": display, "email": email, "source": source,
		"online": online, "virtual_ip": vip,
		"device_quota": quota, "device_used": devices,
		"onboarded": devices > 0,
		"is_local": source == "local",
		"latest_profile": latestProfile,
		"totp_enabled": totpEnabled,
		"totp_required": userTotpPolicyHits(a, totpSource),
	})
}

// GET /api/v1/self/devices：我的设备 + 配额
func (a *App) handleSelfDevices(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	rows, err := a.db.Query(`SELECT id, cert_cn, COALESCE(platform,''), COALESCE(fingerprint,''),
		COALESCE(created_at,''), status FROM devices WHERE user_id=? ORDER BY id DESC`, pc.UserID)
	if err != nil {
		failSystem(w, r, "查询设备失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var cn, platform, fp, created, status string
		if rows.Scan(&id, &cn, &platform, &fp, &created, &status) == nil {
			list = append(list, map[string]interface{}{
				"id": id, "cert_cn": cn, "platform": platform,
				"fingerprint": maskFingerprint(fp), "created_at": created, "status": status,
			})
		}
	}
	var quota, used int
	_ = a.db.QueryRow(`SELECT device_quota FROM users WHERE id=?`, pc.UserID).Scan(&quota)
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND status='active'`, pc.UserID).Scan(&used)
	writeOK(w, r, map[string]interface{}{"list": list, "quota": quota, "used": used})
}

// maskFingerprint：脱敏（前 8 后 8，§12.2 设备列表约定）
func maskFingerprint(fp string) string {
	if len(fp) <= 24 {
		return fp
	}
	return fp[:12] + "…" + fp[len(fp)-12:]
}

// GET /api/v1/self/sessions：我的连接历史（台账）
func (a *App) handleSelfSessions(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	page, pageSize := pageParams(r)
	var total int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username=?`, pc.Username).Scan(&total)
	rows, err := a.db.Query(`SELECT virtual_ip, trusted_ip, node, connected_at, COALESCE(last_seen,''),
		bytes_in, bytes_out, COALESCE(settled,0) FROM sessions WHERE username=?
		ORDER BY COALESCE(NULLIF(last_seen,''), connected_at) DESC LIMIT ? OFFSET ?`,
		pc.Username, pageSize, (page-1)*pageSize)
	if err != nil {
		failSystem(w, r, "查询历史失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var vip, tip, node, conn, seen string
		var bi, bo int64
		var settled int
		if rows.Scan(&vip, &tip, &node, &conn, &seen, &bi, &bo, &settled) == nil {
			list = append(list, map[string]interface{}{
				"virtual_ip": vip, "trusted_ip": tip, "node": node,
				"connected_at": conn, "last_seen": seen,
				"bytes_in": bi, "bytes_out": bo, "online": settled == 0,
			})
		}
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// GET /api/v1/self/usage：我的流量按日聚合（近 30 天）。
// 2026-09-30 起读 traffic_daily（session_tracker 每 5s 增量入账，跨天会话按实际发生日拆分），
// 不再按"会话整桶记入 last_seen 日"聚合。
func (a *App) handleSelfUsage(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	rows, err := a.db.Query(`SELECT day, COALESCE(bytes_in,0), COALESCE(bytes_out,0)
		FROM traffic_daily WHERE username=? AND day >= date('now','-29 days','localtime')
		ORDER BY day`, pc.Username)
	if err != nil {
		failSystem(w, r, "查询统计失败")
		return
	}
	defer rows.Close()
	type day struct {
		Date string `json:"date"`
		In   int64  `json:"in"`
		Out  int64  `json:"out"`
	}
	days := []day{}
	var tIn, tOut int64
	for rows.Next() {
		var d day
		if rows.Scan(&d.Date, &d.In, &d.Out) == nil {
			days = append(days, d)
			tIn += d.In
			tOut += d.Out
		}
	}
	writeOK(w, r, map[string]interface{}{"days": days, "total_in": tIn, "total_out": tOut})
}

// POST /api/v1/self/devices/client-config：为自己生成 .ovpn 下载 token（§15 同一底层）
func (a *App) handleSelfClientConfig(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	var req struct {
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
	}
	// 自助生成冷却（防 generate↔revoke 循环拖垮认证链路的员工级 DoS 面）
	if !selfGenCooler.allow(fmt.Sprintf("gen|%d", pc.UserID)) {
		writeFail(w, r, 20010, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}
	_ = jsonDecode(r, &req)
	token, code, msg := a.issueClientConfigForUser(pc.UserID, req.DeviceName, req.Platform)
	if code != 0 {
		writeFail(w, r, code, http.StatusBadRequest, msg)
		return
	}
	// B 方案：随下载 token 一起签发一次性连接 ticket（深链 &g= 传给客户端，
	// webauth 时回传 grant 参数换静默发码；strict 策略下这是 oa2 回调唯一静默通道）
	writeOK(w, r, map[string]interface{}{
		"download_url":   "/api/v1/client-config/" + token,
		"connect_grant":  issueConnectGrant(pc.UserID),
		"grant_expires_in": 300,
	})
}

// DELETE /api/v1/self/devices/{id}：吊销自己的设备（恒定 user_id 条件；他人/不存在 → 同一 404）
func (a *App) handleSelfDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.selfDeviceDelete(w, r, id, r.PathValue("id"))
}

// POST /api/v1/self/devices/delete：自助吊销的固定路由形态（请求体传 id）。
// 与 DELETE /self/devices/{id} 同逻辑同审计；供门户固定端点调用（客户端不拼接动态路径）
func (a *App) handleSelfDeviceDeleteByBody(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := jsonDecode(r, &req); err != nil || req.ID < 1 {
		failParam(w, r, "id 不合法")
		return
	}
	a.selfDeviceDelete(w, r, req.ID, strconv.FormatInt(req.ID, 10))
}

func (a *App) selfDeviceDelete(w http.ResponseWriter, r *http.Request, id int64, idRaw string) {
	pc := portalClaimsOf(r)
	var certCN string
	err := a.db.QueryRow(`SELECT cert_cn FROM devices WHERE id=? AND user_id=? AND status='active'`,
		id, pc.UserID).Scan(&certCN)
	if err != nil {
		notFound(w, r, "设备")
		return
	}
	_, _ = a.db.Exec(`UPDATE devices SET status='revoked' WHERE id=?`, id)
	a.auditAdminAction(r, pc.Username, "DELETE", "/api/v1/self/devices/"+idRaw, "success", "自助吊销设备 "+certCN)
	a.syncCCDAsync()
	kicked := []map[string]interface{}{}
	for i := range nodes {
		res := kickOnNode(nodes[i], certCN, false)
		kicked = append(kicked, map[string]interface{}{"node": nodes[i].Name, "result": res})
	}
	// BIZ-2（2026-10-11）：strict 绑定下自助吊销与管理台吊销（certs_api.go handleDeviceRevoke）
	// 同效——重推 CRL 使该证书在 TLS 层即时作废；否则 auth-token 存活期内被吊销证书
	// 仍可静默重连。off 模式维持软吊销语义（不推）
	if certBinding(a) == "strict" {
		if err := a.pushCRL(); err != nil {
			log.Printf("[self-revoke] %s CRL 推送失败（TLS 层拦截未更新，请重试吊销）: %v", pc.Username, err)
		}
	}
	writeOK(w, r, map[string]interface{}{"revoked": true, "cert_cn": certCN, "kick_results": kicked})
}

// POST /api/v1/self/disconnect：客户端/门户乐观下线（断开感知 DSF-4，2026-10-11）。
// 主体恒取门户 JWT（不接受任何 user_id 参数）。会话级精确踢的目标 vip 由服务端从
// sessions 台账解析（与 /self/me 同口径：settled=0 + last_seen 新鲜 + 非空 LIMIT 1），
// 不采信请求体回传——客户端可见的本来就只有这一条会话；无新鲜会话时按用户名全节点踢。
// 任一节点返回成功或「会话不存在/已下线」即视为断开成功并立即结算台账；全部节点
// 失败/不可达则不结算（绝不把未确认的断开当成功，漏结算由 tracker 下一轮 diff 兜底）。
// 幂等：重复调用无副作用（会话已不在时踢线无匹配，已结算行不再更新）。
func (a *App) handleSelfDisconnect(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	var username string
	if err := a.db.QueryRow(`SELECT username FROM users WHERE id=?`, pc.UserID).Scan(&username); err != nil {
		notFound(w, r, "用户")
		return
	}
	vip := ""
	_ = a.db.QueryRow(`SELECT virtual_ip FROM sessions
		WHERE username=? AND settled=0 AND virtual_ip<>'' AND last_seen>=`+onlineFreshCond()+
		` LIMIT 1`, username).Scan(&vip)
	results := []map[string]interface{}{}
	disconnected := false
	for i := range nodes {
		var res map[string]interface{}
		if vip != "" {
			res = kickOnNode(nodes[i], "", false, vip) // 会话级精确踢（与 tracker 空闲踢线同形态）
		} else {
			res = kickOnNode(nodes[i], username, false) // 按用户名踢（与 handleSessionKick 同用法）
		}
		results = append(results, map[string]interface{}{"node": nodes[i].Name, "result": res})
		if ok, _ := res["ok"].(bool); ok {
			disconnected = true
			continue
		}
		// local 节点可确认「会话不存在/已下线」：status 可读（errors 为空）但无匹配会话。
		// agent 节点的「未找到匹配会话」经 agentKick 只剩 "agent /kick: HTTP 500" 级错误
		// 文本（agent 端 mgmtKill 对未命中与真实失败同样回 500），不可区分——一律按节点
		// 失败处理，误漏的结算由 tracker 下一轮 diff 兜底（约 5~10s）
		if nodes[i].Kind != "agent" {
			if errs, _ := res["errors"].([]string); len(errs) == 0 {
				disconnected = true
			}
		}
	}
	if disconnected {
		if vip != "" {
			_, _ = a.db.Exec(`UPDATE sessions SET settled=1, last_seen=datetime('now','localtime')
				WHERE username=? AND settled=0 AND virtual_ip=?`, username, vip)
		} else {
			_, _ = a.db.Exec(`UPDATE sessions SET settled=1, last_seen=datetime('now','localtime')
				WHERE username=? AND settled=0`, username)
		}
	}
	log.Printf("[self-disconnect] 用户=%s vip=%q settled=%t results=%v", username, vip, disconnected, results)
	writeOK(w, r, map[string]interface{}{"results": results, "settled": disconnected})
}

// POST /api/v1/self/password：本地账号改密（LDAP/IM 用户返回引导提示）
func (a *App) handleSelfPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Old == "" || req.New == "" {
		failParam(w, r, "旧密码和新密码不能为空")
		return
	}
	var source, hash string
	targetID := pc.UserID
	if err := a.db.QueryRow(`SELECT source, COALESCE(password_hash,'') FROM users WHERE id=?`, pc.UserID).
		Scan(&source, &hash); err != nil {
		notFound(w, r, "用户")
		return
	}
	if source != "local" {
		// 扫码会话：若存在同名本地账号，允许凭旧密码修改本地行
		//（知道当前密码即账号主人；解决"本地账号被扫码会话遮蔽后无法自助改密"，2026-09-30）
		var lid int64
		var lhash string
		e2 := a.db.QueryRow(`SELECT id, COALESCE(password_hash,'') FROM users
			WHERE username=? AND source='local' AND status='active'`, pc.Username).Scan(&lid, &lhash)
		if e2 != nil || lhash == "" {
			failBiz(w, r, 20010, "当前账号密码由企业认证源管理，请在钉钉/企微/飞书或 AD 中修改")
			return
		}
		targetID, source, hash = lid, "local", lhash
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Old)) != nil {
		writeFail(w, r, 30004, http.StatusBadRequest, "旧密码不正确")
		return
	}
	if len([]rune(req.New)) < 8 {
		failParam(w, r, "新密码长度不能少于 8 位")
		return
	}
	if req.New == req.Old {
		failParam(w, r, "新密码不能与旧密码相同")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		failSystem(w, r, "密码加密失败")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(newHash), targetID); err != nil {
		failSystem(w, r, "修改失败")
		return
	}
	a.auditAdminAction(r, pc.Username, "POST", "/api/v1/self/password", "success", "门户自助改密")
	// 强制重登：清 cookie，前端跳登录
	http.SetCookie(w, &http.Cookie{Name: portalCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeOK(w, r, map[string]interface{}{"changed": true})
}
