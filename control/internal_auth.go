package main

// 内部端点：供 idp-adapter 认证时反查（§16.4 水平越权红线不适用——这是机器对机器通道，
// 用 /opt/modsafe/admin-token 做共享令牌，仅监听 localhost 调用）。
// 职责（§②认证链路）：存在性检查 / 禁用拦截 / IM 用户自动建档 / last_login 更新 / 认证审计 / CCD 单用户同步。

import (
	"crypto/subtle"
	"database/sql"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func internalToken() string {
	b, err := os.ReadFile(envOr("MODSAFE_ADMIN_TOKEN_FILE", "/opt/modsafe/admin-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// internalAuthed：共享令牌校验（常数时间比较）+ 回环地址强制。
// adapter 与控制平面同机部署（CONTROL_PLANE_URL=127.0.0.1），合法调用必然来自 loopback。
func internalAuthed(r *http.Request) bool {
	tok := internalToken()
	if tok == "" {
		return false
	}
	h := r.Header.Get("X-Internal-Token")
	if subtle.ConstantTimeCompare([]byte(h), []byte(tok)) != 1 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func mapIDPSource(p string) string {
	switch p {
	case "dingtalk", "wecom", "feishu", "ldap-ad", "openldap", "local":
		return p
	case "ldap":
		return "openldap"
	case "":
		return "local"
	default:
		return p
	}
}

// idpUnionID：哪些 IdP 的 OAuth sub 即该平台的跨应用稳定键（unionid），可作为 union_id 列值：
// 钉钉 sub=unionid、飞书 sub=union_id（两者目录同步侧同样捕获 union_id，键域闭环）；
// 其他 IdP 的 sub 域不同（企微 sub=userid 与目录 external_id 同域无需桥接、
// LDAP sub=DN、本地 sub=local-xxx），写入 union_id 会破坏同步匹配语义，一律返回空
func idpUnionID(idpSource, sub string) string {
	switch mapIDPSource(idpSource) {
	case "dingtalk", "feishu":
		if sub != "" {
			return sub
		}
	}
	return ""
}

type authCheckReq struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	IDPSource   string   `json:"idp_source"`
	ExternalID  string   `json:"external_id"`
	Email       string   `json:"email"`
	ClientIP    string   `json:"client_ip"` // adapter 透传的终端真实 IP（VPN 客户端 trusted_ip）
	Groups      []string `json:"groups"`    // §22.4 SAML 属性组（仅 saml 源携带；同名本地组绑定）
}

func (a *App) handleInternalAuthCheck(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	var req authCheckReq
	if err := jsonDecode(r, &req); err != nil || normalizeKeyword(req.Username) == "" {
		failParam(w, r, "username 必填")
		return
	}
	req.Username = normalizeKeyword(req.Username)

	// §17.4 License 控制点：expired 拒所有新认证；并发满拒新连接。
	// 注意：auth-gen-token 存活期内的重连根本不经过本钩子，因此无需为"重连"豁免——
	// 此前把检查门在"库里不存在的用户"上，导致存量用户可无限突破并发/过期限制（2026-09-29 修复）。
	if ok, reason := a.licenseAllowsNewConnection(); !ok {
		a.auditInternal(r, authCheckReq{Username: req.Username, IDPSource: req.IDPSource, ClientIP: req.ClientIP}, "deny", reason)
		writeOK(w, r, map[string]interface{}{"action": "deny", "user_id": 0, "created": false, "reason": reason})
		return
	}

	var id int64
	var status string
	action, reason, created := "allow", "", false

	// 身份联结（2026-10-01 #62 收紧）：sub（external_id）与 union_id 是唯一可信锚，
	// 两级均限同源匹配（防跨 IdP 键域碰撞）；(source,username) 兜底仅对本地账号生效——
	// OAuth/LDAP 的 name 是昵称/显示名（钉钉 nick、LDAP displayName），可被用户自行改成
	// 任何值，若同名即命中会让"改昵称=冒用他人身份行"（张三把昵称改成同事真名即进其账号）。
	// OAuth/LDAP sub 未命中=新身份 → 建档（撞名加 sub 后 6 位消歧，与目录同步 #56 同款）。
	src := mapIDPSource(req.IDPSource)
	err := a.db.QueryRow(`SELECT id, status FROM users WHERE source=? AND external_id=? AND ?<>'' ORDER BY id LIMIT 1`,
		src, req.ExternalID, req.ExternalID).Scan(&id, &status)
	if err == sql.ErrNoRows {
		err = a.db.QueryRow(`SELECT id, status FROM users WHERE source=? AND union_id=? AND ?<>'' ORDER BY id LIMIT 1`,
			src, req.ExternalID, req.ExternalID).Scan(&id, &status)
	}
	if err == sql.ErrNoRows && (src == "local" || req.ExternalID == "") {
		err = a.db.QueryRow(`SELECT id, status FROM users WHERE username=? AND source=? ORDER BY id LIMIT 1`,
			req.Username, src).Scan(&id, &status)
	}
	switch {
	case err == sql.ErrNoRows:
		// §14.8：IM 用户首次登录自动建档（active + 无组 → CCD 默认拒绝语义）
		// 撞名消歧（#62）：昵称与本源既有行同名时加 sub 后 6 位（与目录同步 #56 同款，
		// 确定性稳定）——否则 UNIQUE(source,username) 冲突建档失败，用户无法连接
		newName := req.Username
		var taken int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE source=? AND username=?`, src, newName).Scan(&taken)
		if taken > 0 {
			suffix := req.ExternalID
			if len(suffix) > 6 {
				suffix = suffix[len(suffix)-6:]
			}
			if suffix != "" {
				newName = req.Username + "-" + suffix
			}
		}
		// 钉钉/飞书建档同步写 union_id（sub=该平台 unionid）——否则该用户后续首次目录同步时
		// 匹配键域不一致（行上 external_id=unionid vs 目录 external_id=userid/open_id），
		// 会再建一行同名身份（2026-09-30 #59/#60 扫码/目录双行分裂根因）
		ins, e := a.db.Exec(`INSERT INTO users(username, display_name, email, source, external_id, union_id, status, last_login_at)
			VALUES(?,?,?,?,?,?, 'active', datetime('now','localtime'))`,
			newName, req.DisplayName, req.Email, src, req.ExternalID,
			idpUnionID(req.IDPSource, req.ExternalID))
		if e != nil {
			failSystem(w, r, "自动建档失败")
			return
		}
		id, _ = ins.LastInsertId()
		created = true
		a.auditInternal(r, req, "success", "首次登录自动建档")
		_ = time.Now()
	case err != nil:
		failSystem(w, r, "查询用户失败")
		return
	case status != "active":
		action = "deny"
		reason = "账号已被禁用，请联系管理员"
		a.auditInternal(r, req, "deny", reason)
	default:
		_, _ = a.db.Exec(`UPDATE users SET last_login_at=datetime('now','localtime') WHERE id=?`, id)
		// 钉钉/飞书存量行补写 union_id（sub=该平台 unionid；空才写不覆盖）——保证
		// 目录同步第一级 union_id 匹配可命中本行，扫码/目录两侧绑定同一身份
		if uid := idpUnionID(req.IDPSource, req.ExternalID); uid != "" {
			_, _ = a.db.Exec(`UPDATE users SET union_id=? WHERE id=? AND COALESCE(union_id,'')=''`, uid, id)
		}
		a.auditInternal(r, req, "success", "")
	}

	if action == "allow" {
		// §22.4 组映射：IdP 下发组名与本地组同名即入组（幂等、不自动建组；
		// 跨源成员受 #46 语义保护——同步只对齐同源用户）。先于 CCD 同步执行，
		// 保证本次认证即按新组下发路由
		if len(req.Groups) > 0 {
			a.bindIdpGroups(id, req.Groups)
		}
		// CCD 单用户同步：必须在 oa2 client-auth 之前完成文件写入
		a.syncCCDForUser(id)
	}
	// cert_cns：该用户全部有效设备的证书 CN 列表（#61 证书身份绑定——adapter 注入
	// id_token claim，oa2 CEL 校验"连接证书 CN ∈ 扫码者设备列表"；吊销设备即时移出）
	certCNs := []string{}
	if action == "allow" {
		if rows, e := a.db.Query(`SELECT cert_cn FROM devices WHERE user_id=? AND status='active'`, id); e == nil {
			for rows.Next() {
				var cn string
				if rows.Scan(&cn) == nil && cn != "" {
					certCNs = append(certCNs, cn)
				}
			}
			rows.Close()
		}
	}
	writeOK(w, r, map[string]interface{}{
		"action": action, "user_id": id, "created": created, "reason": reason,
		"cert_cns": certCNs,
	})
}

// bindIdpGroups：§22.4 组映射——按组名精确匹配既有本地组并入组（幂等，不自动建组）。
// 上限 50 防病态属性；组不存在时静默跳过（组与资源的授权始终由管理员在管理台维护）。
func (a *App) bindIdpGroups(userID int64, groups []string) {
	n := 0
	for _, g := range groups {
		if n >= 50 {
			break
		}
		name := normalizeKeyword(g)
		if name == "" {
			continue
		}
		n++
		res, e := a.db.Exec(`INSERT OR IGNORE INTO group_members(group_id, user_id)
			SELECT id, ? FROM user_groups WHERE name=?`, userID, name)
		if e != nil {
			log.Printf("bindIdpGroups %d ← %q: %v", userID, name, e)
			continue
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			log.Printf("bindIdpGroups: user %d joined group %q (idp attribute)", userID, name)
		}
	}
}

func (a *App) auditInternal(r *http.Request, req authCheckReq, result, reason string) {
	table := auditTable(time.Now())
	ensureAuditTable(a.db, table)
	ip := req.ClientIP // adapter 透传的终端真实 IP；缺省回退连接方地址
	if ip == "" {
		ip = remoteIP(r)
	}
	_, _ = a.db.Exec(`INSERT INTO `+table+`(username, idp_source, result, reason, trusted_ip, trace_id) VALUES(?,?,?,?,?,?)`,
		req.Username, mapIDPSource(req.IDPSource), result, reason, ip, traceID(r))
}

// handleInternalAuthLocal：adapter 本地账号登录验密（§18 break-glass 兜底）。
// 只做验密；建档/禁用拦截/审计/CCD 由 adapter 发码前的 auth-check 钩子统一完成。
// 注意：adapter 侧 userinfo 的 name 必须传账号名本身（auth-check 以 name 建档 username）。
func (a *App) handleInternalAuthLocal(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	if getSetting(a, "local_auth_enabled", "1") != "1" {
		writeFail(w, r, 30003, http.StatusForbidden, "本地账号登录已禁用")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := jsonDecode(r, &req); err != nil || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		failParam(w, r, "username/password 必填")
		return
	}
	username := strings.TrimSpace(req.Username)
	// 暴破限速：oa2 调用方恒为 127.0.0.1，按用户名分桶
	if !loginLimiter.allow("internal|"+username) {
		writeFail(w, r, 30005, http.StatusTooManyRequests, "尝试过于频繁")
		return
	}
	var id int64
	var display, hash, status string
	err := a.db.QueryRow(`SELECT id, COALESCE(display_name,''), COALESCE(password_hash,''), status
		FROM users WHERE username=? AND source='local' ORDER BY id LIMIT 1`, username).
		Scan(&id, &display, &hash, &status)
	if err == sql.ErrNoRows || (err == nil && (status != "active" || hash == "" ||
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil)) {
		if err == sql.ErrNoRows {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(req.Password)) // 时序对齐
		}
		writeFail(w, r, 30004, http.StatusForbidden, "账号或密码错误")
		return
	}
	if err != nil {
		failSystem(w, r, fmtErr("auth-local query", err))
		return
	}
	writeOK(w, r, map[string]interface{}{
		"status": "ok", "user_id": id,
		"sub": "local-" + username, "name": username, "username": username,
		"display_name": display,
	})
}

// handleInternalPortalWhoami：adapter 静默登录反查门户当前登录者（2026-09-30 #57 身份归属修复）。
// 场景：用户在门户换了账号（如保雷），但浏览器还留着旧 web_sess（小熊）——VPN webauth
// 静默复用旧身份发码，客户端显示的还是旧人。修复：静默登录优先以门户会话为准
//（谁登录门户就用谁），门户会话不存在/失效时才回退 web_sess。
// 语义：调用方（adapter，同机 loopback）转发浏览器 Cookie → 解析 portal_sess（aud=portal 强制）
// → 返回该用户行的静默发码身份。adapter 经既有内部通道 _cp_get 调用，token 走 pt 查询参数
//（Cookie 头同样接受，二者取先命中者）。sub 取 union_id（钉钉扫码 sub=unionid，auth-check
// 三级匹配精确命中），无则 external_id，纯本地行 sub="local-"+username（auth-check
// 走 (source,username) 匹配）。未登录/过期/行已禁用 → 404（不适用静默，调用方回退）。
func (a *App) handleInternalPortalWhoami(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	token := r.URL.Query().Get("pt")
	if token == "" {
		if c, err := r.Cookie(portalCookieName); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		writeFail(w, r, 30001, http.StatusNotFound, "no portal session")
		return
	}
	claims, err := parsePortalToken(token)
	if err != nil {
		writeFail(w, r, 30001, http.StatusNotFound, "portal session invalid")
		return
	}
	var username, display, unionID, extID, source, status string
	err = a.db.QueryRow(`SELECT username, COALESCE(display_name,''), COALESCE(union_id,''),
		COALESCE(external_id,''), source, status FROM users WHERE id=?`, claims.UserID).
		Scan(&username, &display, &unionID, &extID, &source, &status)
	if err == sql.ErrNoRows || (err == nil && status != "active") {
		writeFail(w, r, 30001, http.StatusNotFound, "user unavailable")
		return
	}
	if err != nil {
		failSystem(w, r, fmtErr("portal-whoami query", err))
		return
	}
	sub := unionID
	if sub == "" {
		sub = extID
	}
	if sub == "" {
		sub = "local-" + username
	}
	writeOK(w, r, map[string]interface{}{
		"uid": claims.UserID, "username": username, "display_name": display,
		"sub": sub, "provider": source,
	})
}
