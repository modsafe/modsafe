package main

// 用户侧 TOTP 双因素（2026-10-06）：复用 totp.go 纯函数，挂 users 表。
// 租户策略 user_totp_policy（settings）：off（默认，零行为变化）| local_only（仅本地账号）| all（全员）。
// 命中策略且未绑定 → 门户登录签发 TP=1 受限会话（requirePortal 仅放行 me/totp），
// 绑定成功服务端重签完整会话（用户无感，无需重登）。
// 边界语义（与管理台 totp_enforced 一致）：已签发会话 8h 内不受策略收紧/解绑影响，下次登录生效。

import (
	"net/http"
	"strconv"
	"strings"
)

// userTotpPolicyHits：策略是否命中该来源（off 恒否；local_only 仅本地账号；all 全员）
func userTotpPolicyHits(a *App, source string) bool {
	switch getSetting(a, "user_totp_policy", "off") {
	case "all":
		return true
	case "local_only":
		return source == "local"
	}
	return false
}

// userTotpState：读 users 行绑定态（来源取库值而非 JWT——cookie 内 src 历史语义为 IM sub）
func (a *App) userTotpState(userID int64) (enabled bool, secret string, source string) {
	var en int
	_ = a.db.QueryRow(`SELECT COALESCE(totp_enabled,0), COALESCE(totp_secret,''), source FROM users WHERE id=?`,
		userID).Scan(&en, &secret, &source)
	return en == 1, secret, source
}

// GET /api/v1/self/totp/setup：生成（未启用时）secret + otpauth URI，不激活
func (a *App) handleSelfTotpSetup(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	enabled, existing, _ := a.userTotpState(pc.UserID)
	secret := existing
	if secret == "" {
		secret = genTotpSecret()
		if _, err := a.db.Exec(`UPDATE users SET totp_secret=? WHERE id=?`, secret, pc.UserID); err != nil {
			failSystem(w, r, "保存失败")
			return
		}
	}
	uri := "otpauth://totp/Modsafe:" + pc.Username + "?secret=" + secret + "&issuer=Modsafe&digits=6&period=30"
	writeOK(w, r, map[string]interface{}{"secret": secret, "otpauth_uri": uri, "enabled": enabled})
}

// POST /api/v1/self/totp/enable {code}：验一次当前码激活，并重签完整会话解受限
func (a *App) handleSelfTotpEnable(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := jsonDecode(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		failParam(w, r, "需要 6 位验证码")
		return
	}
	_, secret, _ := a.userTotpState(pc.UserID)
	if secret == "" {
		failBiz(w, r, 20004, "请先获取密钥")
		return
	}
	if !totpVerifySecret(secret, req.Code) {
		writeFail(w, r, 30004, http.StatusBadRequest, "验证码错误")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET totp_enabled=1 WHERE id=?`, pc.UserID); err != nil {
		failSystem(w, r, "启用失败")
		return
	}
	a.reissuePortalSession(w, pc) // 绑定完成 → 重签 TP=0 完整会话，前端原地解锁
	a.auditAdminAction(r, pc.Username, "POST", "/api/v1/self/totp/enable", "success", "门户绑定双因素")
	writeOK(w, r, map[string]interface{}{"ok": true})
}

// POST /api/v1/self/totp/disable {code}：本人解绑需当前码；策略命中该用户时禁自行解绑
// （对齐管理台强制态语义，super_admin 可经 /users/{id}/totp-reset 兜底）
func (a *App) handleSelfTotpDisable(w http.ResponseWriter, r *http.Request) {
	pc := portalClaimsOf(r)
	_, _, source := a.userTotpState(pc.UserID)
	if userTotpPolicyHits(a, source) {
		failBiz(w, r, 20003, "企业策略已强制双因素认证，无法自行关闭（请联系管理员）")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "需要 6 位验证码")
		return
	}
	_, secret, _ := a.userTotpState(pc.UserID)
	if secret == "" || !totpVerifySecret(secret, req.Code) {
		writeFail(w, r, 30004, http.StatusBadRequest, "验证码错误")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?`, pc.UserID); err != nil {
		failSystem(w, r, "关闭失败")
		return
	}
	a.auditAdminAction(r, pc.Username, "POST", "/api/v1/self/totp/disable", "success", "门户关闭双因素")
	writeOK(w, r, map[string]interface{}{"ok": true})
}

// reissuePortalSession：按当前绑定态+策略重签门户 cookie（enable 成功后解受限）。
// 重签失败不阻塞响应：旧会话仍是受限态，重新登录自然解锁。
func (a *App) reissuePortalSession(w http.ResponseWriter, pc *portalClaims) {
	enabled, _, source := a.userTotpState(pc.UserID)
	tok, err := signPortalToken(pc.UserID, pc.Username, source, !enabled && userTotpPolicyHits(a, source))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalCookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600,
	})
}

// GET /api/v1/settings/user-totp（super_admin）：读用户双因素策略
func (a *App) handleUserTotpSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, map[string]interface{}{"policy": getSetting(a, "user_totp_policy", "off")})
}

// PUT /api/v1/settings/user-totp（super_admin）：写用户双因素策略
func (a *App) handleUserTotpSettingsPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy string `json:"policy"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "需要 policy 字段")
		return
	}
	switch req.Policy {
	case "off", "local_only", "all":
	default:
		failParam(w, r, "policy 取值须为 off|local_only|all")
		return
	}
	setSetting(a, "user_totp_policy", req.Policy)
	a.auditAdminAction(r, claimsOf(r).Username, "PUT", "/api/v1/settings/user-totp", "success policy="+req.Policy, "")
	writeOK(w, r, map[string]interface{}{"policy": req.Policy})
}

// POST /api/v1/users/{id}/totp-reset（super_admin）：解绑任意用户（丢验证器恢复），
// 该用户下次门户登录按策略重新走绑定流程
func (a *App) handleUserTotpReset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var username string
	if err := a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&username); err != nil {
		failBiz(w, r, 20001, "用户不存在")
		return
	}
	if _, err := a.db.Exec(`UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?`, id); err != nil {
		failSystem(w, r, "重置失败")
		return
	}
	a.auditAdminAction(r, claimsOf(r).Username, "POST", "/api/v1/users/"+r.PathValue("id")+"/totp-reset", "success "+username, "")
	writeOK(w, r, map[string]interface{}{"ok": true})
}
