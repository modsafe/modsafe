package main

// TOTP 双因素（P1-e，管理台登录）：RFC 6238，SHA1/6 位/30s 步长（Google Authenticator 兼容）。
// 纯标准库（crypto/hmac + crypto/sha1 + encoding/base32），无外部依赖。
// 流程：绑定（登录态下 GET /auth/totp/setup 得 secret+otpauth URI，POST /auth/totp/enable 校验码激活）
// → 登录：账号密码通过后若 totp_enabled=1，必须携带 totp_code 才发 token（错码=30004 计入审计+限速）。
// 恢复：super_admin 可对任意管理员 POST /admins/{id}/totp/reset 解绑（丢失手机场景）。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// totpCode：30s 窗口的 6 位码（RFC 6238）
func totpCode(secret []byte, t int64) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(t/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// totpVerify：±1 窗口容差（时钟漂移 ±30s）
func totpVerify(secret []byte, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix()
	for _, w := range []int64{0, -1, 1} {
		if totpCode(secret, now+w*30) == code {
			return true
		}
	}
	return false
}

func genTotpSecret() string {
	b := make([]byte, 20) // 160-bit（RFC 推荐）
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// totpVerifySecret：字符串 secret（base32）→ 解码 → 校验。
// 注意必须先 base32 解码：直接 []byte(secret) 会拿 ASCII 字节当 HMAC key，永远验不过。
func totpVerifySecret(secret string, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimSpace(secret))
	if err != nil || len(key) == 0 {
		return false
	}
	return totpVerify(key, code)
}

func (a *App) adminTotpState(username string) (enabled bool, secret string) {
	var en int
	_ = a.db.QueryRow(`SELECT COALESCE(totp_enabled,0), COALESCE(totp_secret,'') FROM admins WHERE username=?`,
		username).Scan(&en, &secret)
	return en == 1, secret
}

// handleTotpSetup：生成（未启用时）secret + otpauth URI，不激活
func (a *App) handleTotpSetup(w http.ResponseWriter, r *http.Request) {
	c := claimsOf(r)
	enabled, existing := a.adminTotpState(c.Username)
	secret := existing
	if secret == "" {
		secret = genTotpSecret()
		if _, err := a.db.Exec(`UPDATE admins SET totp_secret=? WHERE username=?`, secret, c.Username); err != nil {
			failSystem(w, r, "保存失败")
			return
		}
	}
	uri := "otpauth://totp/Modsafe:" + c.Username + "?secret=" + secret + "&issuer=Modsafe&digits=6&period=30"
	writeOK(w, r, map[string]interface{}{"secret": secret, "otpauth_uri": uri, "enabled": enabled})
}

// handleTotpEnable：校验一次当前码后激活
func (a *App) handleTotpEnable(w http.ResponseWriter, r *http.Request) {
	c := claimsOf(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := jsonDecode(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		failParam(w, r, "需要 6 位验证码")
		return
	}
	_, secret := a.adminTotpState(c.Username)
	if secret == "" {
		failBiz(w, r, 20004, "请先获取密钥")
		return
	}
	if !totpVerifySecret(secret, req.Code) {
		failBiz(w, r, 30004, "验证码错误")
		return
	}
	if _, err := a.db.Exec(`UPDATE admins SET totp_enabled=1 WHERE username=?`, c.Username); err != nil {
		failSystem(w, r, "启用失败")
		return
	}
	a.auditAdminAction(r, c.Username, "totp-enable", r.URL.Path, "success", "")
	writeOK(w, r, map[string]interface{}{"ok": true})
}

// handleTotpDisable：本人解绑需当前码（防会话劫持后直接关双因素）；
// 系统强制态下禁止自行解绑（super_admin 可通过管理员重置通道兜底）
func (a *App) handleTotpDisable(w http.ResponseWriter, r *http.Request) {
	c := claimsOf(r)
	if getSetting(a, "totp_enforced", "0") == "1" {
		failBiz(w, r, 20003, "系统已强制双因素认证，无法自行关闭（由 super_admin 调整系统开关）")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "需要 6 位验证码")
		return
	}
	_, secret := a.adminTotpState(c.Username)
	if secret == "" || !totpVerifySecret(secret, req.Code) {
		failBiz(w, r, 30004, "验证码错误")
		return
	}
	if _, err := a.db.Exec(`UPDATE admins SET totp_enabled=0, totp_secret='' WHERE username=?`, c.Username); err != nil {
		failSystem(w, r, "关闭失败")
		return
	}
	a.auditAdminAction(r, c.Username, "totp-disable", r.URL.Path, "success", "")
	writeOK(w, r, map[string]interface{}{"ok": true})
}

// handleTotpSettingsGet/Put：系统级强制开关（P1-e 双层开关之上层，super_admin）。
// 强制=所有管理员登录必须已绑定 TOTP；未绑定者发"仅可绑定"限定 token（roles 空）。
func (a *App) handleTotpSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, map[string]interface{}{"enforced": getSetting(a, "totp_enforced", "0") == "1"})
}

func (a *App) handleTotpSettingsPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enforced *bool `json:"enforced"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Enforced == nil {
		failParam(w, r, "需要 enforced 字段")
		return
	}
	v := "0"
	if *req.Enforced {
		v = "1"
	}
	setSetting(a, "totp_enforced", v)
	a.auditAdminAction(r, claimsOf(r).Username, "totp-enforce", r.URL.Path,
		"success enforced="+v, "")
	writeOK(w, r, map[string]interface{}{"enforced": *req.Enforced})
}

// handleTotpAdminReset：super_admin 解绑任意管理员（丢手机恢复）
func (a *App) handleTotpAdminReset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var username string
	if err := a.db.QueryRow(`SELECT username FROM admins WHERE id=?`, id).Scan(&username); err != nil {
		failBiz(w, r, 20001, "管理员不存在")
		return
	}
	if _, err := a.db.Exec(`UPDATE admins SET totp_enabled=0, totp_secret='' WHERE username=?`, username); err != nil {
		failSystem(w, r, "重置失败")
		return
	}
	a.auditAdminAction(r, claimsOf(r).Username, "totp-reset", r.URL.Path, "success "+username, "")
	writeOK(w, r, map[string]interface{}{"ok": true})
}
