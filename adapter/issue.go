package main

// 发码链路（_issue_code_and_redirect）：反查控制面 → cert_cns 注入 → 浏览器免扫码会话
// → CCD 下发 → refresh 令牌登记 → CODES 登记 → 302 回 oa2。以及拒绝页。
// 注：CCD 文件名兜底哈希用 SHA-256 截断（Python 版为 md5，仅文件名派生非安全用途）。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, req map[string]any, userinfo map[string]any) {
	// ②认证链路：反查控制平面，deny → 品牌化拒绝页
	allow, info := cpAuthCheck(mStr(req, "provider"), mStr(req, "client_ip"), userinfo)
	if !allow {
		logf("auth-check DENY user=%s reason=%s", uiStr(userinfo, "name"), mStr(info, "reason"))
		denyPage(w, r, firstNonEmpty(mStr(info, "reason"), "账号已被禁用"))
		return
	}
	// #61 证书身份绑定：扫码者有效设备证书 CN 列表注入 id_token claim
	userinfo["_cert_cns"] = info["cert_cns"]
	// §25 阶段1：认证成功登记浏览器会话（#57：连同真实登录源 _provider 一起存）
	sessUI := map[string]any{}
	for k, v := range userinfo {
		sessUI[k] = v
	}
	sessUI["_provider"] = mStr(req, "provider")
	var cookie *http.Cookie
	if cid := webSessSave(sessUI); cid != "" {
		cookie = &http.Cookie{
			Name: "modsafe_web_sess", Value: cid, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
			MaxAge: int(WEB_SESS_HOURS * 3600),
		}
	}
	issueCCD(userinfo)
	// 有 IdP refresh_token 的（钉钉/飞书）保存 → 支持静默重认证；LDAP/企微每次交互认证
	clientRT := ""
	if rt := uiStr(userinfo, "_rt"); rt != "" {
		clientRT = rtIssue(uiStr(userinfo, "sub"), mStr(req, "provider"), rt)
	}
	code := randToken(32)
	codesPut(code, map[string]any{
		"sub": uiStr(userinfo, "sub"), "name": uiStr(userinfo, "name"),
		"email":          uiStr(userinfo, "email"),
		"provider":       mStr(req, "provider"),
		"nonce":          mStr(req, "nonce"),
		"code_challenge": mStr(req, "code_challenge"),
		"cc_method":      mStr(req, "cc_method"),
		"_client_rt":     clientRT,
		"_cert_cns":      userinfo["_cert_cns"],
		"exp":            float64(nowUnix() + TOKEN_TTL),
	})
	oa2CB := mStr(req, "oa2_redirect_uri")
	sep := "?"
	if strings.Contains(oa2CB, "?") {
		sep = "&"
	}
	qs := url.Values{"code": {code}, "state": {mStr(req, "oa2_state")}}.Encode()
	redirectWith(w, oa2CB+sep+qs, cookie)
}

func denyPage(w http.ResponseWriter, r *http.Request, reason string) {
	// 拒绝时使浏览器会话失效（与 Python _deny_page 一致）
	webSessDrop(r.Header.Get("Cookie"))
	b := loadBranding()
	html := "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>" +
		"<title>拒绝访问</title></head>" +
		"<body style=\"font-family:system-ui,sans-serif;text-align:center;padding-top:90px\">" +
		"<h2>⛔ " + esc(mStr(b, "company_name")) + " · " + esc(mStr(b, "product_name")) + "</h2>" +
		"<p style='font-size:16px'>" + esc(reason) + "</p>" +
		"<p style='color:#888'>请联系管理员</p></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(403)
	_, _ = w.Write([]byte(html))
}

// issueCCD：ccd-rules.json 命中（uid 或 nick）→ 写 oa2 client-config 目录
func issueCCD(userinfo map[string]any) {
	rules, ok := loadJSONFile(CCD_RULES_PATH)
	if !ok {
		return
	}
	uid := uiStr(userinfo, "sub")
	nick := uiStr(userinfo, "name")
	entry, _ := rules[uid].(map[string]any)
	if entry == nil {
		entry, _ = rules[nick].(map[string]any)
	}
	if entry == nil {
		return
	}
	routesAny, _ := entry["routes"].([]any)
	var lines []string
	for _, rt := range routesAny {
		lines = append(lines, fmt.Sprintf("push \"route %v\"", rt))
	}
	_ = os.MkdirAll(CCD_OUT_DIR, 0o755)
	fname := ""
	for _, ch := range nick {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' {
			fname += string(ch)
		}
	}
	if fname == "" {
		sum := sha256.Sum256([]byte(uid))
		fname = hex.EncodeToString(sum[:])[:16]
	}
	path := CCD_OUT_DIR + "/" + fname + ".conf"
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err == nil {
		logf("ccd issued for %s → %s", nick, path)
	} else {
		logf("ccd write FAILED for %s → %s: %v", nick, path, err)
	}
}
