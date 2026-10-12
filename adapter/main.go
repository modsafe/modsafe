package main

// modsafe-idp-adapter v2（Go 版）：多 IdP 网关（防腐层）
// 标准 OIDC 服务端（对 openvpn-auth-oauth2）←→ 钉钉/飞书/企业微信（OAuth 私有协议）
// + AD/OpenLDAP（LDAP bind）+ SAML 2.0 SP。端点契约与 Python 版逐条对应。

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func netipParse(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// jsQuote：json.dumps(_target) 等价（不转义 & < >，保 JS 字符串原义）
func jsQuote(s string) string {
	var b strings.Builder
	enc := jsonNewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := b.String()
	return strings.TrimSuffix(out, "\n")
}

// ---- 登录状态登记（req 结构与 Python 一致） ----

func newAuthReq(provider, clientIP, oa2Redirect, oa2State, nonce, challenge, ccMethod string) map[string]any {
	if ccMethod == "" {
		ccMethod = "S256"
	}
	return map[string]any{
		"client_ip":        clientIP,
		"provider":         provider,
		"oa2_redirect_uri": oa2Redirect,
		"oa2_state":        oa2State,
		"nonce":            nonce,
		"code_challenge":   challenge,
		"cc_method":        ccMethod,
		"exp":              float64(nowUnix() + STATE_TTL),
	}
}

func reqExpired(req map[string]any) bool {
	exp, _ := req["exp"].(float64)
	return exp < float64(nowUnix())
}

// ---- redirect_uri 白名单（防授权码劫持/开放重定向/CRLF 注入） ----

func allowedRedirectURIs() map[string]bool {
	adminPort := MODSAFE_ADMIN_PUB_PORT
	allowed := map[string]bool{
		"https://127.0.0.1:" + adminPort + "/api/v1/self/callback": true,
		strings.TrimRight(OA2_BASE, "/") + "/oauth2/callback":      true,
	}
	if u, err := url.Parse(ADAPTER_BASE); err == nil && u.Hostname() != "" {
		allowed["http://"+u.Hostname()+":"+adminPort+"/api/v1/self/callback"] = true
	}
	// 内置条目由 MODSAFE_PORTAL_BASE / ADAPTER_BASE 运行时派生（换域名改 env 即可，免改码）；
	// MODSAFE_REDIRECT_URIS 可整体替换派生结果，EXTRA_REDIRECTS 仍为追加项
	builtin := REDIRECT_URIS
	if builtin == "" {
		var parts []string
		if p := portalBase(); p != "" {
			parts = append(parts,
				p+"/oauth2/n1/oauth2/callback",
				p+"/oauth2/n2/oauth2/callback",
				p+"/api/v1/self/callback")
		}
		builtin = strings.Join(parts, ",")
	}
	for _, u := range strings.Split(builtin, ",") {
		if u = strings.TrimSpace(u); u != "" {
			allowed[u] = true
		}
	}
	for _, u := range strings.Split(EXTRA_REDIRECTS, ",") {
		if u = strings.TrimSpace(u); u != "" {
			allowed[u] = true
		}
	}
	return allowed
}

// ---- /authorize ----

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := q.Get("provider")
	oa2Redirect := q.Get("redirect_uri")
	if oa2Redirect == "" {
		writeHTML(w, 400, "missing redirect_uri")
		return
	}
	allowed := allowedRedirectURIs()
	if strings.ContainsAny(oa2Redirect, "\r\n") || !allowed[oa2Redirect] {
		logf("authorize redirect_uri rejected: %s", truncateStr(oa2Redirect, 80))
		writeHTML(w, 400, "redirect_uri not allowed")
		return
	}
	if provider == "mock" && !MOCK_MODE {
		// mock IdP 生产门禁：仅显式开启 MOCK_MODE 的实例可用
		writeHTML(w, 403, brandPage("<h2>该登录方式未启用</h2>"))
		return
	}
	cookie := r.Header.Get("Cookie")
	cpCfg := cpAuthConfig() // B 方案：strict 判定在静默分支之前；下方 primary_idp/本地兜底复用同一次反查

	// §25 阶段1：近期认证过的浏览器静默发码（#57：门户会话优先于 web_sess）
	if provider == "" {
		// B 方案：网页一键连接的一次性 ticket（grant 参数，自家客户端透传）。
		// 身份以 ticket 为准（控制面原子核销），与浏览器 cookie 无关——
		// strict 策略下这是 oa2 回调唯一的静默通道；无效/过期仅记录并落入正常流程
		if gt := q.Get("grant"); gt != "" {
			if ui := cpConnectGrant(gt); ui != nil {
				internalState := randToken(24)
				req := newAuthReq(firstNonEmpty(mStr(ui, "provider"), "portal-grant"),
					clientIP(r), oa2Redirect, q.Get("state"), q.Get("nonce"),
					q.Get("code_challenge"), firstNonEmpty(q.Get("code_challenge_method"), "S256"))
				authRequestPut(internalState, req)
				sessUser := map[string]any{
					"sub":                mStr(ui, "sub"),
					"name":               mStr(ui, "username"),
					"preferred_username": mStr(ui, "username"),
					"email":              "",
					"_provider":          firstNonEmpty(mStr(ui, "provider"), "portal-grant"),
				}
				logf("portal-grant silent login: %s (skip IdP)", uiStr(sessUser, "name"))
				issueCodeAndRedirect(w, r, req, sessUser)
				return
			}
			logf("portal-grant invalid/expired, fall through to normal auth")
		}

		// strict 策略（B 方案）：VPN 客户端连接（oa2 回调）不接受浏览器 cookie 静默，
		// 必须走完整验证（扫码/SAML/本地登录）；门户自助回调不受影响
		if mStr(cpCfg, "client_verify_policy") == "strict" && strings.HasSuffix(oa2Redirect, "/oauth2/callback") {
			logf("strict client-verify: cookie silent login blocked (redirect_uri=%s)",
				truncateStr(oa2Redirect, 60))
		} else {
			var sessUser map[string]any
			src := "web-sess"
			if portal := cpPortalWhoami(cookie); portal != nil {
				sessUser = map[string]any{
					"sub":                mStr(portal, "sub"),
					"name":               mStr(portal, "username"),
					"preferred_username": mStr(portal, "username"),
					"email":              "",
					"_provider":          firstNonEmpty(mStr(portal, "provider"), "web-sess"),
				}
				src = "portal-sess"
			}
			if sessUser == nil {
				sessUser = webSessLoad(cookie)
			}
			if sessUser != nil {
				internalState := randToken(24)
				req := newAuthReq(firstNonEmpty(uiStr(sessUser, "_provider"), "web-sess"),
					clientIP(r), oa2Redirect, q.Get("state"), q.Get("nonce"),
					q.Get("code_challenge"), firstNonEmpty(q.Get("code_challenge_method"), "S256"))
				authRequestPut(internalState, req)
				logf("%s silent login: %s (skip IdP)", src, uiStr(sessUser, "name"))
				issueCodeAndRedirect(w, r, req, sessUser)
				return
			}
		}
	}

	// §18：无 provider → primary_idp 直达（OAuth/SAML 走品牌中转页）
	primaryAuto := false
	if provider == "" {
		primary := mStr(cpCfg, "primary_idp")
		if primary != "" {
			if _, ok := IDP_META[primary]; ok && idpEnabled(primary) {
				provider = primary
				primaryAuto = true
			}
		}
	}
	if provider == "" {
		// IdP 选择页
		var items strings.Builder
		for _, pl := range enabledIDPs() {
			qs := url.Values{}
			qs.Set("redirect_uri", oa2Redirect)
			qs.Set("state", q.Get("state"))
			qs.Set("nonce", q.Get("nonce"))
			qs.Set("code_challenge", q.Get("code_challenge"))
			qs.Set("code_challenge_method", firstNonEmpty(q.Get("code_challenge_method"), "S256"))
			qs.Set("response_type", "code")
			qs.Set("scope", "openid")
			items.WriteString(`<a class="idp" href="/authorize?provider=` + pl[0] + `&` + qs.Encode() +
				`"><span class="ic">` + IDP_META[pl[0]].Icon + `</span>` + esc(pl[1]) + `</a>`)
		}
		writeHTML(w, 200, brandPage(
			"<h2>选择登录方式</h2>"+items.String()+
				localEntryHTML(cpCfg, oa2Redirect, q.Get("state"), q.Get("nonce"))))
		return
	}

	if _, ok := IDP_META[provider]; !ok && provider != "local" {
		writeHTML(w, 400, "未知登录方式: "+esc(provider))
		return
	}

	internalState := randToken(24)

	// primary 主源 → 品牌中转页（自动跳转 + 本地账号兜底入口），不再裸 302（§18）
	if primaryAuto {
		_st := randToken(24)
		authRequestPut(_st, newAuthReq(provider, clientIP(r), oa2Redirect,
			q.Get("state"), q.Get("nonce"), q.Get("code_challenge"), q.Get("code_challenge_method")))
		var target string
		if h, isOAuth := OAUTH_HANDLERS[provider]; isOAuth {
			t, err := h.authorize(_st)
			if err != nil {
				logf("%s authorize FAILED: %v", provider, err)
				writeHTML(w, 500, brandPage(
					`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">该登录方式未配置完整（缺应用凭据，请联系管理员，详见 adapter 日志）</p>`))
				return
			}
			target = t
		} else {
			// SAML：经 /authorize 二跳发起（AuthnRequest ID 即 state 锚点）
			qs := url.Values{}
			qs.Set("provider", provider)
			qs.Set("redirect_uri", oa2Redirect)
			qs.Set("state", q.Get("state"))
			qs.Set("nonce", q.Get("nonce"))
			qs.Set("code_challenge", q.Get("code_challenge"))
			qs.Set("code_challenge_method", firstNonEmpty(q.Get("code_challenge_method"), "S256"))
			qs.Set("response_type", "code")
			qs.Set("scope", "openid")
			target = "/authorize?" + qs.Encode()
		}
		writeHTML(w, 200, brandPage(
			"<h2>"+esc(idpLabel(provider))+"</h2>"+
				`<a class="btn-primary" href="`+esc(target)+`">立即进入 `+esc(idpLabel(provider))+`</a>`+
				`<div class="jump-progress"><i></i></div>`+
				`<p class="hint">3 秒后自动进入</p>`+
				localEntryHTML(cpCfg, oa2Redirect, q.Get("state"), q.Get("nonce"))+
				`<script>var _jt=setTimeout(function(){location.href=`+jsQuote(target)+`},3000)</script>`))
		return
	}

	authRequestPut(internalState, newAuthReq(provider, clientIP(r), oa2Redirect,
		q.Get("state"), q.Get("nonce"), q.Get("code_challenge"), q.Get("code_challenge_method")))

	if provider == "mock" {
		redirectWith(w, ADAPTER_BASE+"/mock/consent?"+url.Values{"state": {internalState}}.Encode(), nil)
		return
	}
	if provider == "local" {
		localOn := true
		if cpCfg["local_auth_enabled"] != nil {
			localOn, _ = cpCfg["local_auth_enabled"].(bool)
		}
		if !localOn {
			writeHTML(w, 403, brandPage(
				`<h2>本地账号登录</h2><p class='err'>该登录方式已被管理员禁用</p>`))
			return
		}
		redirectWith(w, ADAPTER_BASE+"/login/local?"+url.Values{"istate": {internalState}}.Encode(), nil)
		return
	}
	meta := IDP_META[provider]
	switch meta.Type {
	case "ldap":
		if !idpEnabled(provider) {
			writeHTML(w, 403, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">该登录方式未启用或未配置服务器信息</p>`))
			return
		}
		redirectWith(w, ADAPTER_BASE+"/login/"+provider+"?"+url.Values{"istate": {internalState}}.Encode(), nil)
	case "saml":
		if !idpEnabled(provider) {
			writeHTML(w, 403, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">该登录方式未启用（缺 IdP 配置）</p>`))
			return
		}
		cfg := samlCfg()
		if mStr(cfg, "sso_url") == "" || mStr(cfg, "entity_id") == "" || mStr(cfg, "idp_certificate") == "" {
			writeHTML(w, 403, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">SAML 未配置完整（entityID/SSO/证书）</p>`))
			return
		}
		target, err := samlRedirectURL(internalState)
		if err != nil {
			logf("saml redirect FAILED: %v", err)
			writeHTML(w, 500, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">SAML 请求构造失败</p>`))
			return
		}
		redirectWith(w, target, nil)
	case "oauth":
		if !idpEnabled(provider) {
			writeHTML(w, 403, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">该登录方式未启用（缺凭证配置）</p>`))
			return
		}
		target, err := OAUTH_HANDLERS[provider].authorize(internalState)
		if err != nil {
			logf("%s authorize FAILED: %v", provider, err)
			writeHTML(w, 500, brandPage(
				`<h2>`+esc(idpLabel(provider))+`</h2><p class="err">该登录方式未配置完整（缺应用凭据，请联系管理员，详见 adapter 日志）</p>`))
			return
		}
		redirectWith(w, target, nil)
	}
}

// ---- OAuth 回调（含旧路径 /{pid}/callback） ----

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("pid")
	if pid == "" {
		pid = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/callback")
	}
	if _, ok := OAUTH_HANDLERS[pid]; !ok {
		writeHTML(w, 404, "not found")
		return
	}
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		writeHTML(w, 400, brandPage(
			`<h2>`+esc(idpLabel(pid))+`授权失败</h2><p class="err">`+esc(errParam)+`</p>`))
		return
	}
	code := q.Get("authCode")
	if code == "" {
		code = q.Get("code")
	}
	internalState := q.Get("state")
	req := authRequestPop(internalState)
	if req == nil || reqExpired(req) {
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	userinfo, err := OAUTH_HANDLERS[pid].callback(code)
	if err != nil {
		logf("%s callback FAILED: %v", pid, err)
		writeHTML(w, 502, brandPage(
			`<h2>`+esc(idpLabel(pid))+`登录失败</h2><p class="err">`+esc(truncateStr(err.Error(), 200))+`</p>`))
		return
	}
	logf("%s user ok: sub=%s name=%s", pid, truncateStr(uiStr(userinfo, "sub"), 20), uiStr(userinfo, "name"))
	issueCodeAndRedirect(w, r, req, userinfo)
}

// ---- mock（仅 MOCK_MODE=1 实例可用；/mock/* 端点自身也设门禁，勿只依赖 /authorize 入口） ----

func handleMockConsent(w http.ResponseWriter, r *http.Request) {
	if !MOCK_MODE {
		// mock IdP 生产门禁（与 /authorize 入口一致）
		writeHTML(w, 403, brandPage("<h2>该登录方式未启用</h2>"))
		return
	}
	internalState := r.URL.Query().Get("state")
	req := authRequestGet(internalState)
	if req == nil || reqExpired(req) || mStr(req, "provider") != "mock" {
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	confirm := ADAPTER_BASE + "/mock/confirm?" + url.Values{"state": {internalState}}.Encode()
	writeHTML(w, 200, brandPage(
		`<h2>模拟扫码登录</h2><p>mock 页面。接入真实 IdP 后此页为对应扫码界面。</p>`+
			`<button onclick="window.location='`+esc(confirm)+`'" style="width:100%;padding:12px;`+
			`background:#1296db;color:#fff;border:none;border-radius:8px;cursor:pointer">`+
			`模拟扫码确认（MockUser）</button>`))
}

func handleMockConfirm(w http.ResponseWriter, r *http.Request) {
	if !MOCK_MODE {
		// mock IdP 生产门禁（与 /authorize 入口一致）：confirm 直接发码，绝不可在生产线放行
		writeHTML(w, 403, brandPage("<h2>该登录方式未启用</h2>"))
		return
	}
	internalState := r.URL.Query().Get("state")
	req := authRequestPop(internalState)
	if req == nil || reqExpired(req) || mStr(req, "provider") != "mock" {
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2>"))
		return
	}
	userinfo := map[string]any{"sub": "mock-user-001", "name": "MockUser", "email": "mock@modsafe.local"}
	issueCodeAndRedirect(w, r, req, userinfo)
}

// ---- 登录表单（local / ldap） ----

func loginFormHTML(title, action, istate, errMsg string, extra string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class='err'>` + esc(errMsg) + `</p>`
	}
	return "<h2>" + esc(title) + "</h2>" + errHTML +
		`<form method="POST" action="` + action + `">` +
		`<input type="hidden" name="istate" value="` + esc(istate) + `">` +
		`<label>账号</label><input name="username" autocomplete="username" required>` +
		`<label>密码</label><input name="password" type="password" autocomplete="current-password" required>` +
		`<button type="submit">登 录</button></form>` + extra
}

func handleLoginFormGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login/local" {
		q := r.URL.Query()
		writeHTML(w, 200, brandPage(loginFormHTML("本地账号登录", "/login/local",
			q.Get("istate"), q.Get("error"), "")))
		return
	}
	provider := strings.TrimPrefix(r.URL.Path, "/login/")
	if provider != "ldap-ad" && provider != "openldap" {
		writeHTML(w, 404, "not found")
		return
	}
	q := r.URL.Query()
	istate := q.Get("istate")
	var extra string
	if req := authRequestGet(istate); req != nil {
		extra = localEntryHTML(cpAuthConfig(), mStr(req, "oa2_redirect_uri"),
			mStr(req, "oa2_state"), mStr(req, "nonce"))
	}
	writeHTML(w, 200, brandPage(loginFormHTML(idpLabel(provider)+" 登录",
		"/login/"+provider, istate, q.Get("error"), extra)))
}

func handleLoginLocalPost(w http.ResponseWriter, r *http.Request) {
	form := parseForm(readBody(r))
	istate := form.Get("istate")
	username := strings.TrimSpace(form.Get("username"))
	password := form.Get("password")
	// 只 peek 不消费：验密失败后重试不再"state 无效"
	req := authRequestGet(istate)
	if req == nil || reqExpired(req) {
		authRequestPop(istate)
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	fail := func(msg string) {
		redirectWith(w, ADAPTER_BASE+"/login/local?"+
			url.Values{"istate": {istate}, "error": {msg}}.Encode(), nil)
	}
	if username == "" || password == "" {
		fail("请输入账号和密码")
		return
	}
	userinfo, err := cpLocalAuth(username, password)
	if err != nil {
		logf("local auth FAILED: %s %v", username, err)
		fail(err.Error())
		return
	}
	authRequestPop(istate) // 成功才消费
	logf("local user ok: %s", username)
	issueCodeAndRedirect(w, r, req, userinfo)
}

func handleLoginLDAPPost(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/"), "/login/")
	if provider != "ldap-ad" && provider != "openldap" {
		writeHTML(w, 404, "not found")
		return
	}
	form := parseForm(readBody(r))
	istate := form.Get("istate")
	username := strings.TrimSpace(form.Get("username"))
	password := form.Get("password")
	req := authRequestGet(istate)
	if req == nil || reqExpired(req) {
		authRequestPop(istate)
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	fail := func(msg string) {
		redirectWith(w, ADAPTER_BASE+"/login/"+provider+"?"+
			url.Values{"istate": {istate}, "error": {msg}}.Encode(), nil)
	}
	if username == "" || password == "" {
		fail("请输入账号和密码")
		return
	}
	userinfo, err := ldapAuthenticate(provider, username, password)
	if err != nil {
		logf("ldap(%s) auth FAILED: %v", provider, err)
		fail(err.Error())
		return
	}
	authRequestPop(istate) // 成功才消费
	logf("ldap(%s) user ok: %s name=%s", provider, username, uiStr(userinfo, "name"))
	issueCodeAndRedirect(w, r, req, userinfo)
}

// ---- SAML ACS ----

func handleSamlACS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if err := r.ParseForm(); err != nil {
		writeHTML(w, 400, brandPage("<h2>请求不合法</h2>"))
		return
	}
	relay := r.PostForm.Get("RelayState")
	req := authRequestPop(relay)
	if req == nil || reqExpired(req) {
		writeHTML(w, 400, brandPage("<h2>state 无效或过期</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	if mStr(req, "provider") != "saml" {
		writeHTML(w, 400, brandPage("<h2>state 来源异常</h2><p>请重新发起 VPN 连接</p>"))
		return
	}
	userinfo, err := samlValidateACS(r, relay)
	if err != nil {
		var sae *samlAuthError
		if errors.As(err, &sae) {
			logf("saml acs REJECTED: %s", sae.msg)
			writeHTML(w, 400, brandPage(
				`<h2>`+esc(idpLabel("saml"))+`登录失败</h2><p class="err">`+esc(truncateStr(sae.msg, 200))+`</p>`))
			return
		}
		logf("saml acs ERROR: %v", err)
		writeHTML(w, 502, brandPage(
			`<h2>`+esc(idpLabel("saml"))+`登录失败</h2><p class="err">认证处理异常，请稍后重试</p>`))
		return
	}
	logf("saml user ok: sub=%s name=%s", truncateStr(uiStr(userinfo, "sub"), 24), uiStr(userinfo, "name"))
	issueCodeAndRedirect(w, r, req, userinfo)
}

// ---- 公开端点 ----

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                ISSUER,
		"authorization_endpoint":                ISSUER + "/authorize",
		"token_endpoint":                        ISSUER + "/token",
		"jwks_uri":                              ISSUER + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "name", "preferred_username", "email", "iss", "aud", "exp", "iat", "nonce"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, jwksJSON) }

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	idps := map[string]any{}
	for p := range IDP_META {
		idps[p] = idpEnabled(p)
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "mock": MOCK_MODE, "saml_lib": true, "idps": idps})
}

func handleLogoutWebSess(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	// 允许来源=部署拓扑派生（本机/控制面/门户基址 + MODSAFE_ADMIN_ORIGIN 可选追加），无字面量
	allowedOrigins := map[string]bool{
		ADAPTER_BASE:      true,
		CONTROL_PLANE_URL: true,
		portalBase():      true,
		os.Getenv("MODSAFE_ADMIN_ORIGIN"): true,
	}
	webSessDrop(r.Header.Get("Cookie"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	http.SetCookie(w, &http.Cookie{
		Name: "modsafe_web_sess", Value: "", Path: "/",
		HttpOnly: true, Secure: true, MaxAge: -1,
	})
	if allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleSamlMetadata(w http.ResponseWriter, r *http.Request) {
	body, err := samlSPMetadataXML()
	if err != nil {
		logf("saml metadata FAILED: %v", err)
		writeHTML(w, 500, "metadata generation failed")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(body))
}

// ---- admin 门禁包装 ----

func adminGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthed(r) {
			logf("admin-auth rejected: %s from %s", r.URL.Path, clientIP(r))
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

// ---- 路由与启动 ----

func buildMux() *http.ServeMux {
	mux := http.NewServeMux()

	// 公开（OIDC 门面）
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("GET /jwks", handleJWKS)
	mux.HandleFunc("GET /branding", handleBrandingGet)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /logout-web-sess", handleLogoutWebSess)

	// 认证链路
	mux.HandleFunc("GET /authorize", handleAuthorize)
	mux.HandleFunc("POST /token", handleToken)
	mux.HandleFunc("GET /callback/{pid}", handleOAuthCallback)
	mux.HandleFunc("GET /dingtalk/callback", handleOAuthCallback) // 旧路径兼容
	mux.HandleFunc("GET /feishu/callback", handleOAuthCallback)
	mux.HandleFunc("GET /wecom/callback", handleOAuthCallback)
	mux.HandleFunc("GET /mock/consent", handleMockConsent)
	mux.HandleFunc("GET /mock/confirm", handleMockConfirm)
	mux.HandleFunc("GET /login/local", handleLoginFormGet)
	mux.HandleFunc("GET /login/{provider}", handleLoginFormGet)
	mux.HandleFunc("POST /login/local", handleLoginLocalPost)
	mux.HandleFunc("POST /login/{provider}", handleLoginLDAPPost)

	// SAML SP
	mux.HandleFunc("GET /saml/metadata", handleSamlMetadata)
	mux.HandleFunc("POST /saml/acs", handleSamlACS)

	// 管理（X-Admin-Token 门禁）
	mux.HandleFunc("GET /admin/idp-config", adminGate(handleAdminIDPConfigGet))
	mux.HandleFunc("POST /admin/idp-config", adminGate(handleAdminIDPConfigPost))
	mux.HandleFunc("GET /admin/directory/{idp}", adminGate(handleAdminDirectory))
	mux.HandleFunc("POST /admin/branding", adminGate(handleAdminBrandingPost))
	mux.HandleFunc("GET /admin/network", adminGate(handleAdminNetworkGet))
	mux.HandleFunc("POST /admin/network", adminGate(handleAdminNetworkPost))
	mux.HandleFunc("GET /admin/alerts/channels", adminGate(handleAlertChannelsGet))
	mux.HandleFunc("POST /admin/alerts/channels", adminGate(handleAlertChannelsPost))
	mux.HandleFunc("POST /admin/alerts/channels/delete", adminGate(handleAlertChannelsDelete))
	mux.HandleFunc("GET /admin/alerts/email", adminGate(handleAlertEmailGet))
	mux.HandleFunc("POST /admin/alerts/email", adminGate(handleAlertEmailPost))
	mux.HandleFunc("POST /admin/alerts/send", adminGate(handleAlertsSend))
	mux.HandleFunc("POST /admin/alerts/test", adminGate(handleAlertsTest))
	mux.HandleFunc("POST /admin/clients/issue", adminGate(handleAdminClientsIssue))
	mux.HandleFunc("POST /admin/saml/parse-metadata", adminGate(handleSamlParseMetadata))

	return mux
}

func listenPort() string {
	// 并行冒烟用途：默认 8000 与 Python 版一致；ADAPTER_PORT 仅在灰度并行时设置
	if v := os.Getenv("ADAPTER_PORT"); v != "" {
		return v
	}
	return strconv.Itoa(ADAPTER_PORT)
}

func main() {
	validateConfig()
	logf("modsafe-idp-adapter v2 (Go) starting on :%s", listenPort())
	initRSAKey()
	initConfigSnapshot()
	logf("  issuer   = %s", ISSUER)
	logf("  oa2 base = %s", OA2_BASE)
	for _, pl := range enabledIDPs() {
		logf("  idp      = %s (%s) ENABLED", pl[0], pl[1])
	}
	b := loadBranding()
	logf("  branding = %s / %s", mStr(b, "company_name"), mStr(b, "product_name"))
	// 冒烟模式（ADAPTER_SMOKE=1）：并行试跑不回写生产 oa2 模板文件
	if os.Getenv("ADAPTER_SMOKE") != "1" {
		renderOA2Template(b)
	}

	srv := &http.Server{
		Addr:              net.JoinHostPort("", listenPort()),
		Handler:           buildMux(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	logf("listening on :%s", listenPort())
	if err := srv.ListenAndServe(); err != nil {
		logf("listen: %v", err)
	}
}
