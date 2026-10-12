package main

// 用户自助门户（§16）：面向员工的自服务入口。
// 认证复用 idp-adapter（与 VPN 同一身份）：/self/login → adapter /authorize（PKCE）
// → /self/callback 用 code 换 id_token（JWKS RS256 验签）→ 内部 auth-check 建档/审计
// → 签发门户 JWT（HttpOnly Cookie 8h，aud=portal）。
// 安全红线（§16.4）：/self/* 不接受任何 user_id 参数，主体恒取 JWT，他人数据一律 404；
// 门户 JWT 与管理台 JWT 以 aud 隔离（requireAuth 拒 aud=portal，requirePortal 拒无 aud）。

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const portalCookieName = "portal_sess"
const portalOAuthCookie = "portal_oauth_state" // 登录 CSRF 防护：state 与发起浏览器绑定
const portalAudience = "portal"

var (
	portalClientID     = envOr("MODSAFE_PORTAL_CLIENT_ID", "")
	portalClientSecret = envOr("MODSAFE_PORTAL_CLIENT_SECRET", "")
	// 发给浏览器的外部地址（用户机器可达）；服务端自调用仍走 adapterBase=127.0.0.1。
	// 必填：main→validateConfig 校验，缺失拒绝启动（门户登录跳转依赖它）
	adapterPublicBase = envOr("MODSAFE_ADAPTER_PUBLIC_URL", "")

	pkceMu     sync.Mutex
	pkceStates = map[string]pkceState{} // state → verifier（10 分钟 TTL）
)

type pkceState struct {
	verifier string
	exp      time.Time
}

type portalClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"username"`
	Source   string `json:"src"`
	// TP：双因素待绑定受限会话（user_totp_policy 命中且未绑定）——requirePortal 仅放行 me/totp
	TP bool `json:"tp,omitempty"`
	jwt.RegisteredClaims
}

// totpPending：是否需要门户先完成双因素绑定（策略命中 && 未绑定）
func (a *App) totpPending(userID int64) bool {
	enabled, _, source := a.userTotpState(userID)
	return !enabled && userTotpPolicyHits(a, source)
}

func signPortalToken(userID int64, username, source string, totpPending bool) (string, error) {
	claims := portalClaims{
		UserID: userID, Username: username, Source: source, TP: totpPending,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{portalAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "modsafe-control-portal",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret())
}

// parsePortalToken：强制 aud=portal（管理台 token 无 aud → 拒，垂直越权隔离）
func parsePortalToken(tokenStr string) (*portalClaims, error) {
	claims := &portalClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret(), nil
	}, jwt.WithAudience(portalAudience))
	return claims, err
}

func portalEnabled(a *App) bool {
	return getSetting(a, "portal_enabled", "1") == "1"
}

// requirePortal：/api/v1/self/* 中间件（门户开关 + cookie 会话）
func (a *App) requirePortal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !portalEnabled(a) {
			writeFail(w, r, 30002, http.StatusForbidden, "自助门户已被管理员停用")
			return
		}
		c, err := r.Cookie(portalCookieName)
		if err != nil || c.Value == "" {
			writeFail(w, r, 30001, http.StatusUnauthorized, "未登录")
			return
		}
		claims, err := parsePortalToken(c.Value)
		if err != nil {
			writeFail(w, r, 30001, http.StatusUnauthorized, "登录已过期")
			return
		}
		// 双因素受限会话（TP=1）：仅可完成绑定闭环，其余一律 403
		//（logout 无需放行——该端点本就不经 requirePortal）
		if claims.TP {
			p := r.URL.Path
			if p != "/api/v1/self/me" && !strings.HasPrefix(p, "/api/v1/self/totp/") {
				writeFail(w, r, 30002, http.StatusForbidden, "请先完成双因素认证绑定")
				return
			}
		}
		next(w, r.WithContext(withPortalClaims(r, claims)))
	}
}

// ── OAuth 流（复用 adapter）──

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// handlePortalLogin：GET /api/v1/self/login → 302 adapter /authorize（PKCE S256）
func (a *App) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	if !portalEnabled(a) {
		http.Error(w, "自助门户已被管理员停用", http.StatusForbidden)
		return
	}
	verifierB := make([]byte, 48)
	_, _ = rand.Read(verifierB)
	stateB := make([]byte, 24)
	_, _ = rand.Read(stateB)
	verifier, state := b64u(verifierB), b64u(stateB)
	pkceMu.Lock()
	// 顺手清理过期项
	for k, v := range pkceStates {
		if time.Now().After(v.exp) {
			delete(pkceStates, k)
		}
	}
	pkceStates[state] = pkceState{verifier: verifier, exp: time.Now().Add(10 * time.Minute)}
	pkceMu.Unlock()

	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https" // HTTPS 化（2026-09-30）：经 nginx TLS 终结时读转发头
	}
	redirectURI := scheme + "://" + r.Host + "/api/v1/self/callback"
	q := "provider=&redirect_uri=" + urlQueryEscape(redirectURI) +
		"&state=" + state + "&nonce=" + state +
		"&code_challenge=" + b64u(sha256sum(verifier)) +
		"&code_challenge_method=S256&response_type=code&scope=openid"
	// 登录 CSRF 防护：state 以 HttpOnly cookie 绑定发起浏览器，callback 必须带回同值
	// （否则攻击者可用自己凭证截获的 code+state 让受害者浏览器完成"攻击者身份"登录）
	http.SetCookie(w, &http.Cookie{
		Name: portalOAuthCookie, Value: state, Path: "/api/v1/self", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, adapterPublicBase+"/authorize?"+q, http.StatusFound)
}

// handlePortalCallback：GET /api/v1/self/callback?code&state → 换 id_token → 验签 → 建档 → 门户 cookie
func (a *App) handlePortalCallback(w http.ResponseWriter, r *http.Request) {
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	// 登录 CSRF 防护：state 必须与本浏览器发起时种下的 cookie 一致
	if oc, err := r.Cookie(portalOAuthCookie); err != nil || oc.Value == "" || oc.Value != state {
		http.Error(w, "state 校验失败，请从门户重新发起登录", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: portalOAuthCookie, Value: "", Path: "/api/v1/self", HttpOnly: true, MaxAge: -1})
	pkceMu.Lock()
	st, ok := pkceStates[state]
	delete(pkceStates, state)
	pkceMu.Unlock()
	if !ok || time.Now().After(st.exp) {
		http.Error(w, "state 无效或过期，请重新进入门户", http.StatusBadRequest)
		return
	}
	tok, err := adapterTokenExchange(code, st.verifier)
	if err != nil {
		http.Error(w, "登录失败："+err.Error(), http.StatusBadGateway)
		return
	}
	claims, err := verifyAdapterIDToken(tok.IDToken)
	if err != nil {
		http.Error(w, "身份令牌验证失败："+err.Error(), http.StatusBadGateway)
		return
	}
	// nonce 单次消费校验（此前发出但从不校验）
	if claims.Nonce != "" && claims.Nonce != state {
		http.Error(w, "nonce 校验失败", http.StatusBadRequest)
		return
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Name
	}
	// 复用 ② 认证链路：建档/禁用拦截/审计/CCD 同步（自调用内部端点，行为与 VPN 登录一致）
	userID, deny, reason := a.portalAuthCheck(username, claims.Name, claims.Subject, claims.Email, claims.Provider)
	if deny {
		http.Error(w, "登录被拒绝："+reason, http.StatusForbidden)
		return
	}
	tokStr, err := signPortalToken(userID, username, claims.Subject, a.totpPending(userID))
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name: portalCookieName, Value: tokStr, Path: "/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600,
		})
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

type adapterTokenResp struct {
	IDToken string `json:"id_token"`
}

// adapterTokenExchange：POST adapter /token（client 凭证 + PKCE verifier）
func adapterTokenExchange(code, verifier string) (*adapterTokenResp, error) {
	body := strings.NewReader(strings.Join([]string{
		"grant_type=authorization_code", "code=" + urlQueryEscape(code),
		"client_id=" + urlQueryEscape(portalClientID), "client_secret=" + urlQueryEscape(portalClientSecret),
		"code_verifier=" + urlQueryEscape(verifier),
	}, "&"))
	resp, err := http.Post(adapterBase+"/token", "application/x-www-form-urlencoded", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out adapterTokenResp
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	if e, ok := raw["error"].(string); ok {
		msg, _ := raw["error_description"].(string)
		if msg != "" {
			e = e + ": " + msg
		}
		return nil, &portalError{e}
	}
	if idt, ok := raw["id_token"].(string); ok {
		out.IDToken = idt
		return &out, nil
	}
	return nil, &portalError{"token 响应缺少 id_token"}
}

type portalError struct{ msg string }

func (e *portalError) Error() string { return e.msg }

type adapterIDClaims struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Provider          string `json:"provider,omitempty"` // 真实认证源（2026-09-30：门户透传，杜绝 source=portal 影子身份）
	Nonce             string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// verifyAdapterIDToken：JWKS RS256 验签 + aud/client 校验（门户是暴露面最大的组件，不省验签）
func verifyAdapterIDToken(idToken string) (*adapterIDClaims, error) {
	claims := &adapterIDClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (interface{}, error) {
		return adapterJWKSPubKey()
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(portalClientID))
	return claims, err
}

// ── 本地账号登录（§16.1：与 VPN 同一身份体系的兜底入口）──

// handlePortalLoginLocal：POST /api/v1/self/login-local {username, password}
func (a *App) handlePortalLoginLocal(w http.ResponseWriter, r *http.Request) {
	if !portalEnabled(a) {
		writeFail(w, r, 30002, http.StatusForbidden, "自助门户已被管理员停用")
		return
	}
	// CSRF 防护：仅接受 JSON（text/plain 表单可跨站构造 JSON 体）；有 Origin/Referer 时必须同源
	if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		failParam(w, r, "Content-Type 必须为 application/json")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if host := r.Host; host != "" && !strings.HasSuffix(strings.TrimPrefix(origin, "http://"), host) &&
			!strings.HasSuffix(strings.TrimPrefix(origin, "https://"), host) {
			writeFail(w, r, 30002, http.StatusForbidden, "跨站请求被拒绝")
			return
		}
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
		failParam(w, r, "账号和密码不能为空")
		return
	}
	username := strings.TrimSpace(req.Username)
	// 暴破限速：IP+用户名 分桶（共享 NAT 出口的办公网下不同员工互不影响）
	if !loginLimiter.allow("portal|"+remoteIP(r)+"|"+username) {
		writeFail(w, r, 30005, http.StatusTooManyRequests, "尝试过于频繁，请 5 分钟后重试")
		return
	}
	var id int64
	var display, hash, status string
	err := a.db.QueryRow(`SELECT id, COALESCE(display_name,''), COALESCE(password_hash,''), status
		FROM users WHERE username=? AND source='local'`, username).Scan(&id, &display, &hash, &status)
	if err != nil || status != "active" || hash == "" ||
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		if err != nil {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(req.Password)) // 时序对齐
		}
		writeFail(w, r, 30004, http.StatusUnauthorized, "账号或密码错误")
		return
	}
	_, _ = a.db.Exec(`UPDATE users SET last_login_at=datetime('now','localtime') WHERE id=?`, id)
	a.auditInternal(r, authCheckReq{Username: username, IDPSource: "local"}, "success", "门户本地登录")
	tok, err := signPortalToken(id, username, "local", a.totpPending(id))
	if err != nil {
		failSystem(w, r, "会话签发失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalCookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600,
	})
	writeOK(w, r, map[string]interface{}{"ok": true})
}

// handleSelfBranding：公开品牌信息（未登录可读——登录页本就公开展示品牌，
// 门户顶栏标题与 branding.json 联动，管理台改品牌门户即变）
func (a *App) handleSelfBranding(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("GET", "/branding", nil)
	if err != nil {
		// #99：adapter 不可达时的降级回退——公司名回退中性值（真实公司名只应来自
		// branding.json 配置，代码默认值不再硬编码客户公司名）
		out = map[string]interface{}{"company_name": "modsafe", "product_name": "modsafe"}
	}
	writeOK(w, r, out)
}

// handlePortalLogout：POST /api/v1/self/logout（清 cookie）
func (a *App) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: portalCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeOK(w, r, nil)
}
