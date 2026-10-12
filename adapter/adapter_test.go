package main

// 契约自测：mock 全链路 / 本地账号链路 / primary 中转页 / redirect 白名单 / PKCE /
// refresh 轮转 / SAML 签名与 metadata / admin 门禁。控制平面用 httptest 桩替身。

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type cpStub struct{ cfg map[string]any }

// TestMain：redirect 白名单现由 MODSAFE_PORTAL_BASE 派生——测试基址与下方夹具保持一致
func TestMain(m *testing.M) {
	MODSAFE_PORTAL_BASE = "https://198.51.100.10"
	os.Exit(m.Run())
}

func (s cpStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/internal/auth-config":
		b, _ := json.Marshal(map[string]any{"code": 0, "data": s.cfg})
		_, _ = w.Write(b)
	case "/api/v1/internal/auth-check":
		_, _ = w.Write([]byte(`{"code":0,"data":{"action":"allow","cert_cns":["dev-cert-1"]}}`))
	case "/api/v1/internal/auth-local":
		_, _ = w.Write([]byte(`{"code":0,"data":{"sub":"u-001","username":"alice"}}`))
	case "/api/v1/internal/connect-grant":
		// B 方案 ticket 桩：gt-valid 有效，其余无效（一次性语义由控制面单测覆盖）
		if r.URL.Query().Get("g") == "gt-valid" {
			_, _ = w.Write([]byte(`{"code":0,"data":{"uid":7,"username":"alice","display_name":"Alice","sub":"union-alice","provider":"dingtalk"}}`))
		} else {
			_, _ = w.Write([]byte(`{"code":30001,"message":"ticket invalid or expired"}`))
		}
	default:
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}
}

func setupTestEnv(t *testing.T, stubCfg map[string]any) (string, *httptest.Server, *http.Client) {
	t.Helper()
	tmp := t.TempDir()
	IDP_CONFIG_PATH = filepath.Join(tmp, "idp-config.json")
	REFRESH_STORE = filepath.Join(tmp, "oidc-refresh.json")
	ALERT_CHANNELS_F = filepath.Join(tmp, "alert-channels.json")
	CCD_RULES_PATH = filepath.Join(tmp, "ccd-rules.json")
	CCD_OUT_DIR = filepath.Join(tmp, "ccd")
	BRANDING_PATH = filepath.Join(tmp, "branding.json")
	KEY_DIR = tmp
	KEY_PATH = filepath.Join(tmp, "idp_rsa.pem")
	samlSPCertPath = filepath.Join(tmp, "saml_sp.crt")
	samlSPKeyPath = filepath.Join(tmp, "saml_sp.key")
	ADMIN_TOKEN_PATH = filepath.Join(tmp, "admin-token")

	oldMock := MOCK_MODE
	MOCK_MODE = true
	t.Cleanup(func() { MOCK_MODE = oldMock })

	cpSrv := httptest.NewServer(cpStub{cfg: stubCfg})
	oldCP := CONTROL_PLANE_URL
	CONTROL_PLANE_URL = cpSrv.URL
	t.Cleanup(func() { CONTROL_PLANE_URL = oldCP; cpSrv.Close() })

	initRSAKey()
	initConfigSnapshot()
	setIDPC(map[string]map[string]any{})

	muxSrv := httptest.NewServer(buildMux())
	t.Cleanup(muxSrv.Close)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return tmp, muxSrv, client
}

func getNoFollow(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Cleanup(func() {})
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	resp, err := c.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}

func locationOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != 302 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expect 302, got %d: %s", resp.StatusCode, string(b))
	}
	return resp.Header.Get("Location")
}

func queryOf(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return u.Query()
}

func TestMockEndToEnd(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})

	// healthz
	resp := getNoFollow(t, client, srv.URL+"/healthz")
	var hz map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&hz)
	if hz["status"] != "ok" || hz["mock"] != true {
		t.Fatalf("healthz bad: %v", hz)
	}

	verifier := randToken(32)
	challenge := pkceS256(verifier)
	authURL := srv.URL + "/authorize?" + url.Values{
		"redirect_uri": {"https://198.51.100.10/api/v1/self/callback"},
		"state":        {"oa2-st-1"}, "nonce": {"n-123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"response_type": {"code"}, "scope": {"openid"},
		"provider": {"mock"},
	}.Encode()
	loc := locationOf(t, getNoFollow(t, client, authURL))
	if !strings.HasPrefix(loc, ADAPTER_BASE+"/mock/consent?state=") {
		t.Fatalf("authorize → unexpected %s", loc)
	}
	istate := queryOf(t, loc).Get("state")

	// mock confirm → 发码回 oa2
	loc2 := locationOf(t, getNoFollow(t, client, srv.URL+"/mock/confirm?state="+istate))
	if !strings.HasPrefix(loc2, "https://198.51.100.10/api/v1/self/callback?") {
		t.Fatalf("confirm → unexpected %s", loc2)
	}
	q := queryOf(t, loc2)
	code := q.Get("code")
	if code == "" || q.Get("state") != "oa2-st-1" {
		t.Fatalf("callback qs bad: %v", q)
	}

	// /token（PKCE 正确）
	tokResp := postForm(t, client, srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {OA2_CLIENT_ID}, "client_secret": {OA2_CLIENT_SEC},
		"code_verifier": {verifier},
	})
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token %d: %s", tokResp.StatusCode, string(b))
	}
	var tok map[string]any
	_ = json.NewDecoder(tokResp.Body).Decode(&tok)
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token: %v", tok)
	}

	// id_token 验签（用包内 RSA 公钥）+ claims 断言
	parsed, err := jwt.Parse(idToken, func(tk *jwt.Token) (any, error) {
		return &rsaKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("id_token verify: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "mock-user-001" || claims["nonce"] != "n-123" ||
		claims["iss"] != ISSUER || claims["aud"] != OA2_CLIENT_ID {
		t.Fatalf("claims bad: %v", claims)
	}
	if claims["name"] != "MockUser" {
		t.Fatalf("name bad: %v", claims["name"])
	}

	// code 一次性：重放 → invalid_grant
	replay := postForm(t, client, srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {OA2_CLIENT_ID}, "client_secret": {OA2_CLIENT_SEC},
		"code_verifier": {verifier},
	})
	if replay.StatusCode != 400 {
		t.Fatalf("replay expect 400, got %d", replay.StatusCode)
	}
}

func TestPKCEFailure(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})
	authURL := srv.URL + "/authorize?" + url.Values{
		"redirect_uri":   {"https://198.51.100.10/api/v1/self/callback"},
		"code_challenge": {pkceS256("right-verifier")}, "code_challenge_method": {"S256"},
		"response_type": {"code"}, "provider": {"mock"},
	}.Encode()
	loc := locationOf(t, getNoFollow(t, client, authURL))
	istate := queryOf(t, loc).Get("state")
	loc2 := locationOf(t, getNoFollow(t, client, srv.URL+"/mock/confirm?state="+istate))
	code := queryOf(t, loc2).Get("code")

	resp := postForm(t, client, srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {OA2_CLIENT_ID}, "client_secret": {OA2_CLIENT_SEC},
		"code_verifier": {"wrong-verifier"},
	})
	if resp.StatusCode != 400 {
		t.Fatalf("PKCE fail expect 400, got %d", resp.StatusCode)
	}
}

func TestRedirectWhitelist(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})
	resp := getNoFollow(t, client, srv.URL+"/authorize?provider=mock&redirect_uri=https://evil.example/cb")
	if resp.StatusCode != 400 {
		t.Fatalf("evil redirect expect 400, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "not allowed") {
		t.Fatalf("unexpected body: %s", string(b))
	}
}

func TestSelectorPage(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})
	resp := getNoFollow(t, client,
		srv.URL+"/authorize?redirect_uri=https://198.51.100.10/api/v1/self/callback&response_type=code&scope=openid")
	if resp.StatusCode != 200 {
		t.Fatalf("selector expect 200, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "选择登录方式") || !strings.Contains(string(b), "模拟扫码（测试）") {
		t.Fatalf("selector page incomplete")
	}
}

func TestPrimaryInterstitial(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{"primary_idp": "dingtalk"})
	snap := loadIDPConfig()
	snap["dingtalk"] = map[string]any{"enabled": true, "client_id": "dk-app", "client_secret": "dk-secret"}
	setIDPC(snap)

	resp := getNoFollow(t, client,
		srv.URL+"/authorize?redirect_uri=https://198.51.100.10/api/v1/self/callback&response_type=code&scope=openid")
	if resp.StatusCode != 200 {
		t.Fatalf("interstitial expect 200, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if !strings.Contains(s, "立即进入 钉钉扫码") || !strings.Contains(s, "login.dingtalk.com/oauth2/auth") {
		t.Fatalf("interstitial missing target: %s", truncateStr(s, 300))
	}
}

// TestOAuthAuthorizeIncompleteConfig：OAuth IdP 已启用但凭据不完整时，
// /authorize 必须在本系统内报错（500 品牌页），不得把用户 302 到第三方错误页；
// 凭据补全后恢复正常跳转（authorize 只构造 URL，不出网）
func TestOAuthAuthorizeIncompleteConfig(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})
	cases := []struct {
		pid     string
		partial map[string]any
		full    map[string]any
		target  string
	}{
		{"dingtalk",
			map[string]any{"enabled": true, "client_id": "dk-app"},
			map[string]any{"enabled": true, "client_id": "dk-app", "client_secret": "dk-secret"},
			"https://login.dingtalk.com/oauth2/auth?"},
		{"feishu",
			map[string]any{"enabled": true, "app_id": "fs-app"},
			map[string]any{"enabled": true, "app_id": "fs-app", "app_secret": "fs-secret"},
			"https://open.feishu.cn/open-apis/authen/v1/authorize?"},
		{"wecom",
			map[string]any{"enabled": true, "corp_id": "ww-corp", "agent_id": "1000002"},
			map[string]any{"enabled": true, "corp_id": "ww-corp", "agent_id": "1000002", "secret": "ww-secret"},
			"https://login.work.weixin.qq.com/wwlogin/sso/login?"},
	}
	authzURL := func(pid string) string {
		return srv.URL + "/authorize?provider=" + pid +
			"&redirect_uri=https%3A%2F%2F198.51.100.10%2Fapi%2Fv1%2Fself%2Fcallback&response_type=code&scope=openid"
	}
	for _, tc := range cases {
		snap := loadIDPConfig()
		snap[tc.pid] = tc.partial
		setIDPC(snap)

		resp := getNoFollow(t, client, authzURL(tc.pid))
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 500 || !strings.Contains(string(b), "未配置完整") {
			t.Fatalf("%s 凭据不完整期望 500+未配置完整，got %d: %s", tc.pid, resp.StatusCode, truncateStr(string(b), 200))
		}

		snap = loadIDPConfig()
		snap[tc.pid] = tc.full
		setIDPC(snap)

		loc := locationOf(t, getNoFollow(t, client, authzURL(tc.pid)))
		if !strings.HasPrefix(loc, tc.target) {
			t.Fatalf("%s 凭据完整期望跳转 %s，got %s", tc.pid, tc.target, truncateStr(loc, 200))
		}
	}
}

func TestLocalAccountFlow(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{"local_auth_enabled": true})
	loc := locationOf(t, getNoFollow(t, client, srv.URL+"/authorize?provider=local&"+
		url.Values{"redirect_uri": {"https://198.51.100.10/api/v1/self/callback"},
			"response_type": {"code"}, "scope": {"openid"}}.Encode()))
	if !strings.HasPrefix(loc, ADAPTER_BASE+"/login/local?istate=") {
		t.Fatalf("local authorize → unexpected %s", loc)
	}
	istate := queryOf(t, loc).Get("istate")

	resp := postForm(t, client, srv.URL+"/login/local", url.Values{
		"istate": {istate}, "username": {"alice"}, "password": {"pw"}})
	if resp.StatusCode != 302 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("local login expect 302, got %d: %s", resp.StatusCode, string(b))
	}
	loc2 := resp.Header.Get("Location")
	code := queryOf(t, loc2).Get("code")
	if code == "" {
		t.Fatalf("local login no code: %s", loc2)
	}
	// state 只在成功时消费：二次提交应 state 无效
	resp2 := postForm(t, client, srv.URL+"/login/local", url.Values{
		"istate": {istate}, "username": {"alice"}, "password": {"pw"}})
	if resp2.StatusCode != 400 {
		t.Fatalf("consumed state expect 400, got %d", resp2.StatusCode)
	}
}

func TestAdminGate(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{})
	// 令牌文件缺失 → fail-closed
	resp := getNoFollow(t, client, srv.URL+"/admin/idp-config")
	if resp.StatusCode != 403 {
		t.Fatalf("gate expect 403, got %d", resp.StatusCode)
	}
	// 有令牌 → 200
	if err := os.WriteFile(ADMIN_TOKEN_PATH, []byte("tok-1"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/admin/idp-config", nil)
	req.Header.Set("X-Admin-Token", "tok-1")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)
	if resp2.StatusCode != 200 || out["idps"] == nil {
		t.Fatalf("admin get bad: %d %v", resp2.StatusCode, out)
	}
}

func TestRefreshRotation(t *testing.T) {
	_, _, _ = setupTestEnv(t, map[string]any{})
	tok := rtIssue("sub-1", "dingtalk", "rt-old")
	rec := rtConsume(tok)
	if rec == nil || mStr(rec, "refresh_token") != "rt-old" || mStr(rec, "provider") != "dingtalk" {
		t.Fatalf("consume bad: %v", rec)
	}
	if rtConsume(tok) != nil {
		t.Fatal("one-time violation")
	}
	if rtConsume("unknown") != nil {
		t.Fatal("unknown token must be nil")
	}
}

func TestSAMLRedirectSignAndMetadata(t *testing.T) {
	_, _, _ = setupTestEnv(t, map[string]any{})
	pair, err := ensureSPCert()
	if err != nil {
		t.Fatal(err)
	}
	snap := loadIDPConfig()
	snap["saml"] = map[string]any{
		"enabled": true, "entity_id": "https://idp.example/metadata",
		"sso_url": "https://idp.example/sso", "idp_certificate": pair.certPEM,
	}
	setIDPC(snap)

	raw, err := samlRedirectURL("state-abc")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if !strings.HasPrefix(u.String(), "https://idp.example/sso") {
		t.Fatalf("sso target bad: %s", raw)
	}
	q := u.Query()
	reqB64 := q.Get("SAMLRequest")
	sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
	// 重构被签字符串（SAMLRequest+RelayState+SigAlg 顺序）
	signedQS := "SAMLRequest=" + url.QueryEscape(reqB64) +
		"&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))
	digest := sha256.Sum256([]byte(signedQS))
	if err := rsa.VerifyPKCS1v15(&pair.key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("redirect signature verify: %v", err)
	}
	// 解压 AuthnRequest
	fr := flate.NewReader(bytes.NewReader(mustB64(reqB64)))
	xmlBytes, _ := io.ReadAll(fr)
	if !strings.Contains(string(xmlBytes), `ID="_state-abc"`) ||
		!strings.Contains(string(xmlBytes), "AssertionConsumerServiceURL") {
		t.Fatalf("AuthnRequest bad: %s", string(xmlBytes))
	}

	// SP metadata 可解析
	md, err := samlSPMetadataXML()
	if err != nil {
		t.Fatal(err)
	}
	var ent struct {
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal([]byte(md), &ent); err != nil || ent.EntityID == "" {
		t.Fatalf("sp metadata parse: %v %q", err, ent.EntityID)
	}

	// IdP metadata 解析（用 SP 证书当 IdP 证书）
	sample := fmt.Sprintf(`<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		strings.Join(strings.Fields(strings.SplitN(strings.SplitN(pair.certPEM, "-----BEGIN CERTIFICATE-----", 2)[1], "-----END CERTIFICATE-----", 2)[0]), ""))
	out, err := samlParseIDPMetadata(sample)
	if err != nil {
		t.Fatal(err)
	}
	if mStr(out, "entity_id") != "https://idp.example/metadata" ||
		mStr(out, "sso_url") != "https://idp.example/sso" ||
		mStr(out, "cert_not_after") == "" {
		t.Fatalf("idp metadata parse bad: %v", out)
	}
}

func TestNormalizeCert(t *testing.T) {
	if _, err := samlNormalizeCert(""); err == nil {
		t.Fatal("empty cert must fail")
	}
	body := strings.Repeat("abc", 40) // 120 字符裸 base64 形态
	pemStr, err := samlNormalizeCert(body)
	if err != nil || !strings.HasPrefix(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("normalize: %v", err)
	}
	if blk, _ := pem.Decode([]byte(pemStr)); blk == nil {
		t.Fatal("pem decode fail")
	}
}

// TestOA2TemplateParity：Go 渲染的 oa2 模板必须与 193 权威版（#143 基线 591c1791）
// 逐字节一致（年份动态对齐）——防止再次丢 #140/#142 注入块（切 Go 首日真实发生过的回归）。
func TestOA2TemplateParity(t *testing.T) {
	expected, err := os.ReadFile("../product-design/tpl-193-authoritative.html")
	if err != nil {
		t.Skipf("权威模板文件不在本机: %v", err)
	}
	tmp := t.TempDir()
	oldPath := OA2_TEMPLATE
	OA2_TEMPLATE = tmp + "/template.html"
	defer func() { OA2_TEMPLATE = oldPath }()
	renderOA2Template(map[string]any{
		"company_name": "模方安全", "product_name": "ModSafe", "footer_text": "安全接入",
	})
	got, err := os.ReadFile(OA2_TEMPLATE)
	if err != nil {
		t.Fatal(err)
	}
	year := time.Now().Format("2006")
	exp := strings.Replace(string(expected), "© 2026 模方安全", "© "+year+" 模方安全", 1)
	if string(got) != exp {
		i := 0
		for i < len(got) && i < len(exp) && got[i] == exp[i] {
			i++
		}
		t.Fatalf("template parity broken at byte %d\ngot: %q\nexp: %q", i,
			truncateStr(string(got[maxInt(0, i-40):]), 120),
			truncateStr(exp[maxInt(0, i-40):], 120))
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// B 方案：grant ticket 静默发码（strict 下 oa2 回调唯一静默通道）+ strict 关闭 cookie 静默
func TestPortalGrantStrictPolicy(t *testing.T) {
	_, srv, client := setupTestEnv(t, map[string]any{"client_verify_policy": "strict"})
	oa2CB := "https://198.51.100.10/oauth2/n1/oauth2/callback"

	// ① strict + oa2 回调 + 有效 grant → 静默发码，身份=ticket 用户（与浏览器无关）
	loc := locationOf(t, getNoFollow(t, client, srv.URL+"/authorize?"+url.Values{
		"redirect_uri": {oa2CB}, "state": {"oa2-st-g"}, "nonce": {"n-g"},
		"response_type": {"code"}, "scope": {"openid"},
		"grant": {"gt-valid"},
	}.Encode()))
	q := queryOf(t, loc)
	if !strings.HasPrefix(loc, oa2CB+"?") || q.Get("state") != "oa2-st-g" || q.Get("code") == "" {
		t.Fatalf("grant silent callback bad: %s", loc)
	}
	tokResp := postForm(t, client, srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"client_id": {OA2_CLIENT_ID}, "client_secret": {OA2_CLIENT_SEC},
	})
	if tokResp.StatusCode != 200 {
		t.Fatalf("token: %d", tokResp.StatusCode)
	}
	var tr map[string]any
	_ = json.NewDecoder(tokResp.Body).Decode(&tr)
	idt, _ := tr["id_token"].(string)
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(idt, claims); err != nil {
		t.Fatalf("id_token parse: %v", err)
	}
	if claims["sub"] != "union-alice" || claims["provider"] != "dingtalk" {
		t.Fatalf("grant identity mismatch: sub=%v provider=%v", claims["sub"], claims["provider"])
	}

	// ② strict + oa2 回调 + 无 grant + 浏览器 web_sess → 不再静默（落选择页 200）
	cid := webSessSave(map[string]any{"sub": "union-alice", "name": "alice"})
	req, _ := http.NewRequest("GET", srv.URL+"/authorize?"+url.Values{
		"redirect_uri": {oa2CB}, "state": {"oa2-st-g2"}, "nonce": {"n-g2"},
		"response_type": {"code"}, "scope": {"openid"},
	}.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "modsafe_web_sess", Value: cid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("strict oa2 + web_sess: got %d %s, want selector page 200", resp.StatusCode, resp.Header.Get("Location"))
	}

	// ③ strict + 门户自助回调 + web_sess → 仍静默（门户流程不受 strict 影响）
	req2, _ := http.NewRequest("GET", srv.URL+"/authorize?"+url.Values{
		"redirect_uri": {"https://198.51.100.10/api/v1/self/callback"},
		"state": {"oa2-st-g3"}, "nonce": {"n-g3"},
		"response_type": {"code"}, "scope": {"openid"},
	}.Encode(), nil)
	req2.AddCookie(&http.Cookie{Name: "modsafe_web_sess", Value: cid})
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 302 || !strings.Contains(resp2.Header.Get("Location"), "code=") {
		t.Fatalf("strict portal callback: got %d %s, want silent 302", resp2.StatusCode, resp2.Header.Get("Location"))
	}

	// ④ 无效 grant → 仅记录并落入正常流程（选择页 200，不 302）
	resp3 := getNoFollow(t, client, srv.URL+"/authorize?"+url.Values{
		"redirect_uri": {oa2CB}, "state": {"oa2-st-g4"}, "nonce": {"n-g4"},
		"response_type": {"code"}, "scope": {"openid"},
		"grant": {"gt-bad"},
	}.Encode())
	if resp3.StatusCode != 200 {
		t.Fatalf("invalid grant: got %d want selector 200", resp3.StatusCode)
	}
}
