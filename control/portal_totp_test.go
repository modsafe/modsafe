package main

// 用户侧 TOTP 双因素单测（2026-10-06）：
// 1) 策略命中矩阵：默认 off / local_only 仅本地账号 / all 全员
// 2) 受限会话闭环：policy=local_only 下本地用户登录签发 TP=1 → /self/devices 403
//    → setup → 窗口外错码 30004 → 正码 200 且重签会话 TP=0 → /self/devices 200
// 3) 强制命中态禁自行解绑（20003）；super_admin 重置后 totp_enabled=0
// 测试库全部建在临时目录，不触碰生产数据。

import (
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func setupUserTotpTest(t *testing.T) *App {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("MODSAFE_DATA_DIR", dataDir)
	t.Setenv("MODSAFE_ADMIN_TOKEN_FILE", filepath.Join(dataDir, "atok"))
	if err := os.WriteFile(filepath.Join(dataDir, "atok"), []byte("test-internal-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &App{db: mustOpenDB(dataDir)}
}

func seedLocalUser(t *testing.T, a *App, username string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("Passw0rd!x"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.db.Exec(`INSERT INTO users(username, display_name, source, status, password_hash) VALUES(?,?,?,?,?)`,
		username, username, "local", "active", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// apiCall：走真实路由链（registerAPI 含 requirePortal/requireAuth 中间件）
func apiCall(a *App, method, path, authHeader, cookie string, body io.Reader) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerAPI(mux, a)
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:60000"
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func envelope(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v (%s)", err, w.Body.String())
	}
	return out
}

// totpNow：按 secret 算当前码（与管理台同一算法，供正码/错码构造）
func totpNow(t *testing.T, secret string, offset int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return totpCode(key, time.Now().Unix()+offset*30)
}

func TestUserTotpPolicyMatrix(t *testing.T) {
	a := setupUserTotpTest(t)
	defer a.db.Close()

	// 默认 off：任何来源都不命中（部署即零行为变化）
	if userTotpPolicyHits(a, "local") || userTotpPolicyHits(a, "dingtalk") {
		t.Fatal("default policy must be off")
	}
	setSetting(a, "user_totp_policy", "local_only")
	if !userTotpPolicyHits(a, "local") {
		t.Fatal("local_only must hit local")
	}
	if userTotpPolicyHits(a, "dingtalk") {
		t.Fatal("local_only must not hit dingtalk")
	}
	setSetting(a, "user_totp_policy", "all")
	if !userTotpPolicyHits(a, "dingtalk") {
		t.Fatal("all must hit dingtalk")
	}
}

func TestUserTotpGatedFlow(t *testing.T) {
	a := setupUserTotpTest(t)
	defer a.db.Close()
	setSetting(a, "user_totp_policy", "local_only")
	uid := seedLocalUser(t, a, "totpuser")

	// 登录签发：本地账号 + 策略命中 → 受限会话（TP=1）
	if !a.totpPending(uid) {
		t.Fatal("local user under local_only must be pending")
	}
	tok, err := signPortalToken(uid, "totpuser", "local", true)
	if err != nil {
		t.Fatal(err)
	}
	sess := "portal_sess=" + tok

	// 受限会话：业务端点 403
	w := apiCall(a, "GET", "/api/v1/self/devices", "", sess, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("gated devices: want 403 got %d (%s)", w.Code, w.Body.String())
	}

	// 受限会话：me / setup 放行
	w = apiCall(a, "GET", "/api/v1/self/me", "", sess, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("gated me: want 200 got %d", w.Code)
	}
	if d := envelope(t, w)["data"].(map[string]interface{}); d["totp_required"] != true || d["totp_enabled"] != false {
		t.Fatalf("me totp flags wrong: %v", d)
	}
	w = apiCall(a, "GET", "/api/v1/self/totp/setup", "", sess, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("gated setup: want 200 got %d (%s)", w.Code, w.Body.String())
	}
	secret := envelope(t, w)["data"].(map[string]interface{})["secret"].(string)
	if secret == "" {
		t.Fatal("setup returned empty secret")
	}

	// 窗口外码（+300s，超出 ±1 窗口容差）→ 30004 验证码错误
	w = apiCall(a, "POST", "/api/v1/self/totp/enable", "", sess,
		strings.NewReader(`{"code":"`+totpNow(t, secret, 10)+`"}`))
	if e := envelope(t, w); e["code"].(float64) != 30004 {
		t.Fatalf("wrong code: want 30004 got %v", e["code"])
	}

	// 正码 → 200 + 重签完整会话（Set-Cookie TP=0）
	w = apiCall(a, "POST", "/api/v1/self/totp/enable", "", sess,
		strings.NewReader(`{"code":"`+totpNow(t, secret, 0)+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("enable: want 200 got %d (%s)", w.Code, w.Body.String())
	}
	var newTok string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == portalCookieName {
			newTok = ck.Value
		}
	}
	if newTok == "" {
		t.Fatal("enable did not reissue portal session")
	}
	pc, err := parsePortalToken(newTok)
	if err != nil {
		t.Fatal(err)
	}
	if pc.TP {
		t.Fatal("reissued session must not be pending")
	}

	// 解锁后：业务端点放行
	w = apiCall(a, "GET", "/api/v1/self/devices", "", "portal_sess="+newTok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unlocked devices: want 200 got %d (%s)", w.Code, w.Body.String())
	}

	// 强制命中态：本人禁自行解绑（20003），凭正确码也不行
	w = apiCall(a, "POST", "/api/v1/self/totp/disable", "", sess,
		strings.NewReader(`{"code":"`+totpNow(t, secret, 0)+`"}`))
	if e := envelope(t, w); e["code"].(float64) != 20003 {
		t.Fatalf("disable under enforce: want 20003 got %v", e["code"])
	}

	// super_admin 重置（丢验证器通道）→ totp_enabled=0
	adminTok, err := signToken("admin", []string{"super_admin"})
	if err != nil {
		t.Fatal(err)
	}
	w = apiCall(a, "POST", "/api/v1/users/"+strconv.FormatInt(uid, 10)+"/totp-reset", "Bearer "+adminTok, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reset: want 200 got %d (%s)", w.Code, w.Body.String())
	}
	var enabled int
	_ = a.db.QueryRow(`SELECT COALESCE(totp_enabled,0) FROM users WHERE id=?`, uid).Scan(&enabled)
	if enabled != 0 {
		t.Fatal("reset must clear totp_enabled")
	}
}

// 用户侧端点匿名不可达（新增路由的鉴权回归）
func TestUserTotpEndpointsRequireAuth(t *testing.T) {
	a := setupUserTotpTest(t)
	defer a.db.Close()
	for _, tc := range []struct{ m, p string }{
		{"GET", "/api/v1/self/totp/setup"},
		{"POST", "/api/v1/self/totp/enable"},
		{"POST", "/api/v1/self/totp/disable"},
		{"PUT", "/api/v1/settings/user-totp"},
		{"POST", "/api/v1/users/1/totp-reset"},
	} {
		w := apiCall(a, tc.m, tc.p, "", "", strings.NewReader(`{}`))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s anonymous: want 401 got %d", tc.m, tc.p, w.Code)
		}
	}
}
