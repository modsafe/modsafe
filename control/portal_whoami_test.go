package main

// handleInternalPortalWhoami 单元测试（#57 身份归属修复）。
// 覆盖：鉴权形态（无头/假 token）、union_id 优先 sub、external_id 次选、
// 纯本地行 sub=local-<username>、禁用行 404、pt 参数与 Cookie 两种传入方式。
// 测试库全部建在临时目录，不触碰生产数据；internal token 经 env 注入。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupWhoamiTest(t *testing.T) *App {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("MODSAFE_DATA_DIR", dataDir)                                   // jwt_secret 落临时目录
	t.Setenv("MODSAFE_ADMIN_TOKEN_FILE", filepath.Join(dataDir, "atok"))    // internal token 注入
	if err := os.WriteFile(filepath.Join(dataDir, "atok"), []byte("test-internal-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &App{db: mustOpenDB(dataDir)}
}

func whoamiReq(t *testing.T, a *App, pt string, cookie string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	u := "/api/v1/internal/portal-whoami"
	if pt != "" {
		u += "?pt=" + pt
	}
	r := httptest.NewRequest(http.MethodGet, u, nil)
	r.RemoteAddr = "127.0.0.1:60000"
	r.Header.Set("X-Internal-Token", "test-internal-token")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	a.handleInternalPortalWhoami(w, r)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	// 取 data 层（writeOK envelope: {code,message,data,traceId}）
	if d, ok := body["data"].(map[string]interface{}); ok {
		return w, d
	}
	return w, body
}

func TestPortalWhoamiAuthn(t *testing.T) {
	a := setupWhoamiTest(t)

	// 无 X-Internal-Token → 403
	r := httptest.NewRequest(http.MethodGet, "/api/v1/internal/portal-whoami?pt=x", nil)
	r.RemoteAddr = "127.0.0.1:60000"
	w := httptest.NewRecorder()
	a.handleInternalPortalWhoami(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no token header: want 403 got %d", w.Code)
	}

	// 非 loopback 来源 → 403
	r = httptest.NewRequest(http.MethodGet, "/api/v1/internal/portal-whoami?pt=x", nil)
	r.RemoteAddr = "192.0.2.1:60000"
	r.Header.Set("X-Internal-Token", "test-internal-token")
	w = httptest.NewRecorder()
	a.handleInternalPortalWhoami(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-loopback: want 403 got %d", w.Code)
	}

	// 有头无 token（pt 与 Cookie 均无）→ 404
	w, _ = whoamiReq(t, a, "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("no session: want 404 got %d", w.Code)
	}

	// 假 token → 404
	w, _ = whoamiReq(t, a, "bogus.jwt.value", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("bogus token: want 404 got %d", w.Code)
	}
	a.db.Close() // Windows: 释放 sqlite 文件锁，允许 TempDir 清理
}

func TestPortalWhoamiIdentityResolution(t *testing.T) {
	a := setupWhoamiTest(t)

	// 三类用户：钉钉（union_id+external_id）、本地（两者皆无）、被禁用钉钉
	var dingUID, localUID, disUID int64
	res, err := a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, union_id, status)
		VALUES('zhangsan-d3f210','张三','dingtalk','ext123','unionAAA','active')`)
	if err != nil {
		t.Fatal(err)
	}
	dingUID, _ = res.LastInsertId()
	res, err = a.db.Exec(`INSERT INTO users(username, display_name, source, status)
		VALUES('lu','路工','local','active')`)
	if err != nil {
		t.Fatal(err)
	}
	localUID, _ = res.LastInsertId()
	res, err = a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, union_id, status)
		VALUES('wangwu','王五','dingtalk','ext999','unionBBB','disabled')`)
	if err != nil {
		t.Fatal(err)
	}
	disUID, _ = res.LastInsertId()

	// 签发真实 portal JWT（复用生产签名函数，aud=portal）
	tokDing, _ := signPortalToken(dingUID, "zhangsan-d3f210", "dingtalk", false)
	tokLocal, _ := signPortalToken(localUID, "lu", "local", false)
	tokDis, _ := signPortalToken(disUID, "wangwu", "dingtalk", false)

	// 钉钉用户：sub=union_id 优先，provider=dingtalk
	w, body := whoamiReq(t, a, tokDing, "")
	if w.Code != http.StatusOK {
		t.Fatalf("dingtalk user: want 200 got %d body=%v", w.Code, body)
	}
	if body["sub"] != "unionAAA" || body["provider"] != "dingtalk" || body["username"] != "zhangsan-d3f210" {
		t.Fatalf("dingtalk identity: %v", body)
	}

	// 本地用户：无 union/external → sub=local-<username>，auth-check 走 (source,username) 匹配
	w, body = whoamiReq(t, a, "", "portal_sess="+tokLocal)
	if w.Code != http.StatusOK {
		t.Fatalf("local user via cookie: want 200 got %d", w.Code)
	}
	if body["sub"] != "local-lu" || body["provider"] != "local" {
		t.Fatalf("local identity: %v", body)
	}

	// 被禁用用户 → 404（不适用静默）
	w, _ = whoamiReq(t, a, tokDis, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled user: want 404 got %d", w.Code)
	}

	// 仅 external_id（无 union_id）→ sub=external_id
	res, err = a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, status)
		VALUES('feishu-a','飞书用户','feishu','extFS1','active')`)
	if err != nil {
		t.Fatal(err)
	}
	fsUID, _ := res.LastInsertId()
	tokFS, _ := signPortalToken(fsUID, "feishu-a", "feishu", false)
	w, body = whoamiReq(t, a, tokFS, "")
	if w.Code != http.StatusOK || body["sub"] != "extFS1" || body["provider"] != "feishu" {
		t.Fatalf("feishu identity: %d %v", w.Code, body)
	}

	// 不存在的 uid → 404
	tokGhost, _ := signPortalToken(99999, "ghost", "dingtalk", false)
	w, _ = whoamiReq(t, a, tokGhost, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("ghost uid: want 404 got %d", w.Code)
	}

	// 响应结构：code=0 + data
	w, _ = whoamiReq(t, a, tokDing, "")
	if !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("envelope code!=0: %s", w.Body.String())
	}
	a.db.Close() // Windows: 释放 sqlite 文件锁，允许 TempDir 清理
}

// TestIdpUnionID：union_id 列写入白名单——钉钉/飞书 sub=平台 unionid 可写入，
// 企微（sub=userid 与目录同域）/LDAP/本地必须返回空（写入会破坏同步匹配语义）
func TestIdpUnionID(t *testing.T) {
	cases := []struct {
		idp, sub, want string
	}{
		{"dingtalk", "62t3XGqaNMCL", "62t3XGqaNMCL"},
		{"feishu", "on_7ba877a59e5", "on_7ba877a59e5"},
		{"wecom", "zhangsan", ""}, // 企微 sub=userid，不得进 union_id
		{"ldap-ad", "CN=z,DC=x", ""},
		{"openldap", "uid=z,dc=x", ""},
		{"local", "local-zhangsan", ""},
		{"dingtalk", "", ""},
		{"", "anything", ""},
	}
	for _, c := range cases {
		if got := idpUnionID(c.idp, c.sub); got != c.want {
			t.Fatalf("idpUnionID(%q,%q)=%q want %q", c.idp, c.sub, got, c.want)
		}
	}
}
