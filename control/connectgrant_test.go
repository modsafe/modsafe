package main

// handleInternalConnectGrant 单元测试（B 方案网页一键连接 ticket）。
// 覆盖：鉴权形态（无头 403）、签发→核销身份推导（union_id 优先/external_id 次选/
// local-xxx 兜底，与 whoami 同构）、单次核销（重放 404）、过期 404、禁用用户 404、
// 空参数 400。测试库全部建在临时目录。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupGrantTest(t *testing.T) *App {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("MODSAFE_DATA_DIR", dataDir)
	t.Setenv("MODSAFE_ADMIN_TOKEN_FILE", filepath.Join(dataDir, "atok"))
	if err := os.WriteFile(filepath.Join(dataDir, "atok"), []byte("test-internal-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{db: mustOpenDB(dataDir)}
	t.Cleanup(func() { _ = a.db.Close() }) // Windows 下句柄不关 TempDir 清理失败
	return a
}

func grantReq(t *testing.T, a *App, ticket, internalTok string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/internal/connect-grant?g="+ticket, nil)
	r.RemoteAddr = "127.0.0.1:60000"
	if internalTok != "" {
		r.Header.Set("X-Internal-Token", internalTok)
	}
	w := httptest.NewRecorder()
	a.handleInternalConnectGrant(w, r)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if d, ok := body["data"].(map[string]interface{}); ok {
		return w, d
	}
	return w, body
}

func TestConnectGrantAuthn(t *testing.T) {
	a := setupGrantTest(t)

	// 无 X-Internal-Token → 403
	r := httptest.NewRequest(http.MethodGet, "/api/v1/internal/connect-grant?g=x", nil)
	r.RemoteAddr = "127.0.0.1:60000"
	w := httptest.NewRecorder()
	a.handleInternalConnectGrant(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no internal token: got %d want 403", w.Code)
	}

	// 空 g → 400
	if w, _ := grantReq(t, a, "", "test-internal-token"); w.Code != http.StatusBadRequest {
		t.Fatalf("empty g: got %d want 400", w.Code)
	}
}

func TestConnectGrantIssueConsumeIdentity(t *testing.T) {
	a := setupGrantTest(t)
	var uidDing, uidLocal, uidExt int64
	res, _ := a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, union_id, status)
		VALUES('张三','张三','dingtalk','userid-1','union-1','active')`)
	uidDing, _ = res.LastInsertId()
	res, _ = a.db.Exec(`INSERT INTO users(username, display_name, source, status)
		VALUES('admin','管理员','local','active')`)
	uidLocal, _ = res.LastInsertId()
	res, _ = a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, status)
		VALUES('lisi','李四','openldap','CN=lisi,DC=x','active')`)
	uidExt, _ = res.LastInsertId()

	// union_id 优先（钉钉行 sub=union-1，provider=dingtalk）
	tk := issueConnectGrant(uidDing)
	w, d := grantReq(t, a, tk, "test-internal-token")
	if w.Code != 200 || d["sub"] != "union-1" || d["provider"] != "dingtalk" || d["username"] != "张三" {
		t.Fatalf("dingtalk: code=%d sub=%v provider=%v", w.Code, d["sub"], d["provider"])
	}
	// 单次核销：同 ticket 重放 → 404
	if w, _ := grantReq(t, a, tk, "test-internal-token"); w.Code != http.StatusNotFound {
		t.Fatalf("replay: got %d want 404", w.Code)
	}

	// 纯本地行 sub=local-<username>
	w, d = grantReq(t, a, issueConnectGrant(uidLocal), "test-internal-token")
	if w.Code != 200 || d["sub"] != "local-admin" || d["provider"] != "local" {
		t.Fatalf("local: code=%d sub=%v", w.Code, d["sub"])
	}

	// 无 union 行 sub=external_id
	w, d = grantReq(t, a, issueConnectGrant(uidExt), "test-internal-token")
	if w.Code != 200 || d["sub"] != "CN=lisi,DC=x" {
		t.Fatalf("ldap ext: code=%d sub=%v", w.Code, d["sub"])
	}
}

func TestConnectGrantExpiryAndDisabledUser(t *testing.T) {
	a := setupGrantTest(t)
	res, _ := a.db.Exec(`INSERT INTO users(username, display_name, source, status)
		VALUES('u1','u1','local','active')`)
	uid, _ := res.LastInsertId()

	// 过期 → 404（直接改内存态模拟超时）
	tk := issueConnectGrant(uid)
	cgMu.Lock()
	g := cgTickets[tk]
	g.expiresAt = time.Now().Add(-time.Second)
	cgTickets[tk] = g
	cgMu.Unlock()
	if w, _ := grantReq(t, a, tk, "test-internal-token"); w.Code != http.StatusNotFound {
		t.Fatalf("expired: got %d want 404", w.Code)
	}

	// 禁用用户 → 404，且 ticket 已被消费不可重放
	_, _ = a.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, uid)
	tk2 := issueConnectGrant(uid)
	if w, _ := grantReq(t, a, tk2, "test-internal-token"); w.Code != http.StatusNotFound {
		t.Fatalf("disabled: got %d want 404", w.Code)
	}
	_, _ = a.db.Exec(`UPDATE users SET status='active' WHERE id=?`, uid)
	if w, _ := grantReq(t, a, tk2, "test-internal-token"); w.Code != http.StatusNotFound {
		t.Fatalf("replay after re-enable: got %d want 404", w.Code)
	}
}
