package main

// auth-check 身份联结规则单测（#62 收紧）：
// 1) OAuth 昵称冒用防护：sub 未命中不得按 (source,username) 拣行（改昵称=冒用他人身份）
// 2) 建档撞名消歧：昵称与本源既有行同名时加 sub 后 6 位（否则 UNIQUE 冲突建档失败）
// 3) 本地账号登录保留名字匹配通道（sub=local-xxx 格式，无冒用面）
// 4) external_id/union_id 匹配限同源（跨 IdP 键域碰撞不错配）

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func setupAuthCheckTest(t *testing.T) *App {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("MODSAFE_DATA_DIR", dataDir)
	t.Setenv("MODSAFE_ADMIN_TOKEN_FILE", filepath.Join(dataDir, "atok"))
	if err := os.WriteFile(filepath.Join(dataDir, "atok"), []byte("test-internal-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &App{db: mustOpenDB(dataDir)}
}

func authCheckCall(t *testing.T, a *App, username, display, idp, ext string) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username, "display_name": display,
		"idp_source": idp, "external_id": ext,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/internal/auth-check", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:60000"
	r.Header.Set("X-Internal-Token", "test-internal-token")
	w := httptest.NewRecorder()
	a.handleInternalAuthCheck(w, r)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	d, _ := out["data"].(map[string]interface{})
	return d
}

func TestAuthCheckIdentityRules(t *testing.T) {
	a := setupAuthCheckTest(t)
	defer a.db.Close()

	// 预置：目录同步建的钉钉行（zhangsan）
	res, err := a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, union_id, status)
		VALUES('zhangsan','张三','dingtalk','userid1','unionid1','active')`)
	if err != nil {
		t.Fatal(err)
	}
	zsID, _ := res.LastInsertId()

	// 1) 正常扫码：sub=unionid1 → 级2 union_id 命中张三行
	d := authCheckCall(t, a, "zhangsan", "张三", "dingtalk", "unionid1")
	if d["action"] != "allow" || int64(d["user_id"].(float64)) != zsID || d["created"] != false {
		t.Fatalf("normal scan should hit zhangsan row: %v", d)
	}

	// 2) 昵称冒用：李四把昵称改成 "zhangsan"，sub=unionid2 → 不得命中张三行；建档消歧
	d = authCheckCall(t, a, "zhangsan", "zhangsan", "dingtalk", "unionid2")
	if d["created"] != true {
		t.Fatalf("impersonation should create new row, got: %v", d)
	}
	lisiID := int64(d["user_id"].(float64))
	if lisiID == zsID {
		t.Fatal("impersonator must NOT bind zhangsan's row")
	}
	var uname, ext, uni string
	if err := a.db.QueryRow(`SELECT username, COALESCE(external_id,''), COALESCE(union_id,'')
		FROM users WHERE id=?`, lisiID).Scan(&uname, &ext, &uni); err != nil {
		t.Fatal(err)
	}
	// 消歧名 = zhangsan-ionid2（sub 后 6 位），union_id 同步写入（钉钉）
	if uname != "zhangsan-ionid2" || ext != "unionid2" || uni != "unionid2" {
		t.Fatalf("disambiguated row wrong: %q %q %q", uname, ext, uni)
	}

	// 3) local 登录通道：sub=local-lu 格式，按 (local, lu) 名字命中
	a.db.Exec(`INSERT INTO users(username, display_name, source, status) VALUES('lu','lu','local','active')`)
	d = authCheckCall(t, a, "lu", "lu", "local", "local-lu")
	if d["action"] != "allow" || d["created"] != false {
		t.Fatalf("local login should hit by name: %v", d)
	}

	// 4) 限源：飞书行 external_id=X；钉钉 sub=X 不得命中（建档新行）
	a.db.Exec(`INSERT INTO users(username, display_name, source, external_id, status)
		VALUES('feishu-user','feishu-user','feishu','X','active')`)
	d = authCheckCall(t, a, "ding-user", "ding-user", "dingtalk", "X")
	if d["created"] != true {
		t.Fatalf("cross-source external_id must not match: %v", d)
	}

	// 5) 禁用拦截仍生效：unionid1 行禁用 → 同 sub 认证 deny
	a.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, zsID)
	d = authCheckCall(t, a, "zhangsan", "张三", "dingtalk", "unionid1")
	if d["action"] != "deny" {
		t.Fatalf("disabled user must deny: %v", d)
	}
}
