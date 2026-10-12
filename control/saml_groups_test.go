package main

// §22 SAML 配套单测：
// 1) License feature 位（§22.6-8：无 saml feature 的 license 拒绝启用 SAML）
// 2) auth-check groups 属性绑定（§22.4：同名本地组幂等入组、不自动建组、未知组跳过）

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLicensePayloadHasFeature(t *testing.T) {
	// nil = 试用模式 = 全功能
	if !licensePayloadHasFeature(nil, "saml") {
		t.Fatal("trial (nil payload) must allow all features")
	}
	lic := &licensePayload{Features: []string{" saml ", "scim", "totp"}}
	if !licensePayloadHasFeature(lic, "saml") {
		t.Fatal("payload with saml feature must pass (license value trimmed)")
	}
	if licensePayloadHasFeature(lic, "ha") {
		t.Fatal("payload without feature must reject")
	}
	if licensePayloadHasFeature(&licensePayload{Features: nil}, "saml") {
		t.Fatal("empty features must reject")
	}
}

func TestAuthCheckBindsIdpGroups(t *testing.T) {
	a := setupAuthCheckTest(t)
	defer a.db.Close()

	// 预置：本地组「研发部」（SAML 属性组同名）与「销售部」（不含目标用户组）
	if _, err := a.db.Exec(`INSERT INTO user_groups(name) VALUES('研发部'),('销售部')`); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"username": "samu", "display_name": "萨姆", "idp_source": "saml",
		"external_id": "saml-union-001",
		"groups":      []string{"研发部", "不存在的组", "", "研发部"}, // 未知组跳过；重复幂等
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/internal/auth-check", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:60000"
	r.Header.Set("X-Internal-Token", "test-internal-token")
	w := httptest.NewRecorder()
	a.handleInternalAuthCheck(w, r)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	d, _ := out["data"].(map[string]interface{})
	if d == nil || d["action"] != "allow" {
		t.Fatalf("saml auth-check must allow: %v", out)
	}
	uid := int64(d["user_id"].(float64))

	// 只绑定同名既有组；不存在的组不建组；重复绑定不产生多行
	var cnt int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM group_members gm
		JOIN user_groups g ON g.id=gm.group_id WHERE gm.user_id=? AND g.name='研发部'`, uid).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("user must be bound to 研发部 exactly once, got %d", cnt)
	}
	var total int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE user_id=?`, uid).Scan(&total)
	if total != 1 {
		t.Fatalf("unknown/empty groups must be skipped, total=%d", total)
	}
	var groupsCnt int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM user_groups`).Scan(&groupsCnt)
	if groupsCnt != 2 {
		t.Fatalf("no group should be auto-created, groups=%d", groupsCnt)
	}

	// 第二次认证（同 sub 命中同一行）带不同组 → 追加绑定，不重建身份
	body2, _ := json.Marshal(map[string]interface{}{
		"username": "samu", "display_name": "萨姆", "idp_source": "saml",
		"external_id": "saml-union-001",
		"groups":      []string{"销售部"},
	})
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/internal/auth-check", bytes.NewReader(body2))
	r2.RemoteAddr = "127.0.0.1:60000"
	r2.Header.Set("X-Internal-Token", "test-internal-token")
	w2 := httptest.NewRecorder()
	a.handleInternalAuthCheck(w2, r2)
	var out2 map[string]interface{}
	_ = json.Unmarshal(w2.Body.Bytes(), &out2)
	d2, _ := out2["data"].(map[string]interface{})
	if d2 == nil || d2["action"] != "allow" || int64(d2["user_id"].(float64)) != uid {
		t.Fatalf("second auth must hit same user row: %v", out2)
	}
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE user_id=?`, uid).Scan(&total)
	if total != 2 {
		t.Fatalf("second auth should add 销售部 binding, total=%d", total)
	}
}
