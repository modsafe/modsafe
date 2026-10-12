package main

// 门户辅助：JWKS 公钥缓存、auth-check 自调用、URL/PKCE 工具。

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func sha256sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

var (
	jwksMu    sync.Mutex
	jwksKey   *rsa.PublicKey
	jwksAt    time.Time
)

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// adapterJWKSPubKey：拉 adapter /jwks 构造 RSA 公钥（进程内缓存 1h）。
// 刷新失败时保留旧钥兜底（轮换/瞬断不再直接打断登录）。
func adapterJWKSPubKey() (*rsa.PublicKey, error) {
	jwksMu.Lock()
	defer jwksMu.Unlock()
	if jwksKey != nil && time.Since(jwksAt) < time.Hour {
		return jwksKey, nil
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(adapterBase + "/jwks")
	if err != nil {
		if jwksKey != nil {
			return jwksKey, nil // stale 兜底
		}
		return nil, err
	}
	defer resp.Body.Close()
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		if jwksKey != nil {
			return jwksKey, nil
		}
		return nil, err
	}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nB, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eB, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eB {
			e = e<<8 | int(b)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(nB), E: e}
		jwksKey, jwksAt = key, time.Now()
		return key, nil
	}
	return nil, errNoRSAKey{}
}

type errNoRSAKey struct{}

func (errNoRSAKey) Error() string { return "JWKS 中无 RSA 密钥" }

// portalAuthCheck：门户登录后复用 ② 认证链路（自调用内部端点）：
// 存在性/禁用拦截/自动建档/审计/CCD 同步——与 VPN 登录行为完全一致。
// 2026-09-30：idp_source 透传真实认证源（钉钉/飞书/企微/LDAP）——
// 此前硬编码 "portal" 自动建档出影子身份（同一人两行），已废弃该假源。
func (a *App) portalAuthCheck(username, displayName, sub, email, provider string) (userID int64, deny bool, reason string) {
	if provider == "" || provider == "web-sess" {
		provider = "portal" // 兜底（新 adapter 的 id_token 必带 provider，此分支仅兼容旧令牌）
	}
	body := map[string]interface{}{
		"username": username, "display_name": displayName,
		"idp_source": provider, "external_id": sub, "email": email,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "http://127.0.0.1:9443/api/v1/internal/auth-check", strings.NewReader(string(payload)))
	if err != nil {
		return 0, true, "内部服务不可用"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", internalToken())
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, true, "内部服务不可用"
	}
	defer resp.Body.Close()
	var out struct {
		Code int    `json:"code"`
		Data struct {
			Action string `json:"action"`
			UserID int64  `json:"user_id"`
			Reason string `json:"reason"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, true, "内部服务响应异常"
	}
	if out.Code != 0 || out.Data.Action != "allow" {
		return 0, true, out.Data.Reason
	}
	return out.Data.UserID, false, ""
}
