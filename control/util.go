package main

import (
	time2 "time"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// ── context claims ──

type ctxKey string

const claimsKey ctxKey = "claims"
const portalClaimsKey ctxKey = "portal_claims"

func withClaims(r *http.Request, c *adminClaims) context.Context {
	return context.WithValue(r.Context(), claimsKey, c)
}

func claimsOf(r *http.Request) *adminClaims {
	c, _ := r.Context().Value(claimsKey).(*adminClaims)
	return c
}

func withPortalClaims(r *http.Request, c *portalClaims) context.Context {
	return context.WithValue(r.Context(), portalClaimsKey, c)
}

func portalClaimsOf(r *http.Request) *portalClaims {
	c, _ := r.Context().Value(portalClaimsKey).(*portalClaims)
	return c
}

// ── 解码工具 ──

func jsonDecode(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func jsonDecodeStringSlice(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func remoteIP(r *http.Request) string {
	// #110：nginx 反代后直取 RemoteAddr 会把所有客户端归到 127.0.0.1——
	// 登录限速（30005）变成全局共享桶，可被用来锁死全体管理员（DoS 面）。
	// 优先级：X-Real-IP（nginx 显式覆盖，客户端伪造无效）→ X-Forwarded-For 首跳
	//（#124：多级代理/第三方反代形态下可能只有 XFF——内网部署场景可信）→ RemoteAddr。
	if x := r.Header.Get("X-Real-IP"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func normalizeKeyword(s string) string {
	return strings.TrimSpace(s)
}

// timeUntil：目标时间距现在的时长（用于证书到期计算）
func timeUntil(t time2.Time) time2.Duration { return time2.Until(t) }
