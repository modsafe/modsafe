// modsafe-adapter：多 IdP 网关（防腐层）Go 实现
// 替换原 Python 实现（/opt/modsafe/idp-adapter.py v2, 2468 行），HTTP 契约逐端点兼容：
// 端点路径 / JSON 字段 / cookie / 状态文件路径（idp-config.json、oidc-refresh.json、
// branding.json、ccd-rules.json、alert-channels.json、client-pool）全部保持一致，
// nginx / oa2 / modsafe-control 零改动，systemd 仅换 ExecStart，回滚即换回。
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------- 随机令牌（对齐 Python secrets.token_urlsafe） ----------

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// json 包装（避免到处重复 import encoding/json 的样板）
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func jsonNewEncoder(w io.Writer) *json.Encoder { return json.NewEncoder(w) }

// ---------- map 取值助手（IDPC/branding 等为 Python 风格 dict） ----------

func mStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%v", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

func mBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func mInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// ---------- JSON 文件助手（原子替换 + 权限，对齐 Python tmp/replace） ----------

func loadJSONFile(path string) (map[string]any, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false
	}
	return out, true
}

func saveJSONAtomic(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------- 环境变量 ----------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------- 客户端真实 IP（#124：X-Real-IP → XFF 首跳 → 直连） ----------

func clientIP(r *http.Request) string {
	for _, h := range []string{"X-Real-IP", "X-Forwarded-For"} {
		v := strings.TrimSpace(r.Header.Get(h))
		if v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- 请求体（64KiB 上限，对齐 Python _body） ----------

func readBody(r *http.Request) string {
	nStr := r.Header.Get("Content-Length")
	var n int
	if _, err := fmt.Sscanf(nStr, "%d", &n); err != nil || n <= 0 {
		return ""
	}
	if n > 65536 {
		r.Close = true
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(n)))
	if err != nil {
		return ""
	}
	return string(b)
}

func parseForm(body string) url.Values {
	v, _ := url.ParseQuery(body)
	return v
}

// ---------- 响应助手 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeJSONUTF8(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeHTML(w http.ResponseWriter, code int, s string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(s))
}

func esc(s string) string { return html.EscapeString(s) }

// redirectWith：302 跳转（CR/LF 清洗防响应拆分；可选带 Set-Cookie，对齐 _new_set_cookie）
func redirectWith(w http.ResponseWriter, location string, cookie *http.Cookie) {
	clean := strings.Map(func(ch rune) rune {
		if ch == '\r' || ch == '\n' {
			return -1
		}
		return ch
	}, location)
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	w.Header().Set("Location", clean)
	w.WriteHeader(302)
}

// ---------- cookie ----------

func cookieValue(cookieHeader, name string) string {
	for _, part := range strings.Split(cookieHeader, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		if k == name {
			return v
		}
	}
	return ""
}

// ---------- admin 令牌门禁（对齐 /admin/* X-Admin-Token 校验，fail-closed） ----------

func readAdminToken() string {
	b, err := os.ReadFile(ADMIN_TOKEN_PATH)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func adminAuthed(r *http.Request) bool {
	want := readAdminToken()
	if want == "" {
		return false
	}
	got := r.Header.Get("X-Admin-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ---------- 内部通道令牌（对齐 _cp_token：与 admin 同一共享令牌文件） ----------

// ---------- http_json 等价物 ----------

func httpJSON(target string, method string, headers map[string]string, body any, timeout time.Duration) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		switch b := body.(type) {
		case []byte:
			rdr = strings.NewReader(string(b))
		default:
			j, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			rdr = strings.NewReader(string(j))
		}
	}
	req, err := http.NewRequest(method, target, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "modsafe-idp-adapter")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		trimmed := string(raw)
		if len(trimmed) > 300 {
			trimmed = trimmed[:300]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trimmed)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- PKCE ----------

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64u(sum[:])
}

// ---------- 令牌路径助手（防路径拼接差异） ----------

func joinPath(dir, name string) string { return filepath.Join(dir, name) }

// hmacEqual：hmac.compare_digest 等价
func hmacEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
