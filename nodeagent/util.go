package main

// 共享基础设施：JSON 文件原子读写、map 取值、HTTP 客户端助手。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// envPath：路径环境变量覆盖（安装器 v2 经 modsafe.env 注入归一布局；缺省=历史路径）
func envPath(key, legacy string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return legacy
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// httpJSON：带方法/头/体的 JSON 调用（告警 webhook 用；URL 均为配置文件内的字面量目标，
// 且经 ssrfReject 边界校验）
func httpJSON(target string, method string, headers map[string]string, body any, timeout time.Duration) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = strings.NewReader(string(j))
	}
	req, err := http.NewRequest(method, target, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "modsafe-nodeagent")
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

func readBodyLimited(r *http.Request, max int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(r.Body, max+1))
	if int64(len(b)) > max {
		return nil
	}
	return b
}
