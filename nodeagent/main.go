// modsafe-nodeagent：运维面三件套 Go 实现（collector / watchdog / agent）
// 替换 monitor-collector.py（278 行）、ha-watchdog.py（161 行）、healthz.py/node-agent v4（591 行）。
// 端点/JSON/SQLite schema/文件路径逐条兼容；单二进制按子命令分角色：
//
//	collector → 180 modsafe-monitor.service   (:7505, SQLite monitor.db)
//	watchdog  → 双节点 ha-watchdog.service   (IPVS 健康权重 + 193 侧 180 宿主机守护)
//	agent     → 193 modsafe-healthz.service   (:7503, node-agent v4 全端点)
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: modsafe-nodeagent collector|watchdog|agent")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "collector":
		runCollector()
	case "watchdog":
		runWatchdog()
	case "agent":
		runAgent()
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", os.Args[1])
		os.Exit(2)
	}
}

// ---------- 共享小工具 ----------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func nowUnix() int64 { return time.Now().Unix() }

func logf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func ioReadAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := jsonMarshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

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

// httpGetJSON：字面量 URL 的集群内部探测（watchdog/collector 专用）
func httpGetJSON(target string, timeout time.Duration) (map[string]any, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := ioReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := jsonUnmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// httpGetStatus：只看状态码的探测
func httpGetStatus(target string, timeout time.Duration) (int, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = ioReadAll(resp.Body)
	return resp.StatusCode, nil
}

func mStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func mF64(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	f, _ := m[key].(float64)
	return f
}
