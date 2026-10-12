package main

// agent 角色的状态解析与 management 受控窗口（healthz.py/node-agent v4 移植）。
// 纯函数（parseStatus3/stripProto/sessionLineRe 等）与副作用操作分离，便于单测。

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nodeService = "openvpn-modsafe@2"
	oa2Service  = "oa2-modsafe@2"
	mgmtSock    = "/run/openvpn-modsafe/mgmt-2.sock"
	extIface    = "ens18"
)

// 测试可覆盖的路径（生产值；安装器 v2 经 modsafe.env 注入归一布局）
var (
	agentTokenFile = envPath("MODSAFE_ADMIN_TOKEN", "/opt/modsafe/admin-token")
	nodeConf       = envPath("MODSAFE_NODE2_CONF", "/etc/openvpn/instances/node-2.conf")
	nodeStatusLog  = envPath("MODSAFE_STATUS_LOG2", "/var/log/status-node2.log")
	ccdDir         = envPath("MODSAFE_CCD_OUT", "/etc/openvpn-auth-oauth2/client-config")
	pkiDir         = envPath("MODSAFE_PKI_DIR", "/root/modsafe-pki2")
	iptablesSaveF  = envPath("MODSAFE_IPTABLES_SAVE", "/etc/sysconfig/iptables-modsafe")
	clusterDir     = envPath("MODSAFE_CLUSTER_DIR", "/opt/modsafe/cluster")
	dnsmasqLog     = envPath("MODSAFE_DNSMASQ_LOG", "/var/log/dnsmasq-queries.log")
)

func readToken() string {
	b, err := os.ReadFile(agentTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// stripProto：DCO 下 status v3 Real Address 带 udp4:/udp6: 前缀——统一剥离为裸 IP:port
func stripProto(addr string) string {
	if i := strings.Index(addr, ":"); i >= 0 {
		head := addr[:i]
		switch head {
		case "udp4", "udp6", "tcp4", "tcp6":
			return addr[i+1:]
		}
	}
	return addr
}

// parseStatus3Text：HEADER 行驱动列映射，返回 CLIENT_LIST 全量行（map 列名→值）
func parseStatus3Text(txt string) []map[string]string {
	var rows []map[string]string
	var cols []string
	for _, line := range strings.Split(txt, "\n") {
		p := strings.Split(line, "\t")
		if len(p) >= 3 && p[0] == "HEADER" && p[1] == "CLIENT_LIST" {
			cols = p[2:]
		} else if len(p) > 1 && p[0] == "CLIENT_LIST" {
			row := map[string]string{}
			for i, c := range cols {
				if i+1 < len(p) {
					row[c] = p[i+1]
				}
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// statusSummary：/metrics 与 /sessions 共用的 status 文件解析
func statusSummary() map[string]any {
	out := map[string]any{"online": 0, "bytes_rx": 0, "bytes_tx": 0,
		"clients": []any{}, "sessions": []any{}}
	b, err := os.ReadFile(nodeStatusLog)
	if err != nil {
		return out
	}
	online, rx, tx := 0, 0, 0
	clients := []any{}
	sessions := []any{}
	for _, row := range parseStatus3Text(string(b)) {
		online++
		brx, _ := strconv.Atoi(orZero(row["Bytes Received"]))
		btx, _ := strconv.Atoi(orZero(row["Bytes Sent"]))
		rx += brx
		tx += btx
		real := stripProto(orZero(row["Real Address"]))
		clients = append(clients, map[string]any{
			"real": real, "vip": orZero(row["Virtual Address"]),
			"bytes_rx": brx, "bytes_sent": btx})
		sessions = append(sessions, map[string]any{
			// 修正：Python 原版取 row["CID"]，但 HEADER 列名为 "Client ID"——原版 cid 恒为空；
			// Go 版读正确列名（兼容 CID 别名），/kick 的 mgmt 路径本就自取 Client ID 不受影响
			"cid":             firstNonEmpty(row["Client ID"], row["CID"]),
			"common_name":     orZero(row["Common Name"]),
			"real_address":    real,
			"virtual_address": orZero(row["Virtual Address"]),
			"bytes_received":  brx,
			"bytes_sent":      btx,
			"connected_since": orZero(row["Connected Since"]),
			"username":        orZero(row["Username"]),
		})
	}
	out["online"] = online
	out["bytes_rx"] = rx
	out["bytes_tx"] = tx
	out["clients"] = clients
	out["sessions"] = sessions
	return out
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// ---- 受控 management 窗口：停 oa2 释放槽位 → 连接执行 op → 回启 oa2 ----

// 槽位全局仅一个：net/http 并发 handler 下（如两个 /kick 交错）不加锁会出现
// A 的回启与 B 的停止互相踩踏、B 窗口中途失效；窗口标志供 SIGTERM 兜底回启 oa2
var (
	mgmtMu      sync.Mutex
	mgmtWinOpen atomic.Bool
)

func mgmtConnect() (net.Conn, error) {
	var s net.Conn
	for i := 0; i < 50; i++ { // 最多等 5s 抢槽位
		c, err := net.DialTimeout("unix", mgmtSock, 4*time.Second)
		if err == nil {
			s = c
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return s, nil
}

func mgmtWindow(op func(net.Conn) map[string]any) map[string]any {
	mgmtMu.Lock()
	defer mgmtMu.Unlock()
	mgmtWinOpen.Store(true)
	defer mgmtWinOpen.Store(false)
	_ = svcStop(oa2Service)
	s, err := mgmtConnect()
	if err != nil || s == nil {
		_ = svcStart(oa2Service)
		time.Sleep(300 * time.Millisecond)
		return map[string]any{"ok": false, "error": "management 槽位未获取"}
	}
	defer func() {
		s.Close()
		_ = svcStart(oa2Service)
		time.Sleep(300 * time.Millisecond)
	}()
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	_, _ = s.Read(buf) // banner（best effort）
	_ = s.SetReadDeadline(time.Time{})
	return op(s)
}

// mgmtReadStatus：management status 3（TAB 分隔；CID 列名为 Client ID；终止按独立行 END）
func mgmtReadStatus(s net.Conn) []map[string]string {
	_, _ = s.Write([]byte("status 3\n"))
	var buf []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = s.SetReadDeadline(time.Now().Add(time.Second))
		chunk := make([]byte, 65536)
		n, err := s.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil && n == 0 {
			break
		}
		ended := false
		for _, ln := range strings.Split(string(buf), "\n") {
			if strings.TrimSpace(ln) == "END" {
				ended = true
				break
			}
		}
		if ended {
			break
		}
	}
	var rows []map[string]string
	var cols []string
	for _, line := range strings.Split(string(buf), "\n") {
		if strings.TrimSpace(line) == "END" {
			break
		}
		p := strings.Split(line, "\t")
		if len(p) >= 3 && p[0] == "HEADER" && p[1] == "CLIENT_LIST" {
			cols = p[2:]
		} else if len(p) > 1 && p[0] == "CLIENT_LIST" {
			row := map[string]string{}
			for i, c := range cols {
				if i+1 < len(p) {
					row[c] = p[i+1]
				}
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// mgmtKill：窗口内解析 status 3 取 Client ID，按用户名/证书名/虚拟 IP 匹配后逐个 client-kill
func mgmtKill(username, commonName, virtualIP string, killAll bool) map[string]any {
	result := map[string]any{"ok": false, "killed": []any{}, "errors": []any{}}
	op := func(s net.Conn) map[string]any {
		rows := mgmtReadStatus(s)
		var targets []map[string]string
		for _, r := range rows {
			if killAll ||
				(virtualIP != "" && r["Virtual Address"] == virtualIP) ||
				(username != "" && (r["Username"] == username || r["Common Name"] == username)) ||
				(commonName != "" && r["Common Name"] == commonName) {
				targets = append(targets, r)
			}
		}
		if len(targets) == 0 {
			appendErr(result, "未找到匹配会话")
			return result
		}
		for _, r := range targets {
			cid := r["Client ID"]
			if cid == "" {
				continue
			}
			_, _ = s.Write([]byte(fmt.Sprintf("client-kill %s\n", cid)))
			var resp []byte
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				_ = s.SetReadDeadline(time.Now().Add(time.Second))
				chunk := make([]byte, 4096)
				n, err := s.Read(chunk)
				if n > 0 {
					resp = append(resp, chunk[:n]...)
				}
				if err != nil && n == 0 {
					break
				}
				if strings.Contains(string(resp), "SUCCESS") || strings.Contains(string(resp), "ERROR") {
					break
				}
			}
			text := strings.TrimSpace(string(resp))
			if strings.Contains(text, "SUCCESS") {
				appendKilled(result, map[string]any{"cid": cid, "username": r["Username"],
					"response": truncateStr(text, 100)})
			} else {
				appendErr(result, fmt.Sprintf("cid=%s: %s", cid, truncateStr(text, 100)))
			}
		}
		return result
	}
	out := mgmtWindow(op)
	if out != nil && mStr(out, "error") != "" {
		appendErr(result, mStr(out, "error"))
	}
	killed, _ := result["killed"].([]any)
	result["ok"] = len(killed) > 0
	return result
}

func appendKilled(result map[string]any, v any) {
	k, _ := result["killed"].([]any)
	result["killed"] = append(k, v)
}

func appendErr(result map[string]any, msg string) {
	e, _ := result["errors"].([]any)
	result["errors"] = append(e, msg)
}

// parseFlows：/proc/net/nf_conntrack → VPN 源活跃流（10.8/16 ∪ fdaa:2026:192::/48）
func parseFlows(text string) []map[string]any {
	out := []map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, " src=") {
			continue
		}
		isV6 := strings.HasPrefix(line, "ipv6")
		src, dst, proto := "", "", ""
		dport, total := 0, 0
		firstSrcDone := false
		fields := strings.Fields(line)
		for _, kv := range fields {
			switch {
			case strings.HasPrefix(kv, "src="):
				if !firstSrcDone {
					src = kv[4:]
					firstSrcDone = true
				}
			case strings.HasPrefix(kv, "dst=") && dst == "":
				dst = kv[4:]
			case strings.HasPrefix(kv, "dport=") && dport == 0:
				dport, _ = strconv.Atoi(kv[6:])
			case strings.HasPrefix(kv, "bytes="):
				if v, err := strconv.Atoi(kv[6:]); err == nil {
					total += v
				}
			case strings.HasPrefix(kv, "protocol=") && isV6:
				proto = kv[9:]
			}
		}
		if src == "" || dst == "" {
			continue
		}
		if !strings.HasPrefix(src, "10.8.") && !strings.HasPrefix(src, "fdaa:2026:192:") {
			continue
		}
		if proto == "" {
			proto = ""
			if len(fields) > 2 {
				proto = fields[2]
			}
		}
		out = append(out, map[string]any{"src": src, "dst": dst, "proto": proto,
			"port": dport, "bytes": total})
	}
	return out
}
