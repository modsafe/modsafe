package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── 节点拓扑（默认 180+193 集群形态；data/nodes.json 可覆盖）──

type NodeConfig struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`        // local | agent
	StatusFile string `json:"status_file"` // local: status v3 文件
	MgmtSocket string `json:"mgmt_socket"` // local: management unix socket
	Oa2Unit    string `json:"oa2_unit"`    // local: 踢线窗口需临时停启的 oa2 服务
	AgentURL   string `json:"agent_url"`   // agent: node-agent 基址
	TokenFile  string `json:"token_file"`  // agent: admin-token 文件
}

var defaultNodes = []NodeConfig{
	{Name: "node-1", Kind: "local",
		StatusFile: envOr("MODSAFE_STATUS_LOG1", "/var/log/status-node1.log"),
		MgmtSocket: envOr("MODSAFE_MGMT_SOCK1", "/run/openvpn-modsafe/mgmt-1.sock"),
		Oa2Unit:    "oa2-modsafe@1"},
	{Name: "node-2", Kind: "agent",
		AgentURL:  envOr("NODE_AGENT_193", ""),
		TokenFile: envOr("MODSAFE_ADMIN_TOKEN_FILE", "/opt/modsafe/admin-token")},
}

var (
	nodes       []NodeConfig
	kickMutex   sync.Mutex // 全局踢线窗口互斥（management 单客户端，窗口必须串行）
)

func loadNodes(dataDir string) {
	nodes = defaultNodes
	path := dataDir + "/nodes.json"
	if b, err := os.ReadFile(path); err == nil {
		var custom []NodeConfig
		if json.Unmarshal(b, &custom) == nil && len(custom) > 0 {
			nodes = custom
		}
	}
}

func findNode(name string) *NodeConfig {
	for i := range nodes {
		if nodes[i].Name == name {
			return &nodes[i]
		}
	}
	return nil
}

// ── status v3 文件解析（文件为 TAB 分隔；此 OpenVPN 构建无 CID 列）──

// parseStatusFileChecked：读 status 文件解析；读失败返回 (nil, false) 供上层沿用缓存
func parseStatusFileChecked(path string) ([]map[string]interface{}, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return parseStatusBytes(b), true
}

// parseStatusFile：兼容旧调用（读失败返回空表）
func parseStatusFile(path string) []map[string]interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		return []map[string]interface{}{}
	}
	return parseStatusBytes(b)
}

// stripAddrProto：DCO（ovpn 内核模块）启用后 status v3 的 "Real Address" 带
// 协议前缀（udp4:1.2.3.4:5678），无 DCO 时为裸 IP:port——统一在解析层剥离，
// 台账/导出/展示全部回到裸地址（2026-10-08，会话导出 udp4: 泄漏修复）
func stripAddrProto(addr string) string {
	if i := strings.Index(addr, ":"); i > 0 {
		switch addr[:i] {
		case "udp4", "udp6", "tcp4", "tcp6":
			return addr[i+1:]
		}
	}
	return addr
}

func parseStatusBytes(b []byte) []map[string]interface{} {
	var cols []string
	out := []map[string]interface{}{}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(p) >= 3 && p[0] == "HEADER" && p[1] == "CLIENT_LIST" {
			cols = p[2:]
			continue
		}
		if len(p) > 1 && p[0] == "CLIENT_LIST" {
			row := map[string]string{}
			for i, c := range cols {
				if i+1 < len(p) {
					row[c] = p[i+1]
				}
			}
			out = append(out, map[string]interface{}{
				"username":      row["Username"],
				"common_name":   row["Common Name"],
				"virtual_ip":    row["Virtual Address"],
				"trusted_ip":    stripAddrProto(row["Real Address"]),
				"connected_at":  row["Connected Since"],
				"bytes_in":      atoi64(row["Bytes Received"]),
				"bytes_out":     atoi64(row["Bytes Sent"]),
				"node":          "",
			})
		}
	}
	return out
}

func atoi64(s string) int64 {
	s = strings.TrimSpace(s)
	n := int64(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// ── agent HTTP 客户端 ──

func agentRequest(node NodeConfig, method, path string, body map[string]interface{}) (map[string]interface{}, error) {
	token := ""
	if b, err := os.ReadFile(node.TokenFile); err == nil {
		token = strings.TrimSpace(string(b))
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(method, strings.TrimRight(node.AgentURL, "/")+path, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", token)
	// 认证关键路径（auth-check 会经 liveSessions/CCD 推送）也走本客户端：
	// 10s 超时代替 30s，agent 假死时不再把新用户认证拖住近 1 分钟
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent %s: HTTP %d", path, resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
