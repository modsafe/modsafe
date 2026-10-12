package main

// IPv6 隧道开关（#80，用户要求"未开启则不使用 IPv6"）：
// off（默认）＝隧道仅 IPv4（conf 无 server-ipv6 行，客户端不分配 v6 地址）；
// on ＝双节点 conf 追加 server-ipv6（node-1 fdaa:2026:192:0::/64 / node-2 …:2::/64），
// 客户端重连后同时获得 v6 隧道地址。切换需重启节点（在线会话中断后自动重连，打断性操作）。
// 服务端 v6 强制（MODSAFE-FWD6）与 dnsmasq 常驻不变——off 时无 v6 客户端流量，链闲置无副作用。

import (
	"net/http"
	"os"
	"strings"
)

// node-1 conf 支持 MODSAFE_NODE1_CONF 覆盖（安装器 v2 归一布局）
var (
	nodeConfPathV6   = envOr("MODSAFE_NODE1_CONF", "/etc/openvpn/instances/node-1.conf")
	node1V6Net       = "fdaa:2026:192:0::/64"
	node2V6Net       = "fdaa:2026:192:2::/64"
	ipv6UnitLocal    = "openvpn-modsafe@1"
	ipv6TunnelSource = "10.8.0.0/16"
)

func ipv6Enabled(a *App) bool {
	return getSetting(a, "ipv6_tunnel", "0") == "1"
}

// renderServerIPv6：conf 增删 server-ipv6 行（幂等）；返回新内容与是否发生变化
func renderServerIPv6(content string, enable bool, v6net string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+1)
	changed := false
	for _, l := range lines {
		if strings.HasPrefix(l, "server-ipv6 ") {
			changed = true // 移除既有行
			continue
		}
		out = append(out, l)
	}
	if enable {
		out = append(out, "server-ipv6 "+v6net)
		changed = true
	}
	if !changed {
		return strings.Join(out, "\n"), false
	}
	return strings.Join(out, "\n"), true
}

// applyIPv6Local：node-1 conf 增删 server-ipv6 + 重启（oa2 经 PartOf 联动）
func applyIPv6Local(enable bool, v6net string) error {
	raw, err := os.ReadFile(nodeConfPathV6)
	if err != nil {
		return err
	}
	newContent, changed := renderServerIPv6(string(raw), enable, v6net)
	if !changed {
		return nil
	}
	tmp := nodeConfPathV6 + ".tmp"
	if err := os.WriteFile(tmp, []byte(newContent), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, nodeConfPathV6); err != nil {
		return err
	}
	systemctlRestart(ipv6UnitLocal)
	return nil
}

// handleIPv6Get：GET /api/v1/settings/ipv6
func (a *App) handleIPv6Get(w http.ResponseWriter, r *http.Request) {
	enabled := ipv6Enabled(a)
	label := "关闭（隧道仅 IPv4，客户端不分配 IPv6 地址）"
	if enabled {
		label = "开启（客户端重连后同时获得 IPv6 隧道地址 fdaa:2026:192::/48 段）"
	}
	writeOK(w, r, map[string]interface{}{
		"enabled": enabled, "label": label,
		"nodes": []string{"node-1@180", "node-2@193"},
	})
}

// handleIPv6Put：PUT /api/v1/settings/ipv6 {enabled, confirm_impact}
func (a *App) handleIPv6Put(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled       bool `json:"enabled"`
		ConfirmImpact bool `json:"confirm_impact"`
	}
	if err := jsonDecode(r, &req); err != nil || !req.ConfirmImpact {
		failParam(w, r, "需 confirm_impact 确认打断性影响")
		return
	}

	// 先远端（193）后本机，与加密套件/证书绑定切换同序
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		if _, err := agentRequest(nodes[i], "POST", "/ipv6", map[string]interface{}{
			"enable": req.Enabled, "v6net": node2V6Net,
		}); err != nil {
			failSystem(w, r, "node-2 IPv6 下发失败："+err.Error())
			return
		}
	}
	if err := applyIPv6Local(req.Enabled, node1V6Net); err != nil {
		failSystem(w, r, "node-1 IPv6 应用失败："+err.Error())
		return
	}
	setSetting(a, "ipv6_tunnel", map[bool]string{true: "1", false: "0"}[req.Enabled])
	notice := "IPv6 隧道已关闭：客户端仅使用 IPv4。"
	if req.Enabled {
		notice = "IPv6 隧道已开启：客户端重连后将同时获得 IPv6 地址（fdaa:2026:192::/48 段，仅可访问已授权的 v6 资源）。"
	}
	writeOK(w, r, map[string]interface{}{
		"enabled": req.Enabled,
		"notice":  notice + "双节点已重启，在线会话自动重连。",
	})
}
