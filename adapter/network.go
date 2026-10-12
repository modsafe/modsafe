package main

// 网段管理（后台可配，默认 10.8.0.0/16 按节点 /23 切分）：
// 本机 node 配置改写 + NAT + 服务重启；node-2 经 193 agent 下发。
// 执行安全：每条命令字面量首参（iptables/iptables-save/systemctl）、
// 全部参数经 safeArg 字符校验、无 shell 无拼接。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func safeArg(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		switch ch {
		case ';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', '\'', '"', '\\':
			return false
		}
		if ch < 32 {
			return false
		}
	}
	return true
}

func runIptables(args []string) (string, error) {
	for _, a := range args {
		if !safeArg(a) {
			return "", fmt.Errorf("unsafe arg %q", a)
		}
	}
	cmd := exec.Command("iptables", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func runIptablesSave() (string, error) {
	cmd := exec.Command("iptables-save")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func runSystemctlRestartUnit(unit string) error {
	if !safeArg(unit) {
		return fmt.Errorf("unsafe unit %q", unit)
	}
	cmd := exec.Command("systemctl", "restart", unit)
	return cmd.Run()
}

// flushStaleMasquerade：删除旧的 10.8.x MASQUERADE 规则（iptables -S 解析 → 逐条 -D）
func flushStaleMasquerade() {
	listing, err := runIptables([]string{"-t", "nat", "-S", "POSTROUTING"})
	if err != nil {
		return
	}
	for _, rule := range strings.Split(listing, "\n") {
		toks := strings.Fields(rule)
		if len(toks) > 1 && toks[0] == "-A" && strings.Contains(rule, "10.8.") &&
			strings.Contains(rule, "MASQUERADE") {
			_, _ = runIptables(append([]string{"-t", "nat", "-D"}, toks[1:]...))
		}
	}
}

func applyLocalNode(block, nodeNum string) error {
	var conf string
	switch nodeNum {
	case "1":
		conf = envPath("MODSAFE_NODE1_CONF", "/etc/openvpn/instances/node-1.conf")
	case "2":
		conf = envPath("MODSAFE_NODE2_CONF", "/etc/openvpn/instances/node-2.conf")
	default:
		return errors.New("node_num 仅允许 1/2")
	}
	prefix, err := netip.ParsePrefix(block)
	if err != nil {
		return fmt.Errorf("invalid cidr: %v", err)
	}
	prefix = prefix.Masked()
	// 写入路径防穿越：realpath 后必须仍在实例目录内（目录取自 conf 本身，兼容任意布局）
	instDir := filepath.Dir(conf) + string(filepath.Separator)
	confReal, err := filepath.EvalSymlinks(conf)
	if err != nil {
		confReal = filepath.Clean(conf)
	}
	if !strings.HasPrefix(confReal, instDir) || strings.Contains(conf, "..") {
		return errors.New("非法配置路径")
	}
	raw, err := os.ReadFile(confReal)
	if err != nil {
		return err
	}
	srvLine := fmt.Sprintf("server %s %s", prefix.Addr().String(),
		net.IP(net.CIDRMask(prefix.Bits(), 32)).String())
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "server ") {
			out = append(out, srvLine)
		} else {
			out = append(out, line)
		}
	}
	if err := os.WriteFile(confReal, []byte(strings.Join(out, "\n")), 0o644); err != nil {
		return err
	}
	// NAT: 删旧 10.8.x MASQUERADE，加新（出口网卡经 MODSAFE_NAT_IFACE 可配，缺省=ens18）。
	// 关键步骤失败必须上抛：静默吞错会导致新网段无 MASQUERADE/服务未重启，管理台却显示 ok
	flushStaleMasquerade()
	if _, err := runIptables([]string{"-t", "nat", "-A", "POSTROUTING", "-s", prefix.String(),
		"-o", NAT_IFACE, "-j", "MASQUERADE"}); err != nil {
		logf("iptables MASQUERADE FAILED (node %s %s via %s): %v", nodeNum, prefix.String(), NAT_IFACE, err)
		return fmt.Errorf("iptables NAT 添加失败: %v", err)
	}
	saved, err := runIptablesSave()
	if err != nil {
		logf("iptables-save FAILED (node %s): %v", nodeNum, err)
		return fmt.Errorf("iptables-save 失败: %v", err)
	}
	if err := os.WriteFile(envPath("MODSAFE_IPTABLES_SAVE", "/etc/sysconfig/iptables-modsafe"),
		[]byte(saved), 0o644); err != nil {
		logf("iptables rules persist FAILED (node %s): %v", nodeNum, err)
		return fmt.Errorf("iptables 规则落盘失败: %v", err)
	}
	if err := runSystemctlRestartUnit("openvpn-modsafe@" + nodeNum); err != nil {
		logf("openvpn-modsafe@%s restart FAILED: %v", nodeNum, err)
		return fmt.Errorf("openvpn-modsafe@%s 重启失败: %v", nodeNum, err)
	}
	return nil
}

func applyNetwork(baseCIDR string, nodePrefix int) (map[string]any, map[string]any, error) {
	pool, err := netip.ParsePrefix(baseCIDR)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cidr: %v", err)
	}
	pool = pool.Masked()
	maxBits := 32
	if pool.Addr().Is6() {
		maxBits = 128
	}
	if nodePrefix < pool.Bits() || nodePrefix > maxBits {
		return nil, nil, errors.New("invalid node_prefix")
	}
	b1 := pool
	shift := uint(maxBits) - uint(nodePrefix)
	var b2 netip.Prefix
	if pool.Addr().Is4() {
		a4 := pool.Addr().As4()
		v := binary.BigEndian.Uint32(a4[:])
		v += uint32(1) << shift
		b2 = netip.PrefixFrom(netip.AddrFrom4(uint32To4(v)), nodePrefix)
	} else {
		b := pool.Addr().As16()
		addUint64To16(b[:], uint64(1)<<shift)
		b2 = netip.PrefixFrom(netip.AddrFrom16(b), nodePrefix)
	}
	cfg := map[string]any{
		"base_cidr": pool.String(), "node_prefix": nodePrefix,
		"blocks": map[string]any{"1": b1.String(), "2": b2.String()},
	}
	saveNetwork(cfg)
	if err := applyLocalNode(b1.String(), "1"); err != nil {
		return nil, nil, err
	}
	// 远端 node-2（193 agent）：不可达/失败必须上抛——node-2 网段未生效却报 ok
	// 会导致管理台静默半配置（本机 node-1 已生效，修复 agent 后重试即幂等补齐）
	if NODE_AGENT_193 == "" {
		return cfg, map[string]any{"error": "NODE_AGENT_193 未配置"},
			errors.New("未配置 NODE_AGENT_193，node-2 网段无法下发（单机部署请关闭双节点网段功能）")
	}
	j, _ := jsonMarshal(map[string]any{"token": readAdminToken(), "cidr_block": b2.String()})
	var remote map[string]any
	req, err := http.NewRequest("POST", NODE_AGENT_193+"/apply/network", bytes.NewReader(j))
	if err != nil {
		logf("node-2 agent request build FAILED: %v", err)
		return cfg, map[string]any{"error": "node agent unreachable"},
			errors.New("node-2 agent 不可达，node-2 网段未生效（node-1 已生效，恢复后可重试）")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logf("node-2 agent request FAILED: %v", err)
		return cfg, map[string]any{"error": "node agent unreachable"},
			errors.New("node-2 agent 不可达，node-2 网段未生效（node-1 已生效，恢复后可重试）")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := jsonUnmarshal(raw, &remote); err != nil {
		remote = map[string]any{"error": "bad response"}
	}
	if e := mStr(remote, "error"); e != "" {
		logf("node-2 agent apply FAILED: %s", e)
		return cfg, remote, fmt.Errorf("node-2 agent 应用失败: %s", e)
	}
	return cfg, remote, nil
}

func uint32To4(v uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b
}

func addUint64To16(b []byte, n uint64) {
	for i := 15; i >= 0 && n > 0; i-- {
		s := uint64(b[i]) + (n & 0xff)
		b[i] = byte(s & 0xff)
		n = n>>8 + s>>8
	}
}
