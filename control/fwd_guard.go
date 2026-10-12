package main

// 服务端路由强制（§最小权限，2026-09-30）：CCD 不推路由只是客户端便利性，
// 用户本地加静态路由（route add ... 10.8.0.1）包仍会进隧道被内核转发——
// 必须在服务端 FORWARD 链做目的白名单：仅放行"已授权网段并集"，其余丢弃。
// 授权并集 = 启用的 route 规则 ∪ 组绑定资源 CIDR ∪ DNS(53)；
// 全局层 redirect_gateway=true 时全放行（尊重显式的全局隧道配置）。

import (
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

// fwdMu：串行化本机链编程（并发 apply 曾把 iptables -F/-A 交错成重复条目，2026-10-02）
var fwdMu sync.Mutex

type fwdSpec struct {
	CIDRs    []string `json:"cidrs"`    // 授权目的网段
	DNS      []string `json:"dns"`      // 授权 DNS（仅 53 端口放行）
	AllowAll bool     `json:"allow_all"` // 全局隧道显式开启时 true
}

func iptRun(args ...string) (string, error) {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	return string(out), err
}

func ip6tRun(args ...string) (string, error) {
	out, err := exec.Command("ip6tables", args...).CombinedOutput()
	return string(out), err
}

// v6 VPN 客户端源段（node-1 fdaa:2026:192:0::/64 ∪ node-2 fdaa:2026:192:2::/64 聚合）
const vpnSourceV6 = "fdaa:2026:192::/48"

// applyForwardGuard：本机 iptables/ip6tables 编程 MODSAFE-FWD(6) 链（幂等，可重复调用）。
// v4 网段走 iptables；含冒号的 v6 网段走 ip6tables（2026-10-02 IPv6 支持——
// 此前 v6 授权网段喂给 iptables -d 会报错被跳过=有授权无强制）。
func applyForwardGuard(spec fwdSpec) error {
	fwdMu.Lock()
	defer fwdMu.Unlock()
	// 确保链存在
	if _, err := iptRun("-N", "MODSAFE-FWD"); err != nil && !strings.Contains(err.Error(), "already exists") {
		// 已存在时继续
	}
	_, _ = iptRun("-F", "MODSAFE-FWD")
	if _, err := ip6tRun("-N", "MODSAFE-FWD6"); err != nil && !strings.Contains(err.Error(), "already exists") {
		// 已存在时继续
	}
	_, _ = ip6tRun("-F", "MODSAFE-FWD6")

	v6Count := 0
	if spec.AllowAll {
		_, _ = iptRun("-A", "MODSAFE-FWD", "-j", "ACCEPT")
		_, _ = ip6tRun("-A", "MODSAFE-FWD6", "-j", "ACCEPT")
	} else {
		// 客户端互访默认禁止（conf 未开 client-to-client，双保险）
		_, _ = iptRun("-A", "MODSAFE-FWD", "-d", "10.8.0.0/16", "-j", "DROP")
		_, _ = ip6tRun("-A", "MODSAFE-FWD6", "-d", vpnSourceV6, "-j", "DROP")
		for _, cidr := range spec.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				continue
			}
			if strings.Contains(cidr, ":") {
				if _, err := ip6tRun("-A", "MODSAFE-FWD6", "-d", cidr, "-j", "ACCEPT"); err == nil {
					v6Count++
				}
				continue
			}
			_, _ = iptRun("-A", "MODSAFE-FWD", "-d", cidr, "-j", "ACCEPT")
		}
		for _, dns := range spec.DNS {
			ip := net.ParseIP(dns)
			if ip == nil {
				continue
			}
			tgt := iptRun
			if ip.To4() == nil {
				tgt = ip6tRun
			}
			_, _ = tgt("-A", fwdChainName(ip.To4() == nil), "-d", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
			_, _ = tgt("-A", fwdChainName(ip.To4() == nil), "-d", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
		}
		_, _ = iptRun("-A", "MODSAFE-FWD", "-j", "DROP")
		_, _ = ip6tRun("-A", "MODSAFE-FWD6", "-j", "DROP")
	}

	// 挂接 FORWARD：仅 VPN 源网段进本链（插到最前，先于 Docker 链；非 VPN 源不受影响）
	if _, err := iptRun("-C", "FORWARD", "-s", "10.8.0.0/16", "-j", "MODSAFE-FWD"); err != nil {
		if _, err := iptRun("-I", "FORWARD", "1", "-s", "10.8.0.0/16", "-j", "MODSAFE-FWD"); err != nil {
			return err
		}
	}
	if _, err := ip6tRun("-C", "FORWARD", "-s", vpnSourceV6, "-j", "MODSAFE-FWD6"); err != nil {
		if _, err := ip6tRun("-I", "FORWARD", "1", "-s", vpnSourceV6, "-j", "MODSAFE-FWD6"); err != nil {
			log.Printf("[fwd-guard] v6 FORWARD 挂接失败（内核/模块可能未就绪）: %v", err)
		}
	}
	log.Printf("[fwd-guard] 已应用：授权网段 %d 个（v6 %d）/ DNS %d 个 / allow_all=%v",
		len(spec.CIDRs), v6Count, len(spec.DNS), spec.AllowAll)
	return nil
}

// fwdChainName：DNS 条目按目标地址族选链
func fwdChainName(v6 bool) string {
	if v6 {
		return "MODSAFE-FWD6"
	}
	return "MODSAFE-FWD"
}

// computeForwardSpec：从规则/资源计算授权并集
func (a *App) computeForwardSpec() fwdSpec {
	spec := fwdSpec{CIDRs: []string{}, DNS: []string{}}
	seen := map[string]bool{}
	rows, err := a.db.Query(`SELECT DISTINCT value FROM ccd_rules WHERE enabled=1 AND type='route'`)
	if err == nil {
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil && !seen[v] {
				seen[v] = true
				spec.CIDRs = append(spec.CIDRs, v)
			}
		}
		rows.Close()
	}
	rows, err = a.db.Query(`SELECT DISTINCT r.cidr FROM group_resources gr JOIN resources r ON r.id=gr.resource_id`)
	if err == nil {
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil && !seen[v] {
				seen[v] = true
				spec.CIDRs = append(spec.CIDRs, v)
			}
		}
		rows.Close()
	}
	rows, err = a.db.Query(`SELECT DISTINCT value FROM ccd_rules WHERE enabled=1 AND type='dns'`)
	if err == nil {
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil && !seen[v] {
				seen[v] = true
				spec.DNS = append(spec.DNS, v)
			}
		}
		rows.Close()
	}
	// 全局层显式 redirect_gateway=true → 全放行
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM ccd_rules WHERE enabled=1 AND type='redirect_gateway'
		AND value='true' AND group_id IS NULL AND user_id IS NULL`).Scan(&n)
	spec.AllowAll = n > 0
	return spec
}

// syncForwardGuard：本机应用 + 推送 agent 节点
func (a *App) syncForwardGuard() {
	spec := a.computeForwardSpec()
	if err := applyForwardGuard(spec); err != nil {
		log.Printf("[fwd-guard] 本机应用失败: %v", err)
	}
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		if _, err := agentRequest(nodes[i], "POST", "/fwd-rules", map[string]interface{}{
			"cidrs":     spec.CIDRs,
			"dns":       spec.DNS,
			"allow_all": spec.AllowAll,
		}); err != nil {
			log.Printf("[fwd-guard] agent 下发失败: %v", err)
		}
	}
}

// handleFwdRulesStatus：GET /api/v1/monitor/fwd-guard（管理台可见当前服务端强制策略）
func (a *App) handleFwdRulesStatus(w http.ResponseWriter, r *http.Request) {
	spec := a.computeForwardSpec()
	writeOK(w, r, map[string]interface{}{
		"cidrs": spec.CIDRs, "dns": spec.DNS, "allow_all": spec.AllowAll,
		"mode": map[bool]string{true: "全局放行（全局隧道已启用）", false: "白名单（最小权限）"}[spec.AllowAll],
	})
}

// applyForwardFromAgentBody：agent /fwd-rules 入参 → 本机应用（healthz 调用）
func applyForwardFromAgentBody(cidrs, dns []string, allowAll bool) error {
	return applyForwardGuard(fwdSpec{CIDRs: cidrs, DNS: dns, AllowAll: allowAll})
}
