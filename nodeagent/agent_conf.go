package main

// agent 角色的 conf 推送与防火墙端点（/authtoken /crypto /cert-binding /crl
// /ipv6 /apply/network /fwd-rules /ccd）。conf 编辑为逐行纯函数（RE2 无 lookahead，
// 以"行前缀判断"替代 Python 的 (?!...) 断言），所有编辑先备份 .pre-*.bak 再原子写。

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func filepathRealpath(p string) (string, error) {
	return filepath.EvalSymlinks(p)
}

// ---- 逐行 conf 编辑纯函数 ----

// confReplaceAuthToken：auth-gen-token {n} external-auth 整行替换；返回 (新文本, 替换次数)
func confReplaceAuthToken(txt string, seconds int) (string, int) {
	oldPrefix := "auth-gen-token "
	newLine := fmt.Sprintf("auth-gen-token %d external-auth", seconds)
	out, n := "", 0
	for _, line := range strings.Split(txt, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, oldPrefix) && strings.HasSuffix(trimmed, " external-auth") {
			out += newLine + "\n"
			n++
		} else {
			out += line + "\n"
		}
	}
	out = strings.TrimSuffix(out, "\n")
	return out, n
}

// confSetDataCiphers：删除全部 data-ciphers 行，在第一条 auth 行（非 auth-gen-token/
// auth-token-secret，对应 Python 的 (?!...) 断言）后插入 data-ciphers 行；n=auth 行命中数
func confSetDataCiphers(txt, ciphers string) (string, int) {
	var kept, out []string
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "data-ciphers ") {
			continue
		}
		kept = append(kept, line)
	}
	n := 0
	for _, line := range kept {
		if n == 0 && strings.HasPrefix(line, "auth ") {
			rest := strings.TrimPrefix(line, "auth ")
			if strings.HasPrefix(rest, "gen-token") || strings.HasPrefix(rest, "token-secret") {
				out = append(out, line)
				continue
			}
			out = append(out, line, "data-ciphers "+ciphers)
			n++
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), n
}

// confSetCertBinding：删除全部 verify-client-cert/crl-verify 行，
// 在 management-client-auth 行后插入 ins（多行）；n=锚行命中数
func confSetCertBinding(txt, ins string) (string, int) {
	var kept []string
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "verify-client-cert ") || strings.HasPrefix(line, "crl-verify ") {
			continue
		}
		kept = append(kept, line)
	}
	var out []string
	n := 0
	for _, line := range kept {
		out = append(out, line)
		if n == 0 && strings.HasPrefix(line, "management-client-auth") {
			out = append(out, strings.Split(strings.TrimRight(ins, "\n"), "\n")...)
			n++
		}
	}
	return strings.Join(out, "\n"), n
}

// confSetServerIPv6：删除全部 server-ipv6 行；enable 时追加 v6net；返回 (新文本, 是否有变化)
func confSetServerIPv6(txt string, enable bool, v6net string) (string, bool) {
	var kept []string
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "server-ipv6 ") {
			continue
		}
		kept = append(kept, line)
	}
	joined := strings.Join(kept, "\n")
	if enable {
		joined = strings.TrimRight(joined, "\n") + "\nserver-ipv6 " + v6net + "\n"
	}
	return joined, joined != txt
}

// confReplaceServerLine：server 行改写为 addr/mask（apply/network 与 crypto 前置校验用）
func confReplaceServerLine(txt, addr, mask string) (string, bool) {
	updated := false
	var out []string
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "server ") {
			out = append(out, "server "+addr+" "+mask)
			updated = true
		} else {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n"), updated
}

// ---- 文件助手 ----

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(src); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(dst, b, mode)
}

// confRealPathGuard：实例目录防穿越校验（目录取自 conf 本身，兼容任意布局）
func confRealPathGuard(conf string) (string, error) {
	real, err := filepathRealpath(conf)
	if err != nil {
		real = conf
	}
	instDir := filepath.Dir(conf) + string(filepath.Separator)
	if !strings.HasPrefix(real, instDir) || strings.Contains(conf, "..") {
		return "", fmt.Errorf("illegal conf path")
	}
	return real, nil
}

// ---- 下发端点实现（鉴权已在路由层完成） ----

func applyAuthToken(minutes int) (int, map[string]any) {
	if minutes < 60 || minutes > 10080 {
		return 400, map[string]any{"error": "minutes 须在 60~10080（保证会话内重协商兼容）"}
	}
	txt, err := os.ReadFile(nodeConf)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	newTxt, n := confReplaceAuthToken(string(txt), minutes*60)
	if n != 1 {
		return 500, map[string]any{"error": fmt.Sprintf("conf auth-gen-token 行未匹配 n=%d", n)}
	}
	_ = copyFile(nodeConf, nodeConf+".pre-token.bak")
	if err := os.WriteFile(nodeConf, []byte(newTxt), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	_, err = svcRestart(nodeService)
	if err != nil {
		return 500, map[string]any{"ok": false, "lifetime_seconds": minutes * 60,
			"restart": truncateStr(err.Error(), 200)}
	}
	return 200, map[string]any{"ok": true, "lifetime_seconds": minutes * 60, "restart": "done"}
}

func applyCrypto(ciphers, authAlg string) (int, map[string]any) {
	if ciphers == "" || authAlg == "" {
		return 400, map[string]any{"error": "ciphers/auth 必填"}
	}
	real, err := confRealPathGuard(nodeConf)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	txt, err := os.ReadFile(real)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	newTxt, n := confSetDataCiphers(string(txt), ciphers)
	if n != 1 {
		return 500, map[string]any{"error": fmt.Sprintf("conf auth 行未匹配 n=%d", n)}
	}
	_ = copyFile(real, real+".pre-crypto.bak")
	if err := os.WriteFile(real, []byte(newTxt), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	_, err = svcRestart(nodeService)
	if err != nil {
		return 500, map[string]any{"ok": false, "ciphers": ciphers, "auth": authAlg,
			"restart": truncateStr(err.Error(), 200)}
	}
	return 200, map[string]any{"ok": true, "ciphers": ciphers, "auth": authAlg, "restart": "done"}
}

func applyCertBinding(strict bool, crl string) (int, map[string]any) {
	real, err := confRealPathGuard(nodeConf)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	txt, err := os.ReadFile(real)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	ins := "verify-client-cert none"
	if strict {
		if crl == "" {
			return 400, map[string]any{"error": "strict 需要 crl"}
		}
		ins = "verify-client-cert require\ncrl-verify " + pkiDir + "/crl.pem"
	}
	newTxt, n := confSetCertBinding(string(txt), ins)
	if n != 1 {
		return 500, map[string]any{"error": fmt.Sprintf("conf management-client-auth 行未匹配 n=%d", n)}
	}
	_ = copyFile(real, real+".pre-certbind.bak")
	if err := os.WriteFile(real, []byte(newTxt), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	// oa2@2 CEL drop-in（环境变量形式；off 时移除）
	diDir := "/etc/systemd/system/oa2-modsafe@2.service.d"
	di := diDir + "/90-cert-binding.conf"
	if strict {
		if err := os.MkdirAll(diDir, 0o755); err != nil {
			return 500, map[string]any{"error": err.Error()}
		}
		dropin := "[Service]\nEnvironment=\"OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION=" +
			"openvpn.commonName in token.claims['cert_cns']\"\n"
		if err := os.WriteFile(di, []byte(dropin), 0o644); err != nil {
			return 500, map[string]any{"error": err.Error()}
		}
		if err := os.WriteFile(pkiDir+"/crl.pem", []byte(crl), 0o644); err != nil {
			return 500, map[string]any{"error": err.Error()}
		}
	} else {
		_ = os.Remove(di)
		_ = os.Remove(pkiDir + "/crl.pem")
	}
	_ = svcDaemonReload()
	_, err1 := svcRestart(oa2Service)
	_, err2 := svcRestart(nodeService)
	if err1 != nil || err2 != nil {
		msg := ""
		if err1 != nil {
			msg = err1.Error()
		} else {
			msg = err2.Error()
		}
		return 500, map[string]any{"ok": false, "strict": strict,
			"restart": truncateStr(msg, 200)}
	}
	return 200, map[string]any{"ok": true, "strict": strict, "restart": "done"}
}

func applyCRL(crl string) (int, map[string]any) {
	if !strings.HasPrefix(crl, "-----BEGIN X509 CRL") {
		return 400, map[string]any{"error": "crl 内容非法"}
	}
	if err := os.WriteFile(pkiDir+"/crl.pem", []byte(crl), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	return 200, map[string]any{"ok": true}
}

func applyIPv6(enable bool, v6net string) (int, map[string]any) {
	if enable && !strings.Contains(v6net, ":") {
		return 400, map[string]any{"error": "illegal v6net"}
	}
	real, err := confRealPathGuard(nodeConf)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	txt, err := os.ReadFile(real)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	newTxt, changed := confSetServerIPv6(string(txt), enable, v6net)
	if !changed {
		return 200, map[string]any{"ok": true, "enable": enable, "changed": false}
	}
	_ = copyFile(real, real+".pre-ipv6.bak")
	if err := os.WriteFile(real, []byte(newTxt), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	_, err = svcRestart(nodeService)
	if err != nil {
		return 500, map[string]any{"ok": false, "enable": enable,
			"restart": truncateStr(err.Error(), 200)}
	}
	return 200, map[string]any{"ok": true, "enable": enable, "restart": "done"}
}

func applyNetworkAgent(cidr string) (int, map[string]any) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 400, map[string]any{"error": fmt.Sprintf("invalid cidr: %v", err)}
	}
	prefix = prefix.Masked()
	if prefix.Bits() > 24 {
		return 400, map[string]any{"error": "node block must be /24 or larger"}
	}
	real, err := confRealPathGuard(nodeConf)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	txt, err := os.ReadFile(real)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	addr := prefix.Addr()
	mask := netMaskString(prefix)
	newTxt, updated := confReplaceServerLine(string(txt), addr.String(), mask)
	if !updated {
		return 500, map[string]any{"error": "server line not found in conf"}
	}
	if err := os.WriteFile(real, []byte(newTxt), 0o644); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	flushStaleMasquerade()
	_, _, _ = iptablesRun([]string{"-t", "nat", "-A", "POSTROUTING", "-s", prefix.String(),
		"-o", extIface, "-j", "MASQUERADE"})
	if saved, err := iptablesSave(); err == nil {
		_ = os.WriteFile(iptablesSaveF, []byte(saved), 0o644)
	}
	_, _ = svcRestart(nodeService)
	gw := addr
	return 200, map[string]any{"status": "applied", "cidr_block": cidr,
		"gateway": nextHostAddr(gw)}
}

func applyFwdRules(cidrs []any, dns []any, allowAll bool) (int, map[string]any) {
	// 前置校验：非法 cidr/dns 直接 400——否则拼进 -d 后 iptables 静默失败，
	// ACCEPT 缺失落入尾部 DROP=该网段全断，而接口仍回 ok:true（口径同 applyNetworkAgent；
	// 裸 IP 与 CIDR 均为 iptables -d 的合法目标）
	for _, list := range []struct {
		name string
		vals []any
	}{{"cidrs", cidrs}, {"dns", dns}} {
		for _, v := range list.vals {
			s := fmt.Sprintf("%v", v)
			if _, err := netip.ParsePrefix(s); err != nil {
				if _, err := netip.ParseAddr(s); err != nil {
					return 400, map[string]any{"error": fmt.Sprintf("illegal %s entry: %s", list.name, s)}
				}
			}
		}
	}
	// -A 追加失败即中止上报：半残规则链（缺 ACCEPT 却带尾部 DROP）=网段全断，
	// 不能再吞错返回 ok:true；-N/-F 保持吞错——链已存在是幂等正常路径
	ruleErr := ""
	appendRule := func(fn func([]string) (string, int, error), args []string) {
		if ruleErr != "" {
			return
		}
		if _, _, err := fn(args); err != nil {
			ruleErr = fmt.Sprintf("%s: %v", strings.Join(args, " "), err)
		}
	}
	_, _, _ = iptablesRun([]string{"-N", "MODSAFE-FWD"})
	_, _, _ = iptablesRun([]string{"-F", "MODSAFE-FWD"})
	_, _, _ = ip6tablesRun([]string{"-N", "MODSAFE-FWD6"})
	_, _, _ = ip6tablesRun([]string{"-F", "MODSAFE-FWD6"})
	isV6 := func(s string) bool { return strings.Contains(s, ":") }
	if allowAll {
		appendRule(iptablesRun, []string{"-A", "MODSAFE-FWD", "-j", "ACCEPT"})
		appendRule(ip6tablesRun, []string{"-A", "MODSAFE-FWD6", "-j", "ACCEPT"})
	} else {
		appendRule(iptablesRun, []string{"-A", "MODSAFE-FWD", "-d", "10.8.0.0/16", "-j", "DROP"})
		appendRule(ip6tablesRun, []string{"-A", "MODSAFE-FWD6", "-d", "fdaa:2026:192::/48", "-j", "DROP"})
		for _, c := range cidrs {
			s := fmt.Sprintf("%v", c)
			if isV6(s) {
				appendRule(ip6tablesRun, []string{"-A", "MODSAFE-FWD6", "-d", s, "-j", "ACCEPT"})
			} else {
				appendRule(iptablesRun, []string{"-A", "MODSAFE-FWD", "-d", s, "-j", "ACCEPT"})
			}
		}
		for _, d := range dns {
			s := fmt.Sprintf("%v", d)
			chain, fn := "MODSAFE-FWD", iptablesRun
			if isV6(s) {
				chain, fn = "MODSAFE-FWD6", ip6tablesRun
			}
			appendRule(fn, []string{"-A", chain, "-d", s, "-p", "udp", "--dport", "53", "-j", "ACCEPT"})
			appendRule(fn, []string{"-A", chain, "-d", s, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"})
		}
		// 尾部 DROP 仅在白名单全部就位后追加（中途失败不带 DROP，残留链 RETURN 回 FORWARD 不至于全断）
		appendRule(iptablesRun, []string{"-A", "MODSAFE-FWD", "-j", "DROP"})
		appendRule(ip6tablesRun, []string{"-A", "MODSAFE-FWD6", "-j", "DROP"})
	}
	if ruleErr != "" {
		return 500, map[string]any{"error": truncateStr("iptables "+ruleErr, 300)}
	}
	// 落盘自愈：节点重启后由 fwd-restore.py 恢复
	rules := map[string]any{"cidrs": cidrs, "dns": dns, "allow_all": allowAll}
	_ = saveJSONAtomic(clusterDir+"/fwd-rules.json", rules, 0o644)
	v6n := 0
	for _, c := range cidrs {
		if isV6(fmt.Sprintf("%v", c)) {
			v6n++
		}
	}
	return 200, map[string]any{"ok": true, "cidrs": len(cidrs), "cidrs_v6": v6n,
		"dns": len(dns), "allow_all": allowAll}
}

func flushStaleMasquerade() {
	listing, _, err := iptablesRun([]string{"-t", "nat", "-S", "POSTROUTING"})
	if err != nil {
		return
	}
	for _, rule := range strings.Split(listing, "\n") {
		toks := strings.Fields(rule)
		// 仅删 VPN 内网源（10.8.0.0/16 家族）的过期 MASQUERADE：取 -s 值精确前缀匹配，
		// 避免整行子串匹配把 "110.8.x.x" 之类仅含 "10.8." 字样的无关规则误删
		src := ""
		for i, t := range toks {
			if (t == "-s" || t == "--source") && i+1 < len(toks) {
				src = toks[i+1]
				break
			}
		}
		if len(toks) > 1 && toks[0] == "-A" && strings.HasPrefix(src, "10.8.") &&
			strings.Contains(rule, "MASQUERADE") {
			args := append([]string{"-t", "nat", "-D"}, toks[1:]...)
			_, _, _ = iptablesRun(args)
		}
	}
}

func netMaskString(p netip.Prefix) string {
	if p.Addr().Is6() {
		return net.IP(net.CIDRMask(p.Bits(), 128)).String()
	}
	return net.IP(net.CIDRMask(p.Bits(), 32)).String()
}

func nextHostAddr(a netip.Addr) string {
	return a.Next().String()
}
