package main

// /admin/* 管理端点（控制平面 adapterAdmin 转发的 9 类契约 + 旧工具端点）+ 品牌联动。

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	poolMu  sync.Mutex
	uuidSeq int
)

func uuidShort() string {
	uuidSeq++
	return fmt.Sprintf("%08x%04d", time.Now().UnixNano()&0xffffffff, uuidSeq)[:8]
}

// ---- IdP 凭证配置 ----

func handleAdminIDPConfigGet(w http.ResponseWriter, r *http.Request) {
	cfgAll := loadIDPConfig()
	out := map[string]any{}
	for _, pid := range idpOrder {
		c := map[string]any{}
		for k, v := range cfgAll[pid] {
			c[k] = v
		}
		delete(c, "enabled")
		for k := range c {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "secret") || strings.Contains(lk, "password") {
				if s := mStr(c, k); s != "" {
					c[k] = "******"
				} else {
					c[k] = ""
				}
			}
		}
		cb := ""
		if IDP_META[pid].Type == "oauth" {
			cb = ADAPTER_BASE + "/callback/" + pid
		}
		entry := map[string]any{
			"enabled": idpEnabled(pid), "label": idpLabel(pid),
			"type": IDP_META[pid].Type, "fields": c, "callback_url": cb,
		}
		if pid == "saml" {
			entry["acs_url"] = samlACSURL()
			entry["metadata_url"] = samlMetadataURL()
		}
		out[pid] = entry
	}
	writeJSON(w, 200, map[string]any{"idps": out})
}

func handleAdminIDPConfigPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	pid := mStr(body, "idp")
	if _, ok := IDP_META[pid]; !ok || pid == "mock" {
		writeJSON(w, 400, map[string]any{"error": "unknown idp"})
		return
	}
	fields, _ := body["fields"].(map[string]any)
	cfgAll := loadIDPConfig()
	cur := map[string]any{}
	for k, v := range cfgAll[pid] {
		cur[k] = v
	}
	for k, v := range fields {
		if v == nil || v == "" || v == "******" {
			continue
		}
		cur[k] = v
	}
	if enabled, has := body["enabled"]; has {
		en, _ := enabled.(bool)
		if en {
			switch IDP_META[pid].Type {
			case "ldap":
				if mStr(cur, "server") == "" {
					writeJSON(w, 400, map[string]any{"error": "LDAP 类认证源启用前必须填写服务器地址 server"})
					return
				}
			case "oauth":
				if mStr(cur, "client_id") == "" && mStr(cur, "app_id") == "" && mStr(cur, "corp_id") == "" {
					writeJSON(w, 400, map[string]any{"error": "OAuth 类认证源启用前必须填写应用凭证"})
					return
				}
			case "saml":
				if mStr(cur, "entity_id") == "" || mStr(cur, "sso_url") == "" || mStr(cur, "idp_certificate") == "" {
					writeJSON(w, 400, map[string]any{"error": "SAML 认证源启用前必须填写 entityID、SSO URL 和 IdP 签名证书"})
					return
				}
			}
		}
		cur["enabled"] = en
		others := false
		for p, c := range cfgAll {
			if p != pid && p != "mock" && mBool(c, "enabled") {
				others = true
				break
			}
		}
		if !en && !others {
			writeJSON(w, 400, map[string]any{"error": "不能禁用最后一个启用的认证源"})
			return
		}
	}
	cfgAll[pid] = cur
	if err := saveIDPConfig(cfgAll); err != nil {
		writeJSON(w, 500, map[string]any{"error": "save failed"})
		return
	}
	// 整体替换快照（避免并发登录读到空配置）
	snap := loadIDPConfig()
	setIDPC(snap)
	logf("idp-config updated: %s enabled=%v", pid, mBool(cur, "enabled"))
	writeJSON(w, 200, map[string]any{"status": "ok"})
}

// ---- 目录同步拉取 ----

func handleAdminDirectory(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("idp")
	fn, ok := DIRECTORY_FETCHERS[pid]
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "idp 仅支持 dingtalk/wecom/feishu"})
		return
	}
	d, err := fn()
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"idp": pid, "departments": d["departments"], "users": d["users"]})
}

// ---- 品牌 ----

func handleBrandingGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, loadBranding())
}

func handleAdminBrandingPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	if _, ok := body["company_name"]; !ok {
		writeJSON(w, 400, map[string]any{"error": "company_name required"})
		return
	}
	cfg := loadBranding()
	for k := range DEFAULT_BRANDING {
		if v, ok := body[k]; ok {
			cfg[k] = fmt.Sprintf("%v", v)
		}
	}
	saveBranding(cfg)
	renderOA2Template(cfg)
	_ = runSystemctlRestartUnit("oa2-modsafe@1")
	logf("oa2 restarted via systemctl")
	logf("branding updated: %s / %s", mStr(cfg, "company_name"), mStr(cfg, "product_name"))
	writeJSON(w, 200, map[string]any{"status": "ok", "branding": cfg, "oa2_restarted": true})
}

// ---- 网段 ----

func handleAdminNetworkGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, loadNetwork())
}

func handleAdminNetworkPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	cidr := mStr(body, "cidr")
	prefix, err := netipParse(cidr)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid cidr"})
		return
	}
	if prefix.Bits() > 20 {
		writeJSON(w, 400, map[string]any{"error": "base cidr must be /20 or larger to split node blocks"})
		return
	}
	nodePrefix := 23
	if v, ok := body["node_prefix"].(float64); ok {
		nodePrefix = int(v)
	}
	cfg, remote, err := applyNetwork(cidr, nodePrefix)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	logf("network updated: %s → node1=%v node2=%v remote=%v", cidr,
		cfg["blocks"].(map[string]any)["1"], cfg["blocks"].(map[string]any)["2"], remote)
	writeJSON(w, 200, map[string]any{"status": "ok", "network": cfg, "remote_node": remote})
}

// ---- 告警通道 ----

func handleAlertChannelsGet(w http.ResponseWriter, r *http.Request) {
	cfg := loadChannels()
	channels, _ := cfg["channels"].([]any)
	writeJSON(w, 200, map[string]any{"channels": channels})
}

func handleAlertChannelsPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	typ := mStr(body, "type")
	webhook := mStr(body, "webhook")
	if !contains([]string{"wecom", "dingtalk", "feishu", "generic"}, typ) || webhook == "" {
		writeJSON(w, 400, map[string]any{"error": "type(wecom/dingtalk/feishu/generic) and webhook required"})
		return
	}
	cfg := loadChannels()
	id := mStr(body, "id")
	if id == "" {
		id = uuidShort()
	}
	name := mStr(body, "name")
	if name == "" {
		name = typ
	}
	enabled := true
	if b, ok := body["enabled"].(bool); ok {
		enabled = b
	}
	ch := map[string]any{"id": id, "type": typ, "name": name, "webhook": webhook, "enabled": enabled}
	replaced := false
	channels, _ := cfg["channels"].([]any)
	for i, it := range channels {
		if cm, ok := it.(map[string]any); ok && mStr(cm, "id") == id {
			channels[i] = ch
			replaced = true
		}
	}
	if !replaced {
		channels = append(channels, ch)
	}
	cfg["channels"] = channels
	saveChannels(cfg)
	writeJSON(w, 200, map[string]any{"status": "ok", "channel": ch, "replaced": replaced})
}

func handleAlertChannelsDelete(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	cfg := loadChannels()
	channels, _ := cfg["channels"].([]any)
	before := len(channels)
	id := mStr(body, "id")
	var kept []any
	for _, it := range channels {
		if cm, ok := it.(map[string]any); ok && mStr(cm, "id") != id {
			kept = append(kept, it)
		}
	}
	cfg["channels"] = kept
	saveChannels(cfg)
	writeJSON(w, 200, map[string]any{"status": "ok", "removed": before - len(kept)})
}

func handleAlertEmailGet(w http.ResponseWriter, r *http.Request) {
	cfg := loadChannels()
	em, _ := cfg["email"].(map[string]any)
	out := map[string]any{}
	for k, v := range em {
		out[k] = v
	}
	if mStr(out, "password") != "" {
		out["password"] = "******"
	}
	writeJSON(w, 200, out)
}

func handleAlertEmailPost(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	cfg := loadChannels()
	oldEm, _ := cfg["email"].(map[string]any)
	oldPwd := mStr(oldEm, "password") // 合并前快照
	em := map[string]any{}
	for k, v := range oldEm {
		em[k] = v
	}
	for _, k := range []string{"enabled", "smtp_host", "smtp_port", "smtp_ssl", "username",
		"password", "from_addr", "to_addrs"} {
		if v, ok := body[k]; ok {
			em[k] = v
		}
	}
	if mStr(em, "password") == "******" {
		// 哨兵还原：必须取合并前快照（整表单回存不得覆盖真实 SMTP 密码）
		em["password"] = oldPwd
	}
	port := 0
	if _, err := fmt.Sscanf(mStr(em, "smtp_port"), "%d", &port); err != nil && em["smtp_port"] != nil {
		if _, ok := em["smtp_port"].(float64); !ok {
			writeJSON(w, 400, map[string]any{"error": "smtp_port 必须为整数"})
			return
		}
	}
	if f, ok := em["smtp_port"].(float64); ok {
		port = int(f)
	}
	em["smtp_port"] = port
	cfg["email"] = em
	saveChannels(cfg)
	out := map[string]any{}
	for k, v := range em {
		out[k] = v
	}
	if mStr(out, "password") != "" {
		out["password"] = "******"
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "email": out})
}

func handleAlertsSend(w http.ResponseWriter, r *http.Request) {
	// §20 告警引擎统一发送：{level, message} → 按级别路由到已启用渠道
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	level := mStr(body, "level")
	if level == "" {
		level = "warn"
	}
	message := mStr(body, "message")
	if message == "" {
		writeJSON(w, 400, map[string]any{"error": "message required"})
		return
	}
	results := notifyAll(level, message, nowUnix())
	var sent []string
	for _, rr := range results {
		if !strings.Contains(rr, "FAILED") {
			sent = append(sent, strings.Split(rr, ":")[0])
		}
	}
	v := "none"
	if len(sent) > 0 {
		v = strings.Join(sent, ",")
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "sent_to": v})
}

func handleAlertsTest(w http.ResponseWriter, r *http.Request) {
	results := notifyAll("warn", "这是一条测试告警（后台通知通道验证）", nowUnix())
	writeJSON(w, 200, map[string]any{"status": "ok", "results": results})
}

// ---- 旧工具端点：证书池签发 .ovpn ----

func handleAdminClientsIssue(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	username := strings.TrimSpace(mStr(body, "username"))
	if username == "" {
		writeJSON(w, 400, map[string]any{"error": "username required"})
		return
	}
	poolDir := envPath("MODSAFE_CLIENT_POOL", "/opt/modsafe/client-pool")
	usedFile := envPath("MODSAFE_CLIENT_POOL_USED", "/opt/modsafe/client-pool-used.json")
	poolMu.Lock()
	used, ok := loadJSONFile(usedFile)
	if !ok {
		used = map[string]any{}
	}
	entries, err := os.ReadDir(poolDir)
	if err != nil {
		poolMu.Unlock()
		writeJSON(w, 503, map[string]any{"error": "证书池耗尽，请联系管理员补充"})
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
			names = append(names, strings.TrimSuffix(e.Name(), ".crt"))
		}
	}
	sort.Strings(names)
	certName := ""
	for _, n := range names {
		if _, used1 := used[n]; !used1 {
			certName = n
			break
		}
	}
	if certName == "" {
		poolMu.Unlock()
		writeJSON(w, 503, map[string]any{"error": "证书池耗尽，请联系管理员补充"})
		return
	}
	used[certName] = map[string]any{"assigned_to": username, "ts": nowUnix()}
	_ = saveJSONAtomic(usedFile, used, 0o644)
	poolMu.Unlock()

	pki := envPath("MODSAFE_PKI_DIR", "/root/modsafe-pki2")
	caCrt, err1 := os.ReadFile(filepath.Join(pki, "ca.crt"))
	clCrt, err2 := os.ReadFile(filepath.Join(poolDir, certName+".crt"))
	clKey, err3 := os.ReadFile(filepath.Join(poolDir, certName+".key"))
	taKey, err4 := os.ReadFile(filepath.Join(pki, "ta.key"))
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeJSON(w, 500, map[string]any{"error": "证书文件读取失败"})
		return
	}
	// remote 端点经 MODSAFE_OVPN_REMOTES 配置（逗号分隔 "host port" 对，缺省=历史硬编码值）
	remoteLines := ""
	for _, ep := range strings.Split(OVPN_REMOTES, ",") {
		if ep = strings.TrimSpace(ep); ep != "" {
			remoteLines += "remote " + ep + "\n"
		}
	}
	ovpn := "client\ndev tun\nproto udp\n" +
		remoteLines +
		"remote-random\nnobind\npersist-key\npersist-tun\n" +
		"remote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n" +
		"auth-nocache\nverb 3\nexplicit-exit-notify 1\n" +
		"auth-user-pass\n" +
		"<ca>\n" + string(caCrt) + "</ca>\n" +
		"<cert>\n" + string(clCrt) + "</cert>\n" +
		"<key>\n" + string(clKey) + "</key>\n" +
		"<tls-auth>\n" + string(taKey) + "</tls-auth>\n" +
		"key-direction 1\n"
	logf("client .ovpn issued: cert=%s user=%s", certName, username)
	writeJSON(w, 200, map[string]any{"status": "ok", "cert": certName, "username": username,
		"ovpn_base64": base64.StdEncoding.EncodeToString([]byte(ovpn)),
		"filename":    fmt.Sprintf("modsafe-%s.ovpn", username)})
}

// ---- SAML metadata 解析（管理台「验证 metadata」按钮后端） ----

func handleSamlParseMetadata(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := jsonUnmarshal([]byte(readBody(r)), &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	xmlText := mStr(body, "xml")
	if strings.TrimSpace(xmlText) == "" {
		writeJSON(w, 400, map[string]any{"error": "xml required"})
		return
	}
	parsed, err := samlParseIDPMetadata(xmlText)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	out := map[string]any{"status": "ok"}
	for k, v := range parsed {
		out[k] = v
	}
	writeJSON(w, 200, out)
}

// ---- 小工具 ----

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
