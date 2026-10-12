package main

// 系统设置（§12.2）：品牌设置 + 客户端接入地址 + 告警通知渠道。
// 品牌/通知渠道本体在 adapter（branding.json / alert-channels.json，附录A+§20 已实现），
// 本模块做带鉴权的代理转发——管理台统一走 9443 JWT + 角色矩阵，不再直连 adapter :8000 的 /admin API。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var adapterBase = envOr("MODSAFE_ADAPTER_URL", "http://127.0.0.1:8000")

// validPortalBase（#129）：门户地址配置校验——仅 http/https、必须有 host、不带路径
// （base 只到源，路径由各端点自行拼接）；返回规范化值（scheme://host[:port]）
func validPortalBase(s string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// readAdminToken：集群共享管理令牌（/opt/modsafe/admin-token，与 node-agent/adapter 一致）。
// adapter /admin/* 自 2026-09-29 安全加固起强制校验 X-Admin-Token。
func readAdminToken() string {
	b, err := os.ReadFile(envOr("MODSAFE_ADMIN_TOKEN_FILE", "/opt/modsafe/admin-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// adapterAdmin：adapter /admin/* 转发（本机 localhost）。
// 超时放宽到 30s：POST /admin/branding 内部会渲染模板并重启 oa2（含端口释放轮询，最长 ~10s）
func adapterAdmin(method, path string, body map[string]interface{}) (map[string]interface{}, error) {
	var rdr *bytes.Reader
	if body == nil {
		rdr = bytes.NewReader(nil)
	} else {
		payload, _ := json.Marshal(body)
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, adapterBase+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", readAdminToken())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// adapterOK：adapter 管理接口统一的结果断言（返回 {status:bool, error?:string}）
func adapterOK(w http.ResponseWriter, r *http.Request, out map[string]interface{}, err error, what string) bool {
	if err != nil {
		failSystem(w, r, what+"失败：adapter 不可达 "+err.Error())
		return false
	}
	// adapter 成功响应为 {"status":"ok"}（字符串）；历史实现断言 bool 导致所有
	// 经控制面代理的 adapter 保存必然报"adapter 返回失败"（2026-09-30 修复）
	switch st := out["status"].(type) {
	case bool:
		if !st {
			msg, _ := out["error"].(string)
			if msg == "" {
				msg = "adapter 返回失败"
			}
			failBiz(w, r, 50004, what+"失败："+msg)
			return false
		}
	case string:
		if st != "ok" {
			msg, _ := out["error"].(string)
			if msg == "" {
				msg = st
			}
			failBiz(w, r, 50004, what+"失败："+msg)
			return false
		}
	default:
		failBiz(w, r, 50004, what+"失败：adapter 响应不合法")
		return false
	}
	return true
}

// ── 品牌与接入地址 ──

// GET /api/v1/settings/general
func (a *App) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	// adapter 读端点是 GET /branding（无 /admin 前缀；写才是 POST /admin/branding）
	branding, err := adapterAdmin("GET", "/branding", nil)
	if err != nil {
		branding = map[string]interface{}{"error": "adapter 不可达：" + err.Error()}
	}
	writeOK(w, r, map[string]interface{}{
		"branding":    branding,
		"vpn_remote":  getSetting(a, "vpn_remote", os.Getenv("MODSAFE_VPN_REMOTE")),
		"portal_base": getSetting(a, "portal_base", envOr("MODSAFE_PORTAL_BASE", "")),
	})
}

// PUT /api/v1/settings/general（super_admin；品牌变更即时生效=渲染 oa2 模板并重启 oa2）
func (a *App) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CompanyName *string `json:"company_name"`
		ProductName *string `json:"product_name"`
		FooterText  *string `json:"footer_text"`
		VpnRemote   *string `json:"vpn_remote"`
		PortalBase  *string `json:"portal_base"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if req.PortalBase != nil {
		norm, ok := validPortalBase(*req.PortalBase)
		if !ok {
			failParam(w, r, "门户地址格式应为 https://主机[:端口]（如 https://portal.example.com）")
			return
		}
		setSetting(a, "portal_base", norm)
	}
	if req.VpnRemote != nil {
		if !validVpnRemote(*req.VpnRemote) {
			failParam(w, r, "vpn_remote 格式应为 \"地址 端口\"（如 vpn.example.com 1194）")
			return
		}
		setSetting(a, "vpn_remote", *req.VpnRemote)
	}
	if req.CompanyName != nil || req.ProductName != nil || req.FooterText != nil {
		for k, v := range map[*string]string{
			req.CompanyName: "公司名", req.ProductName: "产品名", req.FooterText: "页脚",
		} {
			if k != nil && len([]rune(strings.TrimSpace(*k))) > 128 {
				failParam(w, r, v+"长度不能超过 128 字符")
				return
			}
		}
		// adapter 保存需完整三字段：未提供的先读现值合并
		body := map[string]interface{}{}
		if cur, err := adapterAdmin("GET", "/branding", nil); err == nil {
			for _, k := range []string{"company_name", "product_name", "footer_text"} {
				if v, ok := cur[k].(string); ok {
					body[k] = v
				}
			}
		}
		if req.CompanyName != nil {
			body["company_name"] = strings.TrimSpace(*req.CompanyName)
		}
		if req.ProductName != nil {
			body["product_name"] = strings.TrimSpace(*req.ProductName)
		}
		if req.FooterText != nil {
			body["footer_text"] = strings.TrimSpace(*req.FooterText)
		}
		out, err := adapterAdmin("POST", "/admin/branding", body)
		if !adapterOK(w, r, out, err, "品牌保存") {
			return
		}
	}
	writeOK(w, r, nil)
}

func validVpnRemote(s string) bool {
	f := strings.Fields(s)
	if len(f) != 2 {
		return false
	}
	port, err := strconv.Atoi(f[1])
	return err == nil && port > 0 && port < 65536
}

// ── 会话策略（空闲自动断开 + 免扫码时长）──

// GET /api/v1/settings/session
func (a *App) handleSessionPolicyGet(w http.ResponseWriter, r *http.Request) {
	mins := 0
	for _, c := range getSetting(a, "session_idle_timeout", "0") {
		if c < '0' || c > '9' {
			mins = 0
			break
		}
		mins = mins*10 + int(c-'0')
	}
	writeOK(w, r, map[string]interface{}{
		"idle_timeout_minutes":       mins,
		"idle_ignore_users":          getSetting(a, "session_idle_ignore_users", "ha-test-client"),
		"auth_token_lifetime_minutes": atoiDefault(getSetting(a, "auth_token_lifetime_minutes", "1440"), 1440),
	})
}

// PUT /api/v1/settings/session（super_admin；idle_timeout_minutes=0 表示关闭）
func (a *App) handleSessionPolicyPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IdleTimeoutMinutes        *int   `json:"idle_timeout_minutes"`
		IdleIgnoreUsers           *string `json:"idle_ignore_users"`
		AuthTokenLifetimeMinutes  *int   `json:"auth_token_lifetime_minutes"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if req.IdleTimeoutMinutes != nil {
		m := *req.IdleTimeoutMinutes
		if m < 0 || m > 60*24*7 {
			failParam(w, r, "空闲超时须在 0（关闭）~ 10080 分钟之间")
			return
		}
		setSetting(a, "session_idle_timeout", strconv.Itoa(m))
	}
	if req.IdleIgnoreUsers != nil {
		users := strings.TrimSpace(*req.IdleIgnoreUsers)
		if len(users) > 512 {
			failParam(w, r, "忽略名单过长")
			return
		}
		setSetting(a, "session_idle_ignore_users", users)
	}
	if req.AuthTokenLifetimeMinutes != nil {
		m := *req.AuthTokenLifetimeMinutes
		if m < 60 || m > 10080 {
			failParam(w, r, "免扫码时长须在 60~10080 分钟之间（下限保证会话内重协商兼容）")
			return
		}
		setSetting(a, "auth_token_lifetime_minutes", strconv.Itoa(m))
	}
	writeOK(w, r, nil)
}

// applyAuthTokenLocal：node-1（控制平面所在机）本机下发——sed conf 的 auth-gen-token 行 + 重启节点
func applyAuthTokenLocal(minutes int) error {
	conf := envOr("MODSAFE_NODE1_CONF", "/etc/openvpn/instances/node-1.conf")
	raw, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^auth-gen-token \d+ external-auth\s*$`)
	if len(re.FindAll(raw, 1)) != 1 {
		return errors.New("conf auth-gen-token 行未唯一")
	}
	newLine := []byte(fmt.Sprintf("auth-gen-token %d external-auth", minutes*60))
	updated := re.ReplaceAll(raw, newLine)
	_ = os.WriteFile(conf+".pre-token.bak", raw, 0o600)
	return os.WriteFile(conf, updated, 0o600)
}

// POST /api/v1/settings/session/apply（super_admin）：把免扫码时长下发双节点（改 conf + 重启，中断 15-30s）。
// 注意：新 TTL 立即按验证时刻计算——已签发 token 若超新时长，重连即要求重新扫码（收紧即时生效）。
func (a *App) handleSessionApply(w http.ResponseWriter, r *http.Request) {
	mins := atoiDefault(getSetting(a, "auth_token_lifetime_minutes", "1440"), 1440)
	if mins < 60 || mins > 10080 {
		failParam(w, r, "免扫码时长未配置或非法（60~10080 分钟）")
		return
	}
	results := []map[string]interface{}{}
	// node-1：本机直改
	if err := applyAuthTokenLocal(mins); err != nil {
		results = append(results, map[string]interface{}{"node": "node-1", "ok": false, "error": err.Error()})
	} else {
		rc := exec.Command("systemctl", "restart", "openvpn-modsafe@1").Run()
		results = append(results, map[string]interface{}{"node": "node-1", "ok": rc == nil,
			"lifetime_seconds": mins * 60})
	}
	// node-2：经 node-agent
	for _, node := range nodes {
		if node.Kind != "agent" {
			continue
		}
		out, err := agentRequest(node, "POST", "/authtoken", map[string]interface{}{"minutes": mins})
		if err != nil {
			results = append(results, map[string]interface{}{"node": node.Name, "ok": false, "error": err.Error()})
			continue
		}
		ok, _ := out["ok"].(bool)
		results = append(results, map[string]interface{}{"node": node.Name, "ok": ok, "result": out})
	}
	writeOK(w, r, map[string]interface{}{"lifetime_seconds": mins * 60, "results": results})
}

// ── 通知渠道（§20，本体 alert-channels.json 在 adapter）──

var validChannelTypes = map[string]bool{"wecom": true, "dingtalk": true, "feishu": true, "generic": true}

// GET /api/v1/settings/notify-channels
func (a *App) handleNotifyChannelsGet(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("GET", "/admin/alerts/channels", nil)
	if err != nil {
		failSystem(w, r, "通知渠道读取失败：adapter 不可达 "+err.Error())
		return
	}
	writeOK(w, r, out)
}

// POST /api/v1/settings/notify-channels（super_admin；id 空=新增，否则编辑）
func (a *App) handleNotifyChannelSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Webhook string `json:"webhook"`
		Enabled *bool  `json:"enabled"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if !validChannelTypes[req.Type] {
		failParam(w, r, "type 仅支持 wecom/dingtalk/feishu/generic")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		failParam(w, r, "name 必填")
		return
	}
	if !strings.HasPrefix(req.Webhook, "http") {
		failParam(w, r, "webhook 必须是 http(s) 地址")
		return
	}
	body := map[string]interface{}{
		"type": req.Type, "name": strings.TrimSpace(req.Name),
		"webhook": strings.TrimSpace(req.Webhook),
		"enabled": req.Enabled == nil || *req.Enabled,
	}
	if req.ID != "" {
		body["id"] = req.ID
	}
	out, err := adapterAdmin("POST", "/admin/alerts/channels", body)
	if !adapterOK(w, r, out, err, "通知渠道保存") {
		return
	}
	writeOK(w, r, nil)
}

// DELETE /api/v1/settings/notify-channels/{id}（super_admin）
func (a *App) handleNotifyChannelDelete(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("POST", "/admin/alerts/channels/delete", map[string]interface{}{"id": r.PathValue("id")})
	if !adapterOK(w, r, out, err, "通知渠道删除") {
		return
	}
	writeOK(w, r, nil)
}

// POST /api/v1/settings/notify-channels/test（super_admin；向所有启用渠道真实发送测试消息）
func (a *App) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("POST", "/admin/alerts/test", map[string]interface{}{})
	if err != nil {
		failSystem(w, r, "测试发送失败：adapter 不可达 "+err.Error())
		return
	}
	writeOK(w, r, out)
}

// GET /api/v1/settings/notify-email
func (a *App) handleNotifyEmailGet(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("GET", "/admin/alerts/email", nil)
	if err != nil {
		failSystem(w, r, "邮箱配置读取失败：adapter 不可达 "+err.Error())
		return
	}
	writeOK(w, r, out)
}

// PUT /api/v1/settings/notify-email（super_admin；字段透传 adapter 校验，密码不回传——占位由前端处理）
func (a *App) handleNotifyEmailPut(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := jsonDecode(r, &body); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if en, _ := body["enabled"].(bool); en {
		if host, _ := body["smtp_host"].(string); strings.TrimSpace(host) == "" {
			failParam(w, r, "启用邮箱告警时 SMTP 服务器不能为空")
			return
		}
	}
	out, err := adapterAdmin("POST", "/admin/alerts/email", body)
	if !adapterOK(w, r, out, err, "邮箱配置保存") {
		return
	}
	writeOK(w, r, nil)
}
