package main

// §18 认证源管理：primary_idp 单选 + 本地兜底 + adapter 配置查询（内部端点）。
// 凭证本体仍在 adapter 的 idp-config.json（不迁库），本处只管"选谁生效"。

import (
	"encoding/json"
	"net/http"
	"time"
)

var validPrimaryIDPs = map[string]bool{
	"dingtalk": true, "wecom": true, "feishu": true,
	"ldap-ad": true, "openldap": true, "oidc": true, "saml": true,
}

// dbSetting：settings 表点查（键恒为代码内字面量；命中与否由调用方决定兜底）。
// 含 SQL 的函数不接收任何环境变量派生参数——env 兜底在调用方选取
func dbSetting(a *App, key string) (string, bool) {
	var v string
	err := a.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

// getSetting：设置读取（键为代码内字面量，默认值直传）
func getSetting(a *App, key, def string) string {
	if v, ok := dbSetting(a, key); ok {
		return v
	}
	return def
}

func setSetting(a *App, key, value string) {
	_, _ = a.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
}

func httpGetJSON(url string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
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

// handleAuthConfigGet：管理台认证管理页数据（primary + adapter 侧凭证配置状态）
func (a *App) handleAuthConfigGet(w http.ResponseWriter, r *http.Request) {
	adapterIDPs := map[string]bool{}
	if health, err := httpGetJSON("http://127.0.0.1:8000/healthz"); err == nil {
		if m, ok := health["idps"].(map[string]interface{}); ok {
			for k, v := range m {
				adapterIDPs[k] = v == true
			}
		}
	}
	writeOK(w, r, map[string]interface{}{
		"primary_idp":           getSetting(a, "primary_idp", ""),
		"local_auth_enabled":    getSetting(a, "local_auth_enabled", "1") == "1",
		"hide_local_link":       getSetting(a, "hide_local_link", "0") == "1",
		"client_verify_policy":  getSetting(a, "client_verify_policy", "off"),
		"configured":            adapterIDPs,
	})
}

// handleAuthConfigPut：单选设置（二次确认由前端承担；审计走写操作钩子）
func (a *App) handleAuthConfigPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrimaryIDP          *string `json:"primary_idp"`
		LocalAuthEnabled    *bool   `json:"local_auth_enabled"`
		HideLocalLink       *bool   `json:"hide_local_link"`
		ClientVerifyPolicy  *string `json:"client_verify_policy"`
		ConfirmImpact       bool    `json:"confirm_impact"`
	}
	if err := jsonDecode(r, &req); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	if req.PrimaryIDP != nil {
		p := *req.PrimaryIDP
		if p != "" && !validPrimaryIDPs[p] {
			failParam(w, r, "primary_idp 不合法")
			return
		}
		// 主源必须已在 adapter 启用（有凭证且 enabled）——否则登录页无法直达，
		// 会静默回退选择页（正是"配置保存了但不生效"的历史事故根因）
		if p != "" {
			enabled, err := adapterIDPEnabled(p)
			if err != nil {
				failBiz(w, r, 50004, "无法确认该认证源状态（adapter 不可达），请稍后重试")
				return
			}
			if !enabled {
				failParam(w, r, "该认证源未启用（缺凭证或未开启），请先在下方「认证源凭证配置」中完成并启用")
				return
			}
		}
		setSetting(a, "primary_idp", p)
	}
	if req.LocalAuthEnabled != nil {
		setSetting(a, "local_auth_enabled", boolToStr(*req.LocalAuthEnabled))
	}
	if req.HideLocalLink != nil {
		setSetting(a, "hide_local_link", boolToStr(*req.HideLocalLink))
	}
	// B 方案客户端连接验证策略：off=现状（浏览器 8h 会话内免扫码）；
	// strict=客户端连接一律网页验证，仅门户一键连接的一次性 ticket（grant 参数）静默。
	// 开启前置条件：自家客户端（Android/Windows）须已支持 ticket 透传，否则一键连接也要求验证。
	if req.ClientVerifyPolicy != nil {
		p := *req.ClientVerifyPolicy
		if p != "off" && p != "strict" {
			failParam(w, r, "client_verify_policy 仅支持 off/strict")
			return
		}
		if p == "strict" && !req.ConfirmImpact {
			failParam(w, r, "开启 strict 需要二次确认（confirm_impact）：官方 OpenVPN/Tunnelblick 客户端将每次连接都要网页验证")
			return
		}
		setSetting(a, "client_verify_policy", p)
	}
	writeOK(w, r, nil)
}

// handleInternalAuthConfig：adapter /authorize 无 provider 时查询（本机 localhost + 共享令牌）
func (a *App) handleInternalAuthConfig(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	writeOK(w, r, map[string]interface{}{
		"primary_idp":        getSetting(a, "primary_idp", ""),
		"local_auth_enabled": getSetting(a, "local_auth_enabled", "1") == "1",
		"hide_local_link":    getSetting(a, "hide_local_link", "0") == "1",
		"client_verify_policy": getSetting(a, "client_verify_policy", "off"),
	})
}

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// adapterIDPEnabled：查询某 IdP 在 adapter 的启用状态（healthz.idps）
func adapterIDPEnabled(pid string) (bool, error) {
	health, err := httpGetJSON("http://127.0.0.1:8000/healthz")
	if err != nil {
		return false, err
	}
	m, _ := health["idps"].(map[string]interface{})
	en, _ := m[pid].(bool)
	return en, nil
}

// ── 认证源凭证配置（§12.2 认证管理：凭证本体在 adapter idp-config.json，此处鉴权代理）──

// GET /api/v1/auth/idp-credentials：各 IdP 凭证回显（secret 类字段脱敏 ******，空=未配置）
func (a *App) handleIdpCredentialsGet(w http.ResponseWriter, r *http.Request) {
	out, err := adapterAdmin("GET", "/admin/idp-config", nil)
	if err != nil {
		failSystem(w, r, "凭证读取失败：adapter 不可达 "+err.Error())
		return
	}
	writeOK(w, r, out)
}

// PUT /api/v1/auth/idp-credentials：{idp, fields:{...}, enabled}；脱敏值/空串=保留原值
func (a *App) handleIdpCredentialsPut(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := jsonDecode(r, &body); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	idp, _ := body["idp"].(string)
	if idp == "" {
		failParam(w, r, "idp 必填")
		return
	}
	// §22.6-8 License 联动：启用 SAML 需授权含 saml feature 位（20007 功能未授权）
	if idp == "saml" {
		if en, _ := body["enabled"].(bool); en && !a.licenseHasFeature("saml") {
			writeFail(w, r, 20007, http.StatusForbidden, "当前授权不包含 SAML 功能，请升级 License")
			return
		}
	}
	out, err := adapterAdmin("POST", "/admin/idp-config", body)
	if !adapterOK(w, r, out, err, "凭证保存") {
		return
	}
	writeOK(w, r, nil)
}

// handleSamlParseMetadata：POST /api/v1/auth/saml/parse-metadata
// §22.5 管理台「验证 metadata」——解析在 adapter 执行（lxml 在那边），此处鉴权代理
func (a *App) handleSamlParseMetadata(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := jsonDecode(r, &body); err != nil {
		failParam(w, r, "请求体不合法")
		return
	}
	out, err := adapterAdmin("POST", "/admin/saml/parse-metadata", body)
	if !adapterOK(w, r, out, err, "metadata 解析") {
		return
	}
	writeOK(w, r, out)
}
