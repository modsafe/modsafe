package main

// 控制平面反查通道（§②认证链路 + §18）：存在性检查/自动建档/CCD 同步、
// primary_idp 配置、门户会话反查、本地账号验密。权威源=控制平面。

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type cpResp struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func cpGet(path string, timeout time.Duration) (map[string]any, error) {
	req, err := http.NewRequest("GET", CONTROL_PLANE_URL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Internal-Token", readAdminToken())
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out cpResp
	if err := jsonUnmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// cpAuthCheck：发码前反查（存在/启用/自动建档/CCD 同步）。失败按 fail-mode。
func cpAuthCheck(provider, clientIP string, userinfo map[string]any) (bool, map[string]any) {
	groupsAny, _ := userinfo["_groups"].([]any)
	if len(groupsAny) > 50 {
		groupsAny = groupsAny[:50]
	}
	name := uiStr(userinfo, "name")
	body := map[string]any{
		"username":     firstNonEmpty(name, uiStr(userinfo, "sub")),
		"display_name": name,
		"idp_source":   provider,
		"external_id":  uiStr(userinfo, "sub"),
		"email":        uiStr(userinfo, "email"),
		"client_ip":    clientIP,
		"groups":       groupsAny,
	}
	j, _ := jsonMarshal(body)
	req, err := http.NewRequest("POST", CONTROL_PLANE_URL+"/api/v1/internal/auth-check", strings.NewReader(string(j)))
	if err != nil {
		return failMode(), map[string]any{"reason": "control-plane unreachable"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", readAdminToken())
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logf("auth-check ERROR (fail-%s): %v", AUTH_CHECK_FAIL_MODE, err)
		return failMode(), map[string]any{"reason": "control-plane unreachable"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out cpResp
	if err := jsonUnmarshal(raw, &out); err != nil {
		logf("auth-check ERROR (fail-%s): %v", AUTH_CHECK_FAIL_MODE, err)
		return failMode(), map[string]any{"reason": "control-plane unreachable"}
	}
	data := out.Data
	if data == nil {
		data = map[string]any{}
	}
	logf("auth-check user=%s action=%v created=%v reason=%s",
		name, data["action"], data["created"], mStr(data, "reason"))
	return mStr(data, "action") == "allow", data
}

func failMode() bool { return AUTH_CHECK_FAIL_MODE == "open" }

// cpAuthConfig：primary_idp / 本地兜底开关。失败 → 空配置（显示选择页）。
func cpAuthConfig() map[string]any {
	data, err := cpGet("/api/v1/internal/auth-config", 4*time.Second)
	if err != nil {
		logf("auth-config ERROR (fallback to selector): %v", err)
		return map[string]any{}
	}
	return data
}

// cpPortalWhoami：#57 身份归属修复——门户当前登录者优先于 web_sess。
// 未登录/过期/身份不可用返回 nil，调用方回退 web_sess。
func cpPortalWhoami(cookieHeader string) map[string]any {
	cid := cookieValue(cookieHeader, "portal_sess")
	if cid == "" {
		return nil
	}
	data, err := cpGet("/api/v1/internal/portal-whoami?pt="+url.QueryEscape(cid), 4*time.Second)
	if err != nil {
		return nil
	}
	if data == nil || mStr(data, "sub") == "" || mStr(data, "username") == "" {
		return nil
	}
	return data
}

// cpConnectGrant：B 方案——核销网页一键连接的一次性 ticket（控制面原子消费），
// 返回与 portal-whoami 同构的身份（sub/username/provider）；nil=无效/过期/控制面不可达
//（不可达按 fail-open 处理：回退既有 cookie 静默/交互验证路径，与 whoami 故障语义一致）。
func cpConnectGrant(ticket string) map[string]any {
	data, err := cpGet("/api/v1/internal/connect-grant?g="+url.QueryEscape(ticket), 4*time.Second)
	if err != nil {
		logf("connect-grant ERROR: %v", err)
		return nil
	}
	if data == nil || mStr(data, "sub") == "" || mStr(data, "username") == "" {
		return nil
	}
	return data
}

// cpLocalAuth：本地账号验密（users 表 source=local，§18 break-glass）
func cpLocalAuth(username, password string) (map[string]any, error) {
	j, _ := jsonMarshal(map[string]any{"username": username, "password": password})
	req, err := http.NewRequest("POST", CONTROL_PLANE_URL+"/api/v1/internal/auth-local", strings.NewReader(string(j)))
	if err != nil {
		return nil, fmt.Errorf("控制平面不可用: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", readAdminToken())
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("控制平面不可用: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out cpResp
	_ = jsonUnmarshal(raw, &out)
	if resp.StatusCode >= 300 || out.Code != 0 {
		msg := out.Message
		if msg == "" {
			msg = "账号或密码错误"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	d := out.Data
	if d == nil {
		d = map[string]any{}
	}
	uname := mStr(d, "username")
	if uname == "" {
		uname = username
	}
	return map[string]any{
		"sub":                mStr(d, "sub"),
		"name":               uname,
		"preferred_username": uname,
	}, nil
}

func uiStr(ui map[string]any, key string) string {
	if ui == nil {
		return ""
	}
	s, _ := ui[key].(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
