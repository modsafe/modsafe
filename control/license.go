package main

// License 系统（§17）：Ed25519 离线授权，商业控量（用户数/并发/节点数/功能/有效期）。
// 格式：base64(payload_json) + "." + base64(ed25519_signature)。
// 诚实定位（§17.3）：防君子不防高手——签名防伪造、控制量防超用，不对抗逆向。
// 公钥：licensePubHex 常量（正式交付时换正式密钥对重编），可被 MODSAFE_LICENSE_PUB env
// 或 data/license.pub 覆盖；私钥厂商离线保管（license-offline/，禁止进产品包/仓库）。

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CE 发布不内置公钥：避免"公钥公开 + 厂商 seed 一旦泄漏 = 授权可伪造"的组合。
// 部署方经 MODSAFE_LICENSE_PUB env 或 data/license.pub 注入公钥；
// 未注入时 license 校验不可用（导入授权会报错），试用模式不受影响。
const licensePubHex = ""

const licenseTrialDays = 30  // 无 license 试用模式
const licenseGraceDays = 15  // 到期后宽限：功能全可用，仅红横幅
const licenseWarnDays = 30   // 到期前提醒窗口

type licensePayload struct {
	LicID           string   `json:"lic_id"`
	Customer        string   `json:"customer"`
	Edition         string   `json:"edition"`
	MaxUsers        int      `json:"max_users"`
	MaxConcurrent   int      `json:"max_concurrent"`
	MaxNodes        int      `json:"max_nodes"`
	Features        []string `json:"features"`
	NotBefore       string   `json:"not_before"`
	ExpiresAt       *string  `json:"expires_at"` // null = perpetual
	InstanceBinding *string  `json:"instance_binding"`
	Ver             int      `json:"ver"`
}

var (
	licenseMu    sync.Mutex
	licenseCache *licensePayload // 内存缓存：DB 记录损坏/被删时回退（§17.2 不停服）
)

func licensePubKey() (ed25519.PublicKey, error) {
	hexKey := licensePubHex
	if v := os.Getenv("MODSAFE_LICENSE_PUB"); v != "" {
		hexKey = strings.TrimSpace(v)
	}
	if b, err := os.ReadFile(filepath.Join(envOr("MODSAFE_DATA_DIR", "data"), "license.pub")); err == nil && len(b) >= 64 {
		hexKey = strings.TrimSpace(string(b))
	}
	pub, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("license 公钥未配置或不合法：请设置 MODSAFE_LICENSE_PUB 环境变量或 data/license.pub")
	}
	return pub, nil
}

// parseLicenseFile：导入时验证（验签 + 字段校验 + 时间窗）。任何失败返回错误。
func parseLicenseFile(raw string) (*licensePayload, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return nil, errors.New("格式应为 base64(payload).base64(signature)")
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("payload base64 不合法")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("signature base64 不合法")
	}
	pub, err := licensePubKey()
	if err != nil {
		return nil, errors.New("内嵌公钥不合法")
	}
	if !ed25519.Verify(pub, payloadBytes, sig) {
		return nil, errors.New("签名验证失败（文件被篡改或密钥不匹配）")
	}
	var p licensePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, errors.New("payload JSON 不合法")
	}
	switch p.Edition {
	case "standard", "professional", "enterprise":
	default:
		return nil, errors.New("edition 不合法")
	}
	if p.Ver != 1 || p.MaxUsers < 1 || p.MaxConcurrent < 1 || p.MaxNodes < 1 {
		return nil, errors.New("payload 字段不合法")
	}
	if p.NotBefore != "" {
		if nb, e := time.Parse(time.RFC3339, p.NotBefore); e == nil && time.Now().Before(nb) {
			return nil, errors.New("授权尚未到生效时间")
		}
	}
	return &p, nil
}

func errorsNew(s string) error { return &licenseError{s} }

type licenseError struct{ msg string }

func (e *licenseError) Error() string { return e.msg }

// loadInstalledLicense：取当前生效 license（DB 最新一条；DB 异常/记录损坏回退内存缓存 §17.2）
func (a *App) loadInstalledLicense() *licensePayload {
	licenseMu.Lock()
	defer licenseMu.Unlock()
	var raw string
	err := a.db.QueryRow(`SELECT raw FROM license ORDER BY id DESC LIMIT 1`).Scan(&raw)
	if err == nil {
		if p, perr := parseLicenseFile(raw); perr == nil {
			licenseCache = p
			return p
		}
	}
	return licenseCache
}

// licenseState：状态机（trial/ok/expiring/grace/expired）+ 用量
func (a *App) licenseState() map[string]interface{} {
	var usedUsers, totalUsers int
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(status='active'),0), COUNT(*) FROM users`).Scan(&usedUsers, &totalUsers)
	live := len(liveSessions())

	lic := a.loadInstalledLicense()
	now := time.Now()

	st := map[string]interface{}{
		"used_users":    usedUsers,
		"total_users":   totalUsers,
		"live_sessions": live,
		"nodes":         len(nodes),
		"max_nodes":     len(nodes), // 无 license 约束时 = 当前实际节点数
	}
	if lic == nil {
		// 试用模式：自首次启动 30 天
		var start string
		if err := a.db.QueryRow(`SELECT value FROM settings WHERE key='trial_started_at'`).Scan(&start); err != nil || start == "" {
			start = now.Format(time.RFC3339)
			_, _ = a.db.Exec(`INSERT INTO settings(key, value) VALUES('trial_started_at', ?)`, start)
		}
		t0, _ := time.Parse(time.RFC3339, start)
		deadline := t0.AddDate(0, 0, licenseTrialDays)
		days := int(time.Until(deadline).Hours() / 24)
		status := "trial"
		if days < 0 {
			status = "expired"
		}
		st["status"] = status
		st["edition"] = "trial"
		st["customer"] = "试用模式"
		st["trial_started_at"] = start
		st["trial_deadline"] = deadline.Format("2006-01-02")
		st["days_remaining"] = days
		st["features"] = []string{"全部功能（试用）"}
		return st
	}

	st["lic_id"] = lic.LicID
	st["edition"] = lic.Edition
	st["customer"] = lic.Customer
	st["max_users"] = lic.MaxUsers
	st["max_concurrent"] = lic.MaxConcurrent
	st["max_nodes"] = lic.MaxNodes
	st["features"] = lic.Features
	st["not_before"] = lic.NotBefore

	if lic.ExpiresAt == nil {
		st["status"] = "ok"
		st["expires_at"] = nil
		return st
	}
	exp, err := time.Parse(time.RFC3339, *lic.ExpiresAt)
	if err != nil {
		st["status"] = "ok" // 无法解析的到期时间按永久处理（签发工具保证格式）
		return st
	}
	days := int(time.Until(exp).Hours() / 24)
	st["expires_at"] = *lic.ExpiresAt
	st["days_remaining"] = days
	switch {
	case now.After(exp.AddDate(0, 0, licenseGraceDays)):
		st["status"] = "expired" // 宽限期满：拒新认证/拒建用户，在线不踢
	case now.After(exp):
		st["status"] = "grace" // 宽限期：功能全可用 + 红横幅
	case days <= licenseWarnDays:
		st["status"] = "expiring" // 黄色提醒
	default:
		st["status"] = "ok"
	}
	return st
}

// licenseAllowsNewUser：创建/启用用户控制点（§17.4；expired/grace 满后拒绝）
func (a *App) licenseAllowsNewUser() (bool, string) {
	lic := a.loadInstalledLicense()
	if lic == nil {
		// 试用模式：试用到期即拒绝（同 expired 语义）
		var start string
		if err := a.db.QueryRow(`SELECT value FROM settings WHERE key='trial_started_at'`).Scan(&start); err == nil && start != "" {
			if t0, e := time.Parse(time.RFC3339, start); e == nil {
				if time.Now().After(t0.AddDate(0, 0, licenseTrialDays+licenseGraceDays)) {
					return false, "试用已到期，请导入正式授权"
				}
			}
		}
		return true, ""
	}
	if lic.ExpiresAt != nil {
		if exp, e := time.Parse(time.RFC3339, *lic.ExpiresAt); e == nil {
			if time.Now().After(exp.AddDate(0, 0, licenseGraceDays)) {
				return false, "授权已过期，请联系厂商续费"
			}
		}
	}
	var activeUsers int
	_ = a.db.QueryRow(`SELECT COALESCE(SUM(status='active'),0) FROM users`).Scan(&activeUsers)
	if activeUsers+1 > lic.MaxUsers {
		return false, "授权用户数已达上限，请联系厂商扩容"
	}
	return true, ""
}

// licenseAllowsNewConnection：新连接认证控制点（expired 拒所有认证；并发满拒新连接）
func (a *App) licenseAllowsNewConnection() (bool, string) {
	lic := a.loadInstalledLicense()
	if lic == nil {
		var start string
		if err := a.db.QueryRow(`SELECT value FROM settings WHERE key='trial_started_at'`).Scan(&start); err == nil && start != "" {
			if t0, e := time.Parse(time.RFC3339, start); e == nil {
				if time.Now().After(t0.AddDate(0, 0, licenseTrialDays+licenseGraceDays)) {
					return false, "试用已到期，请联系管理员导入正式授权"
				}
			}
		}
		return true, ""
	}
	if lic.ExpiresAt != nil {
		if exp, e := time.Parse(time.RFC3339, *lic.ExpiresAt); e == nil {
			if time.Now().After(exp.AddDate(0, 0, licenseGraceDays)) {
				return false, "授权已过期，请联系管理员续费"
			}
		}
	}
	if len(liveSessions()) >= lic.MaxConcurrent {
		return false, "并发会话已达授权上限，请稍后重试"
	}
	return true, ""
}

// licensePayloadHasFeature：feature 位检查（纯函数便于单测）。nil payload（试用模式）= 全功能
func licensePayloadHasFeature(p *licensePayload, feature string) bool {
	if p == nil {
		return true // 试用模式：全部功能
	}
	for _, f := range p.Features {
		if strings.EqualFold(strings.TrimSpace(f), feature) {
			return true
		}
	}
	return false
}

// licenseHasFeature：当前生效授权是否包含某 feature（§22.6-8 SAML 门禁用）
func (a *App) licenseHasFeature(feature string) bool {
	return licensePayloadHasFeature(a.loadInstalledLicense(), feature)
}

// handleLicenseGet：管理台 License 页（登录即可见，状态横幅全员需要）
func (a *App) handleLicenseGet(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, a.licenseState())
}

// handleLicensePost：导入 .lic（验签 + 落库 + 即时生效，无需重启 §17.8-6）
func (a *App) handleLicensePost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Raw string `json:"raw"`
	}
	if err := jsonDecode(r, &req); err != nil || strings.TrimSpace(req.Raw) == "" {
		failParam(w, r, "raw（.lic 文件内容）必填")
		return
	}
	p, err := parseLicenseFile(req.Raw)
	if err != nil {
		writeFail(w, r, 20009, http.StatusBadRequest, "授权导入失败："+err.Error())
		return
	}
	// 导入时校验节点数约束（§17.4 HA 节点控制点：超限直接拒绝导入）
	if len(nodes) > p.MaxNodes {
		writeFail(w, r, 20009, http.StatusBadRequest,
			fmt.Sprintf("授权 max_nodes=%d 小于当前集群节点数 %d", p.MaxNodes, len(nodes)))
		return
	}
	_, err = a.db.Exec(`INSERT INTO license(payload, signature, raw, installed_by) VALUES(?,?,?,?)`,
		req.Raw, "", req.Raw, claimsOf(r).Username)
	if err != nil {
		failSystem(w, r, "授权落库失败")
		return
	}
	licenseMu.Lock()
	licenseCache = p
	licenseMu.Unlock()
	writeOK(w, r, a.licenseState())
}
