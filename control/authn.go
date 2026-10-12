package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// dbTimeout：关键路径查询上限，防单条 syscall 挂死拖垮认证
const dbTimeout = 8 * time.Second

// dummyBcryptHash：用户不存在路径的时序对齐用固定哈希（bcrypt("modsafe-dummy")）
var dummyBcryptHash = func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("modsafe-dummy"), bcrypt.DefaultCost)
	return string(h)
}()

// ── JWT（HS256；secret 首次生成后持久化，重启不失效）──

func jwtSecret() []byte {
	dataDir := envOr("MODSAFE_DATA_DIR", "data")
	path := filepath.Join(dataDir, "jwt_secret")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		panic(err)
	}
	return b
}

type adminClaims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

func signToken(username string, roles []string) (string, error) {
	claims := adminClaims{
		Username: username, Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "modsafe-control",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret())
}

func parseToken(tokenStr string) (*adminClaims, error) {
	claims := &adminClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret(), nil
	})
	return claims, err
}

// ── 中间件 ──

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeFail(w, r, 30001, http.StatusUnauthorized, "未登录")
			return
		}
		claims, err := parseToken(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			writeFail(w, r, 30001, http.StatusUnauthorized, "登录已过期")
			return
		}
		// §16.4 垂直越权隔离：门户 JWT（aud=portal）不能打通管理台 API
		if len(claims.Audience) > 0 {
			writeFail(w, r, 30001, http.StatusUnauthorized, "未登录")
			return
		}
		next(w, r.WithContext(withClaims(r, claims)))
	}
}

// requireRoles：空列表 = 任意已登录管理员；仅 auditor 角色的账号对写操作一律 30002（§12.3 三权分立）
func (a *App) requireRoles(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c := claimsOf(r)
			if len(roles) > 0 && !hasAnyRole(c.Roles, roles...) {
				writeFail(w, r, 30002, http.StatusForbidden, "无权限执行此操作")
				return
			}
			if isWriteMethod(r.Method) && hasAnyRole(c.Roles, "auditor") && len(c.Roles) == 1 {
				writeFail(w, r, 30002, http.StatusForbidden, "审计员为只读角色")
				return
			}
			if isWriteMethod(r.Method) {
				a.auditAdminWrite(r, c) // 写操作审计钩子（§19.9 管理操作审计）
			}
			next(w, r)
		}
	}
}

func isWriteMethod(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodDelete || m == http.MethodPatch
}

func hasAnyRole(roles []string, wants ...string) bool {
	for _, r := range roles {
		for _, w := range wants {
			if r == w {
				return true
			}
		}
	}
	return false
}

// ── handlers ──

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Username == "" || req.Password == "" {
		failParam(w, r, "用户名和密码不能为空")
		return
	}
	// 暴破限速：同 IP 5 分钟内最多 10 次尝试（无锁定回溯，窗口自然过期）
	if !loginLimiter.allow("admin|"+remoteIP(r)) {
		writeFail(w, r, 30005, http.StatusTooManyRequests, "尝试过于频繁，请 5 分钟后重试")
		return
	}
	var id int64
	var hash string
	var mustChange int
	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()
	err := a.db.QueryRowContext(ctx, `SELECT id, password_hash, must_change_password FROM admins WHERE username=?`,
		req.Username).Scan(&id, &hash, &mustChange)
	if err == sql.ErrNoRows {
		// 时序对齐：对固定 dummy hash 走一次 bcrypt，消除"用户名是否存在"的响应时间差
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(req.Password))
		a.auditLogin(r, req.Username, "local", "fail", "用户不存在")
		writeFail(w, r, 30004, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	if err != nil {
		failSystem(w, r, "查询管理员失败")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		a.auditLogin(r, req.Username, "local", "fail", "密码错误")
		writeFail(w, r, 30004, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	// P1-e TOTP：已绑定账号必须携带有效 6 位码（错码与密码错误同语义，走同一限速+审计）
	var totpEnabled int
	_ = a.db.QueryRowContext(ctx, `SELECT COALESCE(totp_enabled,0) FROM admins WHERE username=?`,
		req.Username).Scan(&totpEnabled)
	if totpEnabled == 1 {
		_, totpSecret := a.adminTotpState(req.Username)
		if !totpVerifySecret(totpSecret, r.Header.Get("X-TOTP-Code")) {
			a.auditLogin(r, req.Username, "local", "fail", "TOTP 验证码错误")
			writeFail(w, r, 30004, http.StatusUnauthorized, "需要有效的动态验证码（X-TOTP-Code）")
			return
		}
	}
	// #109 系统级强制：未绑定者发"仅可绑定"限定 token（roles 空，只能走 TOTP 绑定闭环）
	if totpEnabled == 0 && getSetting(a, "totp_enforced", "0") == "1" {
		token, err := signToken(req.Username, []string{})
		if err != nil {
			failSystem(w, r, "签发会话失败")
			return
		}
		a.auditLogin(r, req.Username, "local", "success", "totp-enroll-required")
		writeOK(w, r, map[string]interface{}{
			"token":                token,
			"user":                 map[string]interface{}{"id": id, "username": req.Username, "roles": []string{}},
			"must_change_password": mustChange == 1,
			"totp_enroll":          true,
		})
		return
	}
	roles := jsonDecodeStringSlice(mustQueryRow(a.db, `SELECT roles FROM admins WHERE username=?`, req.Username))
	token, err := signToken(req.Username, roles)
	if err != nil {
		failSystem(w, r, "签发会话失败")
		return
	}
	a.auditLogin(r, req.Username, "local", "success", "")
	writeOK(w, r, map[string]interface{}{
		"token":                token,
		"user":                 map[string]interface{}{"id": id, "username": req.Username, "roles": roles},
		"must_change_password": mustChange == 1,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, nil) // 无状态 JWT：登出即客户端清除
}

// handleChangePassword：管理员改自己的密码（requireAuth 即可——任何角色都可改自己）。
// 审计手动落 audit_admin 月表（requireAuth 不经过 requireRoles 的写钩子）；审计不记密码本体。
func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	c := claimsOf(r)
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := jsonDecode(r, &req); err != nil || req.OldPassword == "" || req.NewPassword == "" {
		failParam(w, r, "旧密码和新密码不能为空")
		return
	}
	if len([]rune(req.NewPassword)) < 8 {
		failParam(w, r, "新密码长度不能少于 8 位")
		return
	}
	if req.NewPassword == req.OldPassword {
		failParam(w, r, "新密码不能与旧密码相同")
		return
	}
	var hash string
	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()
	err := a.db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE username=?`, c.Username).Scan(&hash)
	if err == sql.ErrNoRows || (err == nil && bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil) {
		writeFail(w, r, 30004, http.StatusBadRequest, "旧密码不正确")
		return
	}
	if err != nil {
		failSystem(w, r, "查询管理员失败")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		failSystem(w, r, "密码加密失败")
		return
	}
	if _, err := a.db.Exec(`UPDATE admins SET password_hash=?, must_change_password=0 WHERE username=?`,
		string(newHash), c.Username); err != nil {
		failSystem(w, r, fmtErr("change password", err))
		return
	}
	a.auditAdminAction(r, c.Username, "POST", "/api/v1/auth/change-password", "success", "")
	writeOK(w, r, map[string]interface{}{"changed": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	c := claimsOf(r)
	writeOK(w, r, map[string]interface{}{"id": 0, "username": c.Username, "roles": c.Roles})
}

func (a *App) auditLogin(r *http.Request, username, source, result, reason string) {
	table := auditTable(time.Now())
	ensureAuditTable(a.db, table)
	_, _ = a.db.Exec(`INSERT INTO `+table+`(username, idp_source, result, reason, trusted_ip, trace_id) VALUES(?,?,?,?,?,?)`,
		username, source, result, reason, remoteIP(r), traceID(r))
}

func mustQueryRow(db *sql.DB, q string, args ...interface{}) string {
	var s string
	_ = db.QueryRow(q, args...).Scan(&s)
	return s
}
