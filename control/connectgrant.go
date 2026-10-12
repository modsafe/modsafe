package main

// 网页一键连接一次性 ticket（B 方案）：门户自助签发配置时随下载 token 一起签发，
// 自家客户端打开验证页时作为 grant 参数回传，adapter 反查本端点核销换身份静默发码。
// 安全属性：仅门户已登录会话（密码+TOTP 已验证）可签发、TTL 300s、单次核销。
// 内存态即可——5 分钟临时物，控制面重启丢失的后果只是该窗口内退化为要求验证一次。

import (
	"database/sql"
	"log"
	"net/http"
	"sync"
	"time"
)

type connectGrantRec struct {
	userID    int64
	expiresAt time.Time
}

var (
	cgMu      sync.Mutex
	cgTickets = map[string]connectGrantRec{}
)

// issueConnectGrant：为门户自助用户签发一次性 ticket（与下载 token 同 TTL，顺带清扫过期项）
func issueConnectGrant(userID int64) string {
	ticket := randomToken(32)
	cgMu.Lock()
	now := time.Now()
	for k, v := range cgTickets {
		if now.After(v.expiresAt) {
			delete(cgTickets, k)
		}
	}
	cgTickets[ticket] = connectGrantRec{userID: userID, expiresAt: now.Add(5 * time.Minute)}
	cgMu.Unlock()
	return ticket
}

// consumeConnectGrant：原子核销（先删后查，一次性——无论后续用户校验成败都不再可用）。
// 返回用户 id；nil 表示 ticket 无效/过期。
func consumeConnectGrant(ticket string) *connectGrantRec {
	if ticket == "" {
		return nil
	}
	cgMu.Lock()
	g, ok := cgTickets[ticket]
	if ok {
		delete(cgTickets, ticket)
	}
	cgMu.Unlock()
	if !ok || time.Now().After(g.expiresAt) {
		return nil
	}
	return &g
}

// handleInternalConnectGrant：GET /api/v1/internal/connect-grant?g=<ticket>
// adapter 静默发码前反查；返回与 portal-whoami 同构的身份（sub 三级推导同款，
// 保证 auth-check 三级匹配与现有静默链路完全一致）。无效/过期/用户不可用 → 404。
func (a *App) handleInternalConnectGrant(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	ticket := r.URL.Query().Get("g")
	if ticket == "" {
		failParam(w, r, "g 必填")
		return
	}
	g := consumeConnectGrant(ticket)
	if g == nil {
		writeFail(w, r, 30001, http.StatusNotFound, "ticket invalid or expired")
		return
	}
	var username, display, unionID, extID, source, status string
	err := a.db.QueryRow(`SELECT username, COALESCE(display_name,''), COALESCE(union_id,''),
		COALESCE(external_id,''), source, status FROM users WHERE id=?`, g.userID).
		Scan(&username, &display, &unionID, &extID, &source, &status)
	if err == sql.ErrNoRows || (err == nil && status != "active") {
		// ticket 已核销（不可重放），用户侧禁用属 deny 语义——登录审计由 auth-check 统一承担
		writeFail(w, r, 30001, http.StatusNotFound, "user unavailable")
		return
	}
	if err != nil {
		failSystem(w, r, fmtErr("connect-grant query", err))
		return
	}
	sub := unionID
	if sub == "" {
		sub = extID
	}
	if sub == "" {
		sub = "local-" + username
	}
	log.Printf("[connect-grant] consumed for user %s (source=%s)", username, source)
	writeOK(w, r, map[string]interface{}{
		"uid": g.userID, "username": username, "display_name": display,
		"sub": sub, "provider": source,
	})
}
