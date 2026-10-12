package main

// 内存状态与持久化令牌库（对齐 Python AUTH_REQUESTS/CODES/WEB_SESS/SAML_ASSERTION_SEEN
// 与 /opt/modsafe/oidc-refresh.json；语义逐条对应：TTL、一次性消费、顺带清扫、原子落盘）

import (
	"log"
	"sync"
	"time"
)

var (
	mu            sync.Mutex
	authRequests  = map[string]map[string]any{} // internal_state -> req
	codes         = map[string]map[string]any{} // code -> rec
	samlAssertion = map[string]int64{}          // 断言 ID -> exp（5min 重放窗口）

	webSessMu sync.Mutex
	webSess   = map[string]webSessRec{} // cookie_id -> {userinfo, exp}
)

type webSessRec struct {
	UserInfo map[string]any `json:"userinfo"`
	Exp      float64        `json:"exp"`
}

func authRequestPut(state string, req map[string]any) {
	now := float64(nowUnix())
	mu.Lock()
	for k, v := range authRequests {
		if vf, _ := v["exp"].(float64); vf < now {
			delete(authRequests, k)
		}
	}
	for k, v := range codes {
		if vf, _ := v["exp"].(float64); vf < now {
			delete(codes, k)
		}
	}
	authRequests[state] = req
	mu.Unlock()
}

func authRequestGet(state string) map[string]any {
	mu.Lock()
	defer mu.Unlock()
	r := authRequests[state]
	if r == nil {
		return nil
	}
	cp := map[string]any{}
	for k, v := range r {
		cp[k] = v
	}
	return cp
}

func authRequestPop(state string) map[string]any {
	mu.Lock()
	defer mu.Unlock()
	r := authRequests[state]
	delete(authRequests, state)
	return r
}

func codesPop(code string) map[string]any {
	mu.Lock()
	defer mu.Unlock()
	r := codes[code]
	delete(codes, code)
	return r
}

func codesPut(code string, rec map[string]any) {
	mu.Lock()
	codes[code] = rec
	mu.Unlock()
}

// ---- 浏览器免扫码会话（§25 阶段1；TTL 8h，0=禁用不种） ----

func webSessSave(userinfo map[string]any) string {
	if WEB_SESS_HOURS <= 0 {
		return ""
	}
	cid := randToken(24)
	now := float64(time.Now().UnixNano()) / 1e9
	webSessMu.Lock()
	for k, v := range webSess {
		if v.Exp < now {
			delete(webSess, k)
		}
	}
	cp := map[string]any{}
	for k, v := range userinfo {
		cp[k] = v
	}
	webSess[cid] = webSessRec{UserInfo: cp, Exp: now + WEB_SESS_HOURS*3600}
	webSessMu.Unlock()
	return cid
}

func webSessLoad(cookieHeader string) map[string]any {
	if WEB_SESS_HOURS <= 0 {
		return nil
	}
	cid := cookieValue(cookieHeader, "modsafe_web_sess")
	if cid == "" {
		return nil
	}
	now := float64(time.Now().UnixNano()) / 1e9
	webSessMu.Lock()
	defer webSessMu.Unlock()
	rec := webSess[cid]
	if rec.UserInfo == nil || rec.Exp < now {
		delete(webSess, cid)
		return nil
	}
	cp := map[string]any{}
	for k, v := range rec.UserInfo {
		cp[k] = v
	}
	return cp
}

func webSessDrop(cookieHeader string) {
	cid := cookieValue(cookieHeader, "modsafe_web_sess")
	if cid == "" {
		return
	}
	webSessMu.Lock()
	delete(webSess, cid)
	webSessMu.Unlock()
}

// ---- IdP refresh token 库（随机一次性令牌 → 轮转；2026-09-29 防伪造修复的同款语义） ----

var rtMu sync.Mutex

func rtIssue(sub, provider, refreshToken string) string {
	token := randToken(32)
	rtMu.Lock()
	defer rtMu.Unlock()
	store, ok := loadJSONFile(REFRESH_STORE)
	if !ok {
		store = map[string]any{}
	}
	now := float64(nowUnix())
	clean := map[string]any{}
	for k, v := range store {
		if rec, ok := v.(map[string]any); ok {
			if ef, _ := rec["exp"].(float64); ef > now {
				clean[k] = v
			}
		}
	}
	clean[token] = map[string]any{
		"sub": sub, "provider": provider, "refresh_token": refreshToken,
		"exp": now + 86400*30,
	}
	if err := saveJSONAtomic(REFRESH_STORE, clean, 0o600); err != nil {
		log.Printf("[adapter] refresh store write: %v", err)
	}
	return token
}

func rtConsume(token string) map[string]any {
	rtMu.Lock()
	defer rtMu.Unlock()
	store, ok := loadJSONFile(REFRESH_STORE)
	if !ok {
		return nil
	}
	rec, _ := store[token].(map[string]any)
	delete(store, token) // 一次性消费
	if rec == nil {
		return nil
	}
	if ef, _ := rec["exp"].(float64); ef <= float64(nowUnix()) {
		_ = saveJSONAtomic(REFRESH_STORE, store, 0o600)
		return nil
	}
	_ = saveJSONAtomic(REFRESH_STORE, store, 0o600)
	return rec
}

// ---- SAML 断言 ID 去重（5 分钟窗口，顺带清扫） ----

func samlAssertionSeen(aid string) bool {
	now := nowUnix()
	mu.Lock()
	defer mu.Unlock()
	for k, exp := range samlAssertion {
		if exp < now {
			delete(samlAssertion, k)
		}
	}
	if _, dup := samlAssertion[aid]; dup {
		return true
	}
	samlAssertion[aid] = now + 300
	return false
}

func logf(format string, args ...any) {
	log.Printf(format, args...)
}
