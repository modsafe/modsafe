package main

// /token：标准 OIDC token endpoint（RS256 id_token，PKCE S256，refresh 轮转）

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func issueIDToken(clientID string, claims map[string]any) (string, error) {
	now := time.Now().Unix()
	std := jwt.MapClaims{
		"iss": ISSUER, "sub": claims["sub"], "aud": clientID,
		"iat": now, "exp": now + 3600,
		"name": claims["name"], "preferred_username": claims["name"],
		"email":    claims["email"],
		"cert_cns": claims["_cert_cns"],
	}
	if p, ok := claims["provider"].(string); ok && p != "" {
		std["provider"] = p
	}
	if n, ok := claims["nonce"].(string); ok && n != "" {
		std["nonce"] = n
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, std)
	tok.Header["kid"] = "modsafe-idp-1"
	return tok.SignedString(rsaKey)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	body := parseForm(readBody(r))
	grantType := body.Get("grant_type")
	code := body.Get("code")
	clientID := body.Get("client_id")
	clientSecret := body.Get("client_secret")
	codeVerifier := body.Get("code_verifier")
	refreshToken := body.Get("refresh_token")

	if clientID == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Basic ") {
			if raw, err := base64.StdEncoding.DecodeString(auth[6:]); err == nil {
				if cid, csec, ok := strings.Cut(string(raw), ":"); ok {
					clientID, clientSecret = cid, csec
				}
			}
		}
	}

	if grantType == "refresh_token" {
		if clientID != OA2_CLIENT_ID || clientSecret != OA2_CLIENT_SEC {
			writeJSON(w, 401, map[string]any{"error": "invalid_client"})
			return
		}
		rec := rtConsume(refreshToken) // 一次性赎回（轮转制）
		if rec == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant",
				"error_description": "silent reauth unavailable"})
			return
		}
		if mStr(rec, "provider") != "dingtalk" || mStr(idpc()["dingtalk"], "client_id") == "" {
			// 飞书/企微/LDAP 暂不支持静默重认证
			writeJSON(w, 400, map[string]any{"error": "invalid_grant",
				"error_description": "provider unsupported for silent reauth"})
			return
		}
		c := idpc()["dingtalk"]
		resp, err := httpJSON("https://api.dingtalk.com/v1.0/oauth2/userAccessToken", "POST",
			map[string]string{"Content-Type": "application/json"},
			map[string]any{"clientId": mStr(c, "client_id"), "clientSecret": mStr(c, "client_secret"),
				"refreshToken": mStr(rec, "refresh_token"), "grantType": "refresh_token"},
			15*time.Second)
		if err != nil {
			logf("refresh reauth failed: %v", err)
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": truncateStr(err.Error(), 120)})
			return
		}
		at := mStr(resp, "accessToken")
		info, err := httpJSON("https://api.dingtalk.com/v1.0/contact/users/me", "GET",
			map[string]string{"x-acs-dingtalk-access-token": at}, nil, 15*time.Second)
		if err != nil {
			logf("refresh reauth failed: %v", err)
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": truncateStr(err.Error(), 120)})
			return
		}
		claims := map[string]any{
			"sub":   firstNonEmpty(mStr(info, "unionId"), mStr(info, "openId")),
			"name":  firstNonEmpty(mStr(info, "nick"), "unknown"),
			"email": mStr(info, "email"),
		}
		// #61：refresh 重认证同样反查控制面（禁用拦截 + cert_cns——strict 模式 oa2 CEL 校验需要）
		allow, ck := cpAuthCheck("dingtalk", "", claims)
		if !allow {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant",
				"error_description": firstNonEmpty(mStr(ck, "reason"), "账号已被禁用")})
			return
		}
		claims["_cert_cns"] = ck["cert_cns"]
		newRT := rtIssue(uiStr(claims, "sub"), "dingtalk",
			firstNonEmpty(mStr(resp, "refreshToken"), mStr(rec, "refresh_token")))
		it, err := issueIDToken(clientID, claims)
		if err != nil {
			logf("refresh reauth failed: %v", err)
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "reauth failed"})
			return
		}
		logf("refresh reauth ok: sub=%s name=%s", truncateStr(uiStr(claims, "sub"), 24), uiStr(claims, "name"))
		writeJSON(w, 200, map[string]any{
			"access_token": randToken(32), "token_type": "Bearer", "expires_in": 3600,
			"id_token": it, "scope": "openid profile email", "refresh_token": newRT,
		})
		return
	}

	if grantType != "authorization_code" {
		writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	if clientID != OA2_CLIENT_ID || clientSecret != OA2_CLIENT_SEC {
		writeJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}
	rec := codesPop(code)
	if rec == nil || expired(rec) {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant",
			"error_description": "code invalid or expired"})
		return
	}
	if ch := mStr(rec, "code_challenge"); ch != "" {
		if pkceS256(codeVerifier) != ch {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant",
				"error_description": "PKCE verification failed"})
			return
		}
	}
	it, err := issueIDToken(clientID, rec)
	if err != nil {
		logf("token issue failed: %v", err)
		writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "token issue failed"})
		return
	}
	logf("token issued: provider=%s sub=%s name=%s", mStr(rec, "provider"), truncateStr(mStr(rec, "sub"), 24), mStr(rec, "name"))
	resp := map[string]any{
		"access_token": randToken(32), "token_type": "Bearer", "expires_in": 3600,
		"id_token": it, "scope": "openid profile email",
	}
	if crt := mStr(rec, "_client_rt"); crt != "" {
		resp["refresh_token"] = crt // 登录时签发的随机轮转令牌
	}
	writeJSON(w, 200, resp)
}

func expired(rec map[string]any) bool {
	exp, _ := rec["exp"].(float64)
	return exp < float64(nowUnix())
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
