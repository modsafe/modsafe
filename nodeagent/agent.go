package main

// agent 角色：modsafe-healthz.service / node-agent v4 的 Go 移植（193, :7503）。
// 端点：GET /healthz /metrics /sessions /flows /dnslog；POST /ccd /kick /authtoken
// /crypto /cert-binding /crl /fwd-rules /ipv6 /apply/network。
// 鉴权：X-Admin-Token 头或 body token，与 /opt/modsafe/admin-token 比对。

import (
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func agentAuthed(r *http.Request, bodyToken string) bool {
	tok := r.Header.Get("X-Admin-Token")
	if tok == "" {
		tok = bodyToken
	}
	want := readToken()
	return want != "" && tok == want
}

func agentJSONBody(r *http.Request) map[string]any {
	raw := readBodyLimited(r, 1<<20)
	var body map[string]any
	if jsonUnmarshal(raw, &body) != nil || body == nil {
		return nil
	}
	return body
}

func runAgent() {
	NOTIFY_ALLOW_PRIV = os.Getenv("MODSAFE_NOTIFY_ALLOW_PRIVATE") == "1"
	logf("modsafe node-agent (Go) starting on :7503")
	// SIGTERM/SIGINT 兜底：mgmt 窗口内被 systemctl stop/restart 时进程直接退出、
	// mgmtWindow 的 defer 不执行，oa2 停止后无人回启=认证门户宕机——窗口活跃则先回启再退出
	//（SIGKILL/进程崩溃无法捕获，仍需 systemd 层或人工恢复）
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
		<-ch
		if mgmtWinOpen.Load() {
			_ = svcStart(oa2Service)
		}
		os.Exit(0)
	}()
	srv := &http.Server{
		Addr:              ":7503",
		Handler:           agentMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		logf("listen: %v", err)
	}
}

func agentMux() *http.ServeMux {
	mux := http.NewServeMux()

	// ---- GET ----
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		st := svcActive(nodeService)
		code := 200
		if st != "active" {
			code = 503
		}
		writeJSON(w, code, map[string]any{"service": st})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		st := svcActive(nodeService)
		m := statusSummary()
		m["service"] = st
		// #166：本机 dnsmasq 活性暴露给 collector 远端告警（不影响 /healthz——watchdog
		// 按 openvpn 判活摘流量，DNS 故障不该摘 RS）
		m["dns"] = svcActive("dnsmasq")
		code := 200
		if st != "active" {
			code = 503
		}
		writeJSON(w, code, m)
	})
	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		st := svcActive(nodeService)
		m := statusSummary()
		code := 200
		if st != "active" {
			code = 503
		}
		writeJSON(w, code, map[string]any{"service": st, "sessions": m["sessions"]})
	})
	mux.HandleFunc("GET /flows", func(w http.ResponseWriter, r *http.Request) {
		// 流量审计（#70）：/proc/net/nf_conntrack → VPN 源活跃流（GET+X-Admin-Token 头）
		if !agentAuthed(r, "") {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		raw, err := os.ReadFile("/proc/net/nf_conntrack")
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "nf_conntrack unreadable: " + err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"flows": parseFlows(string(raw))})
	})
	mux.HandleFunc("GET /dnslog", func(w http.ResponseWriter, r *http.Request) {
		// 域名维度（#71）：tail dnsmasq 查询日志原文（解析在控制面）；token 可走 query
		qtok := ""
		if i := strings.Index(r.URL.RawQuery, "token="); i >= 0 {
			qtok = r.URL.RawQuery[i+len("token="):]
			if j := strings.Index(qtok, "&"); j >= 0 {
				qtok = qtok[:j]
			}
		}
		if !agentAuthed(r, qtok) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		n := 400
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				n = parsed
			}
		}
		if n < 50 {
			n = 50
		}
		if n > 2000 {
			n = 2000
		}
		raw, err := os.ReadFile(dnsmasqLog)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "dnsmasq log unreadable: " + err.Error()})
			return
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		writeJSON(w, 200, map[string]any{"lines": lines})
	})

	// ---- POST ----
	mux.HandleFunc("POST /ccd", func(w http.ResponseWriter, r *http.Request) {
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		fname := strings.TrimSpace(mStr(body, "filename"))
		if !strings.HasSuffix(fname, ".conf") || strings.Contains(fname, "/") ||
			strings.Contains(fname, "..") {
			writeJSON(w, 400, map[string]any{"error": "filename 必须为 xxx.conf"})
			return
		}
		target := filepath.Join(ccdDir, fname)
		if mBool(body, "delete") {
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				writeJSON(w, 500, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, "action": "deleted"})
			return
		}
		tmp := target + ".tmp"
		if err := os.WriteFile(tmp, []byte(mStr(body, "content")), 0o644); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		if err := os.Rename(tmp, target); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "action": "written"})
	})
	mux.HandleFunc("POST /kick", func(w http.ResponseWriter, r *http.Request) {
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		username := strings.TrimSpace(mStr(body, "username"))
		commonName := strings.TrimSpace(mStr(body, "common_name"))
		virtualIP := strings.TrimSpace(mStr(body, "virtual_ip"))
		killAll := mBool(body, "all")
		if username == "" && commonName == "" && virtualIP == "" && !killAll {
			writeJSON(w, 400, map[string]any{"error": "username / common_name / virtual_ip / all 必填其一"})
			return
		}
		result := mgmtKill(username, commonName, virtualIP, killAll)
		code := 500
		if mBool(result, "ok") {
			code = 200
		}
		writeJSON(w, code, result)
	})
	mux.HandleFunc("POST /authtoken", func(w http.ResponseWriter, r *http.Request) {
		// 免扫码时长（auth-gen-token lifetime）下发：改 conf + 重启节点（PartOf 联动 oa2）
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		minutes := mInt(body, "minutes")
		code, out := applyAuthToken(minutes)
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /crypto", func(w http.ResponseWriter, r *http.Request) {
		// 加密套件下发（国密/标准切换）：改 data-ciphers/auth 行 + 重启节点
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		code, out := applyCrypto(mStr(body, "ciphers"), mStr(body, "auth"))
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /cert-binding", func(w http.ResponseWriter, r *http.Request) {
		// 证书身份绑定下发（#61）：verify-client-cert/crl-verify 改写 + oa2 CEL drop-in + 双重启
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		code, out := applyCertBinding(mBool(body, "strict"), mStr(body, "crl"))
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /crl", func(w http.ResponseWriter, r *http.Request) {
		// CRL 单独下发（吊销设备后即时更新，不动 conf/服务）
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		code, out := applyCRL(mStr(body, "crl"))
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /fwd-rules", func(w http.ResponseWriter, r *http.Request) {
		// 服务端路由强制：FORWARD 白名单（授权网段并集）下发
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		cidrs, _ := body["cidrs"].([]any)
		dns, _ := body["dns"].([]any)
		if body["cidrs"] != nil && cidrs == nil || body["dns"] != nil && dns == nil {
			writeJSON(w, 400, map[string]any{"error": "cidrs/dns 必须为数组"})
			return
		}
		code, out := applyFwdRules(cidrs, dns, mBool(body, "allow_all"))
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /ipv6", func(w http.ResponseWriter, r *http.Request) {
		// IPv6 隧道开关下发（#80）：node-2 conf 增删 server-ipv6 行 + 重启
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		v6net := strings.TrimSpace(mStr(body, "v6net"))
		if v6net == "" {
			v6net = "fdaa:2026:192:2::/64"
		}
		code, out := applyIPv6(mBool(body, "enable"), v6net)
		writeJSON(w, code, out)
	})
	mux.HandleFunc("POST /apply/network", func(w http.ResponseWriter, r *http.Request) {
		body := agentJSONBody(r)
		if body == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if !agentAuthed(r, mStr(body, "token")) {
			writeJSON(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		code, out := applyNetworkAgent(mStr(body, "cidr_block"))
		writeJSON(w, code, out)
	})

	// 兜底
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"error": "not found"})
	})
	return mux
}

var _ net.Conn // 保留 net 引用（mgmt 窗口在 agent_status.go）
