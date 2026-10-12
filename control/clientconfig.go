package main

// §15 API：POST /users/{id}/client-config（签发+设备登记+一次性token）
//       GET  /client-config/{token}（.ovpn 文件流，token 5 分钟单次核销）
// 设备证书 PEM 存 devices 表（下载时直接取，不重复签发）

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dlGrant struct {
	userID    int64
	deviceID  int64
	filename  string
	expiresAt time.Time
}

var (
	dlMu     sync.Mutex
	dlTokens = map[string]dlGrant{}
)

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dlTokenRe：一次性下载 token 形态门禁（randomToken(32) → 64 位 hex）
var dlTokenRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// issueClientConfigForUser：§15 六步核心（同名设备复用 → 签发/登记 → 一次性 token）。
// 管理台（/users/:id/client-config）与自助门户（/self/devices/client-config）共用。
// 2026-09-30 起同名复用：同用户已存在同名 active 设备时直接对其重发下载 token，
// 不再新建证书/设备行——网页一键连接的重复点击不再堆积设备与客户端配置文件。
func (a *App) issueClientConfigForUser(id int64, deviceName, platform string) (token string, errCode int, errMsg string) {
	var username string
	var quota int
	err := a.db.QueryRow(`SELECT username, device_quota FROM users WHERE id=? AND status='active'`, id).
		Scan(&username, &quota)
	if err != nil {
		return "", 20001, "用户不存在或已禁用"
	}
	// 设备名白名单（自助入口用户可控，防响应头/文件内容注入；与 profile 命名规则一致）
	deviceName = sanitizeDeviceName(deviceName)
	platform = sanitizeDeviceName(platform)
	if deviceName == "" {
		// 稳定默认名（按用户+平台）：不填设备名的重复点击走同名复用，不再产生
		// 时间戳设备（device-0930-1500 每分钟不同曾致设备无限增长，2026-09-30 修复）
		plat := strings.Trim(platform, "_-.")
		if plat == "" {
			plat = "pc"
		}
		deviceName = fmt.Sprintf("u%d-%s", id, plat)
	}
	filename := username + "-" + deviceName + ".ovpn"

	// 同名复用：命中即重发 token（下载时 renderOVPN 按当前套件渲染，证书不变）
	var existID int64
	if err := a.db.QueryRow(`SELECT id FROM devices WHERE user_id=? AND device_name=? AND status='active'
		ORDER BY id DESC LIMIT 1`, id, deviceName).Scan(&existID); err == nil {
		return a.grantDownload(id, existID, filename)
	}

	certPEM, keyPEM, fp, err := signClientCert(username)
	if err != nil {
		return "", 50001, "证书签发失败: " + err.Error()
	}
	// 配额原子化：INSERT ... SELECT 条件插入，杜绝 check-then-insert 并发突破
	//（门户自助双击曾可超配额领设备，2026-09-29 修复）
	res, err := a.db.Exec(`INSERT INTO devices(user_id, cert_cn, fingerprint, platform, device_name, status, cert_pem, key_pem)
		SELECT ?,?,?,?,?, 'active', ?, ?
		WHERE (SELECT COUNT(*) FROM devices WHERE user_id=? AND status='active') < ?`,
		id, username, fp, platform, deviceName, certPEM, keyPEM, id, quota)
	if err != nil {
		return "", 50001, "设备登记失败"
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var used int
		_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND status='active'`, id).Scan(&used)
		return "", 20002, fmt.Sprintf("设备配额已满（%d/%d），请先停用旧设备", used, quota)
	}
	devID, _ := res.LastInsertId()
	return a.grantDownload(id, devID, filename)
}

// grantDownload：为已有设备签发一次性下载 token（顺带回收过期未核销 token）
func (a *App) grantDownload(userID, deviceID int64, filename string) (string, int, string) {
	token := randomToken(32)
	dlMu.Lock()
	now := time.Now()
	for k, v := range dlTokens {
		if now.After(v.expiresAt) {
			delete(dlTokens, k)
		}
	}
	dlTokens[token] = dlGrant{userID: userID, deviceID: deviceID,
		filename: filename, expiresAt: now.Add(5 * time.Minute)}
	dlMu.Unlock()
	return token, 0, ""
}

// sanitizeDeviceName：设备/平台名白名单（字母数字及 _-.，其余转 _，长度≤40）
func sanitizeDeviceName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(s))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func (a *App) handleClientConfigGen(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
	}
	_ = jsonDecode(r, &req)
	token, code, msg := a.issueClientConfigForUser(id, req.DeviceName, req.Platform)
	if code != 0 {
		writeFail(w, r, code, http.StatusBadRequest, msg)
		return
	}
	var fp string
	_ = a.db.QueryRow(`SELECT fingerprint FROM devices WHERE user_id=? ORDER BY id DESC LIMIT 1`, id).Scan(&fp)
	writeOK(w, r, map[string]interface{}{
		"download_token": token, "expires_in": 300, "fingerprint": fp,
	})
}

// handleClientConfigDownload：token 单次核销 → .ovpn 文件流（无 envelope，浏览器直接下载）
func (a *App) handleClientConfigDownload(w http.ResponseWriter, r *http.Request) {
	a.clientConfigDownload(w, r, r.PathValue("token"), r.URL.Query().Get("fmt"))
}

// handleClientConfigDownloadByBody：固定路由形态（请求体传 token/fmt），与 GET
// /client-config/{token} 同逻辑同一次性核销语义；供门户固定端点调用（客户端不拼接动态路径）
func (a *App) handleClientConfigDownloadByBody(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Fmt   string `json:"fmt"`
	}
	if err := jsonDecode(r, &req); err != nil || !dlTokenRe.MatchString(req.Token) {
		writeFail(w, r, 20009, http.StatusGone, "下载链接已失效，请重新生成")
		return
	}
	a.clientConfigDownload(w, r, req.Token, req.Fmt)
}

func (a *App) clientConfigDownload(w http.ResponseWriter, r *http.Request, token, fmtParam string) {
	dlMu.Lock()
	g, ok := dlTokens[token]
	if ok {
		delete(dlTokens, token)
	}
	dlMu.Unlock()
	if !ok {
		writeFail(w, r, 20009, http.StatusGone, "下载链接已失效，请重新生成")
		return
	}
	if time.Now().After(g.expiresAt) {
		writeFail(w, r, 20009, http.StatusGone, "下载链接已过期")
		return
	}
	var certStored, keyStored string
	err := a.db.QueryRow(`SELECT cert_pem, key_pem FROM devices WHERE id=? AND status='active'`, g.deviceID).
		Scan(&certStored, &keyStored)
	if err != nil || certStored == "" {
		failSystem(w, r, "设备证书缺失")
		return
	}
	ovpn, err := a.renderOVPN(g.filename, certStored, keyStored)
	if err != nil {
		log.Printf("[ovpn] 渲染失败 %s: %v", g.filename, err)
		failSystem(w, r, "配置渲染失败（"+err.Error()+"）")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDisposition(g.filename))
	// macOS Tunnelblick（#161/#165）：.modsafe/auth-user.txt 文件引用无法随裸 .ovpn
	// 提供（Tunnelblick 导入校验会拒绝引用外部文件），替换为裸 auth-user-pass =
	// 连接时交互输入（用户名=本人姓名保证会话归属，密码随意可存钥匙串，重连走
	// auth-gen-token）。注意必须是【替换成裸行】而不是删除整行：服务端
	// management-client-auth 模式下，客户端必须在握手里发送 user/pass，OpenVPN
	// 才会把认证交给 oa2 走 webauth/pending 流程——删行=握手期被核心直接拒绝
	//（2026-10-11 Mac tls-error「Auth Username/Password was not provided by peer」实锤）。
	if fmtParam == "tunnelblick" {
		var kept []string
		for _, line := range strings.Split(ovpn, "\n") {
			if strings.HasPrefix(line, "auth-user-pass ") {
				kept = append(kept, "auth-user-pass")
				continue
			}
			kept = append(kept, line)
		}
		ovpn = strings.Join(kept, "\n")
	}
	// macOS Tunnelblick 包（#160）：?fmt=tblk → 单文件 zip（内含 config.ovpn），
	// 下载后双击即被 Tunnelblick 导入（普通 .ovpn 在 macOS 需手动拖拽，一步变两步）
	if r.URL.Query().Get("fmt") == "tblk" {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		wtr, err := zw.Create("config.ovpn")
		if err == nil {
			_, err = wtr.Write([]byte(ovpn))
		}
		if err2 := zw.Close(); err == nil {
			err = err2
		}
		if err != nil {
			failSystem(w, r, "打包失败（"+err.Error()+"）")
			return
		}
		w.Header().Set("Content-Disposition",
			contentDisposition(strings.TrimSuffix(g.filename, ".ovpn")+".tblk"))
		_, _ = w.Write(buf.Bytes())
		return
	}
	_, _ = w.Write([]byte(ovpn))
}

// tls-crypt-v2 迁移（#106）：tls-auth→tls-crypt-v2。客户端密钥从预生成池原子取用
// （/etc/openvpn/instances/tlscv2-pool/，服务器 timer 定时补充——与 §15 证书池同模式，
// 控制面不做 exec：原子 rename 防并发重复消费）。
// tls-crypt-v2 密钥池目录支持 MODSAFE_TLSCV2_POOL 覆盖（安装器 v2 归一布局）
var tlscv2PoolDir = envOr("MODSAFE_TLSCV2_POOL", "/etc/openvpn/instances/tlscv2-pool")

func takeTlsCryptV2ClientKey() (string, error) {
	entries, err := os.ReadDir(tlscv2PoolDir)
	if err != nil || len(entries) == 0 {
		return "", fmt.Errorf("tls-crypt-v2 密钥池为空（等待自动补充或联系管理员检查 modsafe-tlscv2-pool.timer）")
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		src := filepath.Join(tlscv2PoolDir, e.Name())
		consumed := filepath.Join(tlscv2PoolDir, "consumed-"+e.Name())
		if err := os.Rename(src, consumed); err != nil {
			continue // 被并发请求抢走，尝试下一个
		}
		b, err := os.ReadFile(consumed)
		if err != nil {
			return "", fmt.Errorf("读取客户端密钥失败: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("tls-crypt-v2 密钥池为空（等待自动补充或联系管理员检查 modsafe-tlscv2-pool.timer）")
}

// renderOVPN：§15.2 模板（remote 来自 settings/vpn_remote（env 种子），未配置拒绝签发；
// 内网 VIP 回退 remote 经 MODSAFE_DIRECTOR_VIP 可选注入；
// 加密套件跟随 crypto_suite 设置——GM=SM4-GCM/SM3，标准=AES/SHA256，与双节点 conf 同口径）
func (a *App) renderOVPN(filename, certPEM, keyPEM string) (string, error) {
	// PKI 全局（caChain/taKey）为懒加载：纯下载路径（同名复用/一次性 token）不经过
	// signClientCert，若控制面重启后首个请求就是复用下载，会渲染出空 <ca> 的配置
	//（客户端报 "Cannot load CA certificate file [[INLINE]]"，2026-09-30 修复）
	if err := pkiInit(); err != nil {
		log.Printf("[ovpn] PKI 加载失败，输出配置将缺少 CA（拒绝渲染）: %v", err)
	}
	remote := getSetting(a, "vpn_remote", os.Getenv("MODSAFE_VPN_REMOTE"))
	if strings.TrimSpace(remote) == "" {
		return "", fmt.Errorf("vpn_remote 未配置：请在管理台「通用设置」填写，或设置 MODSAFE_VPN_REMOTE（拒绝签出不可达配置）")
	}
	// remote/vip 渲染前格式校验（host port / host）：字段值可写（设置表/env），
	// 直拼进 .ovpn 模板——不校验则换行可注入任意 OpenVPN 客户端指令（up/script-security 等）
	remoteHost, _, ok := splitHostPort(remote)
	if !ok {
		return "", fmt.Errorf("vpn_remote 格式不合法（应为 \"host port\"，host=域名/IP，port=1-65535）：%q", remote)
	}
	// 第二 remote=内网 VIP 回退（可经 MODSAFE_DIRECTOR_VIP 配置；未配置=单 remote，不再内置）
	secondRemote := ""
	if vip := strings.TrimSpace(os.Getenv("MODSAFE_DIRECTOR_VIP")); vip != "" && remoteHost != vip {
		if !validHost(vip) {
			return "", fmt.Errorf("MODSAFE_DIRECTOR_VIP 格式不合法（应为域名/IP）：%q", vip)
		}
		secondRemote = "\nremote " + vip + " 1194"
	}
	spec := cryptoSpec(cryptoSuite(a))
	_, _, chainPEM := pkiSnapshot() // 锁内快照（ca-renew 重载后即为新链）
	chain := strings.TrimSpace(string(chainPEM))
	if chain == "" {
		return "", fmt.Errorf("CA 链为空，拒绝渲染")
	}
	// #106：tls-auth→tls-crypt-v2 客户端密钥（池原子取用）
	clientKey, err := takeTlsCryptV2ClientKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`# modsafe 客户端配置 — %s — 生成于 %s
client
dev tun
proto udp
# 双 remote：公网优先（外网/流量用户）；办公内网用户对公网 IP 的 UDP 回环
# （hairpin）通常被网关拒绝（ECONNREFUSED），失败自动落到内网 LVS VIP 直连
remote %s%s
resolv-retry infinite
nobind
persist-key
persist-tun
# LVS-DR 架构：回包源 IP 为节点真实 IP（非 VIP），需要 float 允许对端地址漂移
float

remote-cert-tls server
data-ciphers %s
auth %s

# 双节点已启用 DCO（ovpn 内核模块 + 服务端 2.7.7[DCO] 构建，#109）。
# 无 DCO 驱动的客户端自动回退经典 tun；GM 套件会话由 openvpn 自动回退用户态
#（ovpn 内核模块不支持 SM4-GCM，AES-GCM 全速 DCO）。

# SSO 扫码登录（IV_SSO webauth）；凭证走文件（免 GUI 弹框，username=真实姓名保证会话归属）。
# #124：凭据文件挪入隐藏子目录（.modsafe/，launcher 写入并对目录设隐藏属性）——
# 配置目录只剩 .ovpn 可见文件；OpenVPN 相对路径以配置目录为基准（GUI 以 config_dir 为进程 CWD）
auth-user-pass .modsafe/auth-user.txt
setenv IV_SSO openurl,webauth

connect-retry 5 30
connect-retry-max 2
# UDP 主动断开即时通知服务端（服务端立刻摘会话，status 文件 10s 内刷新）；
# 只影响新签发配置，存量配置靠服务端 keepalive 兜底；TCP 下此行无效但无害
explicit-exit-notify 3
verb 3

<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>
<tls-crypt-v2>
%s
</tls-crypt-v2>
`, filename, time.Now().Format("2006-01-02 15:04:05"), remote, secondRemote,
		spec.DataCiphers, spec.Auth, chain, certPEM, keyPEM, clientKey), nil
}

// validHost：remote 主机字段字符白名单（域名/IPv4/裸 IPv6；排除空白与换行，
// 保证渲染进 .ovpn 模板时不产生新行/新指令）
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == ':':
		default:
			return false
		}
	}
	return true
}

// splitHostPort：解析 "host port"（单空格分隔）→ (host, port, ok)；port 1-65535。
// vpn_remote / MODSAFE_DIRECTOR_VIP 渲染进 .ovpn 前的格式门禁（防模板行注入）
func splitHostPort(s string) (string, string, bool) {
	i := strings.IndexByte(s, ' ')
	if i <= 0 || strings.IndexByte(s[i+1:], ' ') >= 0 {
		return "", "", false
	}
	host, port := s[:i], s[i+1:]
	if !validHost(host) {
		return "", "", false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	return host, port, true
}
