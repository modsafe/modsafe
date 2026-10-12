// modsafe-launcher（2026-10-04 #91 定名）：§25 阶段2 网页一键连接的本地桥（Windows）。
// 两种模式（#94：modsafe:// 为唯一协议，早期临时协议兼容已删）：
//   modsafe://connect?profile=NAME            已导入配置直接连
//   modsafe://setup?token=T&name=NAME         一键接入：从门户下载 .ovpn → 写入
//                                              用户 config 目录 → 连接（新员工零手动）
// 安全（§25.4）：name 白名单 ^[A-Za-z0-9_.-]{1,64}$；SERVER_BASE 编译常量（防任意下载源）；
// token 是 §15 一次性下载凭证（5 分钟 TTL）——拿到 token 本身就等于拥有下载权，风险等价直接下载。
// 认证决策仍在服务端：导入的配置连的就是本企业服务器，登录走扫码/会话。
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// 门户基址：编译期不内置任何部署地址。解析顺序：env MODSAFE_PORTAL_BASE > 深链学习值
//（首次一键连接时持久化，见 learnPortalBase）> 空。
// 注意：CORS 白名单随本值动态生效——env 未配且本机未做过一键连接时，门户 /status
// 探测会被 CORS 拦截（表现为"未检测到 launcher"），部署时应在安装器注入 MODSAFE_PORTAL_BASE。
var portalBase = envDefault("MODSAFE_PORTAL_BASE", "")

// portalBaseFile：学习到的门户基址持久化位置（随安装目录）
func portalBaseFile() string {
	appdata := os.Getenv("LOCALAPPDATA")
	if appdata == "" {
		return ""
	}
	return filepath.Join(appdata, "modsafeLauncher", "portal-base")
}

func loadPortalBase() {
	if portalBase != "" {
		return
	}
	p := portalBaseFile()
	if p == "" {
		return
	}
	if b, err := os.ReadFile(p); err == nil {
		if v := normalizeBase(strings.TrimSpace(string(b))); v != "" {
			portalBase = v
		}
	}
}

// learnPortalBase：深链携带的合法 base 运行时采纳并持久化（换门户域名后首次连接即自动跟随）
func learnPortalBase(base string) {
	if base == "" || base == portalBase {
		return
	}
	portalBase = base
	if p := portalBaseFile(); p != "" {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(base), 0o600)
	}
}

// portalHint：用户提示中的门户入口（未配置时退化为泛称，不带假地址）
func portalHint() string {
	if portalBase != "" {
		return strings.TrimRight(portalBase, "/") + "/portal"
	}
	return "员工门户"
}

// profile 名白名单：首字符限定字母/数字/下划线（排除 - 和 .），杜绝
// 「--connect -Foo」形态的参数位歧义与 .ovpn / 点文件路径边角（深链 name 可为任意串）
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// credRefRe（#124）：从 .ovpn 内容提取 auth-user-pass 引用的凭据文件相对路径（支持子目录）
var credRefRe = regexp.MustCompile(`(?m)^auth-user-pass\s+(\S+)`)

// #129：门户地址可配置——modsafe:// 可携带 base=（门户所在源）；launcher 校验后跟随，
// 使「换门户地址」无需重发 launcher。安全底线：下载配置 <ca> 段的全部证书必须链到
// 离线根 CA（指纹锚点=pki-offline/ca.crt 的 DER SHA-256，锚根以外的证书须为锚根有效
// 签发的链证书），否则视为来源不可信拒绝导入——
// 防"任意站点构造 modsafe:// URL 投毒配置"（配置含用户私钥，注入=流量被劫持到攻击者 VPN）。
const rootCAFp = "f27d8e21f55ea08bc2ffe5e10bc4bc1dae87e61db8219b362dba2db0a1aafe06"

// normalizeBase：校验 base 参数——仅 https、host 非空且非本机回环；返回规范化 base 或空串（空=用编译默认）
func normalizeBase(base string) string {
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// verifyProfileCA（#129）：提取 .ovpn 全部 <ca> 段内的证书做锚定链校验——必须存在
// DER SHA-256 命中离线根 CA 指纹的锚根，且其余每张证书都由已信任证书有效签发
//（服务端 ca-chain.crt=root+subca，链深一层）。任一证书不在锚根签名链内即整体拒绝：
// OpenVPN 把 <ca> 当多 CA 信任束（任一 CA 签的服务端证书都能通过校验），而根 CA
// 证书本身随每个 profile 公开下发——"真根 CA+攻击者 CA 并存"时只查任一命中即被绕过。
func verifyProfileCA(body string) bool {
	var certs []*x509.Certificate
	for _, caBlock := range regexp.MustCompile(`(?s)<ca>(.*?)</ca>`).FindAllStringSubmatch(body, -1) {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' {
				return -1
			}
			return r
		}, caBlock[1])
		for _, m := range regexp.MustCompile(`-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=]+)-----END CERTIFICATE-----`).FindAllStringSubmatch(clean, -1) {
			der, err := base64.StdEncoding.DecodeString(m[1])
			if err != nil {
				return false // fail-closed：信任段内容异常即拒绝
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return false
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return false
	}
	trusted := map[*x509.Certificate]bool{}
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == rootCAFp {
			trusted[c] = true
		}
	}
	if len(trusted) == 0 {
		return false // 锚根缺席=来源不可信
	}
	// 不动点扩展信任：由任一已信任证书有效签发的证书纳入（正常仅 root→subca 一层）
	for progress := true; progress && len(trusted) < len(certs); {
		progress = false
		for _, c := range certs {
			if trusted[c] {
				continue
			}
			for t := range trusted {
				if c.CheckSignatureFrom(t) == nil {
					trusted[c] = true
					progress = true
					break
				}
			}
		}
	}
	return len(trusted) == len(certs)
}

// ── i18n（#66）：跟随 Windows 显示语言（主语言 ID 0x09=英语→en，否则 zh）。
// kernel32!GetUserDefaultUILanguage 无需额外依赖。表覆盖全部用户可见弹窗文案。 ──
var langID = syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

func uiLang() string {
	if r, _, _ := langID.Call(); uint16(r&0xFF) == 0x09 {
		return "en"
	}
	return "zh"
}

var msgZh = map[string]string{
	"usage":        "用法：modsafe://connect?profile=名称 或 modsafe://setup?token=一次性令牌&name=名称",
	"title":        "模方安全 一键连接",
	"badcall":      "无法识别的调用：",
	"badmode":      "不支持的模式：",
	"badname":      "参数不合法（name 仅字母数字_.-）",
	"dlfail":       "下载配置失败：",
	"dlfailhint":   "\n请确认 5 分钟内从门户发起，且每个链接只能用一次。",
	"dlused":       "下载配置失败（链接已用或过期）。请回到门户重新点「一键接入」。",
	"notovpn":      "下载内容不是有效的 VPN 配置，已放弃写入。",
	"badca":        "配置来源校验失败（CA 指纹不匹配），已拒绝导入。\n请从员工门户重新下载：%s",
	"mkdirfail":    "创建配置目录失败：",
	"writefail":    "写入配置失败：",
	"noguiafter":   "\n未检测到模方安全客户端（未安装或安装不完整）。\n请从员工门户下载安装：%s",
	"savedto":      "已保存配置到 ",
	"setupok":      "配置已导入并开始连接。\n接下来：①如弹出账号密码框，任意输入后确定；②浏览器自动完成认证后即上线。",
	"badprofilename": "配置名不合法（仅字母数字_.-，1-64 位）",
	"noguiprefix":  "未检测到模方安全客户端（未安装或安装不完整）。\n请从员工门户下载安装：%s\n详情：",
	"noconfig":     "本机没有名为「%s」的已导入配置。\n请回到自助门户使用「一键接入」，或在「设备」页重新下载配置。",
	"startfail":    "启动连接失败：",
}

var msgEn = map[string]string{
	"usage":        "Usage: modsafe://connect?profile=NAME or modsafe://setup?token=ONE-TIME-TOKEN&name=NAME",
	"title":        "Modsafe One-Click Connect",
	"badcall":      "Unrecognized invocation: ",
	"badmode":      "Unsupported mode: ",
	"badname":      "Invalid parameters (name: letters/digits/._- only)",
	"dlfail":       "Failed to download the profile: ",
	"dlfailhint":   "\nMake sure it was started from the portal within 5 minutes; each link works only once.",
	"dlused":       "Download failed (link used or expired). Please click \"One-click setup\" in the portal again.",
	"notovpn":      "The downloaded content is not a valid VPN profile. Nothing was written.",
	"badca":        "Profile source verification failed (CA fingerprint mismatch). Import rejected.\nRe-download from the portal: %s",
	"mkdirfail":    "Failed to create the config directory: ",
	"writefail":    "Failed to write the profile: ",
	"noguiafter":   "\nModsafe client not detected (not installed or incomplete).\nDownload it from the portal: %s",
	"savedto":      "Profile saved to ",
	"setupok":      "Profile imported and connecting.\nNext: if a credentials box pops up, enter anything and click OK; the browser will finish authentication and you are online.",
	"badprofilename": "Invalid profile name (letters/digits/._- only, 1-64 chars)",
	"noguiprefix":  "Modsafe client not detected (not installed or incomplete).\nDownload it from the portal: %s\nDetails: ",
	"noconfig":     "No imported profile named \"%s\" on this machine.\nUse \"One-click setup\" in the self-service portal, or re-download the profile on the Devices page.",
	"startfail":    "Failed to start the connection: ",
}

func tr(key string) string {
	if uiLang() == "en" {
		return msgEn[key]
	}
	return msgZh[key]
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// logDir：#69 目录沿用规则——openSecLauncher 旧目录存在则沿用（日志与状态文件同目录）
func logDir() string {
	dir := os.Getenv("LOCALAPPDATA") + `\modsafeLauncher`
	if _, err := os.Stat(os.Getenv("LOCALAPPDATA") + `\openSecLauncher`); err == nil {
		dir = os.Getenv("LOCALAPPDATA") + `\openSecLauncher`
	}
	return dir
}

func log(step, detail string) {
	f, err := os.OpenFile(logDir()+`\launcher.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s %s\n", time.Now().Format("15:04:05.000"), step, detail)
}

func main() {
	loadPortalBase()
	// #115/#118：--listen 常驻状态服务——门户（HTTPS）向本机 127.0.0.1:11443/status 查询
	// 实时连接状态（服务端台账滞后 ≤40s，本机检测零延迟）。
	// #118：一次性协议调用完成后同样转入监听（见 tail 调用）——用户没跑过 install.bat
	//（无开机自启）时，第一次一键连接即完成"调用 + 自带监听"双职责，无需 exec 自启。
	if len(os.Args) >= 2 && os.Args[1] == "--listen" {
		runListener()
		return
	}
	log("start", "invoked")
	if len(os.Args) < 2 {
		msg(tr("usage"))
		return
	}
	uri := os.Args[1]
	log("uri", uri)
	// #94：modsafe:// 唯一协议（用户拍板删除 modsafevpn:// 旧书签兼容，推翻 #78 红线）
	if !strings.HasPrefix(uri, "modsafe://") {
		msg(tr("badcall") + uri)
		return
	}
	params := map[string]string{}
	for _, kv := range strings.Split(uri[strings.Index(uri, "?")+1:], "&") {
		p := strings.SplitN(kv, "=", 2)
		if len(p) != 2 {
			continue
		}
		v, decErr := url.QueryUnescape(p[1])
		if decErr != nil {
			v = p[1]
		}
		if p[0] == "profile" {
			params["name"] = v // connect 模式兼容
		} else {
			params[p[0]] = v
		}
	}
	// 按 "//" 定位路径（前缀已锁定 modsafe://）
	switch strings.Trim(strings.TrimPrefix(strings.Split(uri[strings.Index(uri, "//")+2:], "?")[0], "/"), "/") {
	case "setup":
		runSetup(params["token"], params["name"], params["u"], params["base"], params["g"])
	case "connect":
		runConnect(params["name"])
	default:
		msg(tr("badmode") + uri)
	}
	// #118：一次性调用完成后转入常驻监听（同进程续命）——用户没跑过 install.bat
	//（无开机自启）时，第一次一键连接即完成"调用 + 自带监听"双职责，无需 exec 自启
	listenForever()
}

// listenForever：协议调用流程结束后接管本机状态监听；
// 端口已被占用说明已有常驻实例在跑，静默退出（互斥不打架）。
func listenForever() {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	if resp, err := client.Get("http://127.0.0.1:11443/ping"); err == nil {
		resp.Body.Close()
		log("exit", "listener already running")
		os.Exit(0)
	}
	runListener()
}

// runSetup：下载 → 写用户 config（含凭证文件，免 GUI 弹框）→ 连接（新员工一键接入全流程）
// #129：base=门户所在源（门户页携带）——跟随门户地址无需重发 launcher；空/非法则用 env/学习值
// B 方案：grant=门户签发的一次性连接 ticket（strict 策略下 webauth 免验证的唯一凭据）——
// 落盘 .modsafe/grant.txt，modsafe-gui 打开验证页时附加 &grant= 并即删（客户端一次性）。
func runSetup(token, name, username, base, grant string) {
	if token == "" || !nameRe.MatchString(name) {
		log("setup-reject", "token/name")
		msg(tr("badname"))
		return
	}
	base = normalizeBase(base)
	learnPortalBase(base)
	dlBase := portalBase
	if base != "" {
		dlBase = base
	}
	log("setup", name+" base="+dlBase)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(dlBase + "/api/v1/client-config/" + token)
	if err != nil {
		log("download-error", err.Error())
		msg(tr("dlfail") + err.Error() + tr("dlfailhint"))
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		log("download-bad", fmt.Sprintf("http %d", resp.StatusCode))
		msg(tr("dlused"))
		return
	}
	s := string(body)
	if !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "client") || !strings.Contains(s, "<ca>") {
		log("content-reject", fmt.Sprintf("%d bytes", len(body)))
		msg(tr("notovpn"))
		return
	}
	// #129：CA 指纹校验——配置必须链到离线根 CA，否则视为来源不可信（防 modsafe:// URL 投毒配置：
	// base 可跟随门户地址动态变化，内容锚点=离线根 CA 指纹是最终防线）
	if !verifyProfileCA(s) {
		log("ca-reject", "root CA fingerprint mismatch")
		msg(fmt.Sprintf(tr("badca"), portalHint()))
		return
	}

	home, _ := os.UserHomeDir()
	cfgDir := filepath.Join(home, "OpenVPN", "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		log("mkdir-error", err.Error())
		msg(tr("mkdirfail") + err.Error())
		return
	}
	cleanupStaleProfiles(cfgDir, name)
	target := filepath.Join(cfgDir, name+".ovpn")
	if err := os.WriteFile(target, body, 0o600); err != nil {
		log("write-error", err.Error())
		msg(tr("writefail") + err.Error())
		return
	}
	log("written", target)
	// 凭证文件：username=真实姓名（服务端会话归属键），password 固定占位（服务端走 webauth 不验密码）。
	// #124：写到配置内 auth-user-pass 引用的路径（服务端引用 .modsafe/auth-user.txt，目录设隐藏属性
	// ——配置目录只剩 .ovpn 可见文件）；旧 profile 引用根目录 auth-user.txt 时照旧写根（兼容存量）。
	if username == "" {
		username = name
	}
	// u= 取自 URL（QueryUnescape 后可含换行）——凭据文件首行必须是单行用户名，截到首个换行
	if i := strings.IndexAny(username, "\r\n"); i >= 0 {
		username = username[:i]
	}
	credRel := "auth-user.txt"
	if m := credRefRe.FindStringSubmatch(string(body)); len(m) > 1 {
		// 防穿越（对照 nodeagent /ccd 的校验口径；#124 支持子目录故放行 /）：
		// credRef 取自下载内容——恶意 profile 借 ../.. 或绝对/UNC 路径可把凭据文件
		// 写到配置目录外任意路径。含 .. / 绝对路径一律拒绝，回落默认根路径
		if filepath.IsAbs(m[1]) || strings.Contains(m[1], "..") {
			log("cred-reject", m[1])
		} else {
			credRel = m[1]
		}
	}
	cred := filepath.Join(cfgDir, filepath.FromSlash(credRel))
	if err := os.MkdirAll(filepath.Dir(cred), 0o700); err != nil {
		log("cred-dir-error", err.Error())
	}
	if err := os.WriteFile(cred, []byte(username+"\nnopass\n"), 0o600); err != nil {
		log("cred-error", err.Error())
	} else {
		log("cred", cred+" ("+username+")")
	}
	if filepath.Dir(filepath.FromSlash(credRel)) == ".modsafe" {
		hideDir(filepath.Join(cfgDir, ".modsafe"))
		os.Remove(filepath.Join(cfgDir, "auth-user.txt")) // 旧版遗留根凭据（新配置已不引用）：静默清理
	}
	// B 方案 ticket 落盘：与凭据文件同目录（配置目录隐藏子目录 .modsafe/）；
	// 旧 ticket 一并清掉（TTL 5 分钟外本就无效，覆盖写防串用）。空 grant=老门户兼容，不落盘。
	grantPath := filepath.Join(cfgDir, ".modsafe", "grant.txt")
	_ = os.Remove(grantPath)
	if grant != "" {
		if err := os.WriteFile(grantPath, []byte(strings.TrimSpace(grant)), 0o600); err != nil {
			log("grant-error", err.Error())
		} else {
			log("grant", "ticket staged for "+name)
		}
	}

	gui, err := findOpenVPNGui()
	if err != nil {
		log("no-gui", err.Error())
		msg(tr("savedto") + target + fmt.Sprintf(tr("noguiafter"), portalHint()))
		return
	}
	// GUI 运行中不会自动发现新文件：重启 GUI（接入场景无既有连接，代价可忽略）
	exec.Command("taskkill", "/IM", "openvpn-gui.exe", "/F").Run()
	time.Sleep(2 * time.Second)

	writeLaunchState() // #120：connecting 态事实源——拉起 GUI 前落盘

	if err := startConnect(gui, name); err != nil {
		log("launch-error", err.Error())
		msg(tr("startfail") + err.Error())
		return
	}
	log("launched", gui+" --connect "+name)
	go msg(tr("setupok")) // #120：异步弹窗——进程立即转入常驻监听，不被未点击的弹窗卡死（#119 缺口 B）
	// #118：不再 os.Exit——返回 main 由 listenForever 接管本机监听
}

// cleanupStaleProfiles：清理同用户前缀的历史配置，只保留本次要写的 profile。
// 网页导入机制下设备页/历史版本会留下 u{uid}-xxx.ovpn 杂散文件（GUI 托盘全部列出）；
// name 约定 u{uid}-xxx，故按 u{数字}- 前缀识别同用户的旧配置（2026-09-30）。
func cleanupStaleProfiles(cfgDir, name string) {
	prefix := name
	if i := strings.Index(name, "-"); i > 0 {
		prefix = name[:i+1]
	}
	if !regexp.MustCompile(`^u\d+-$`).MatchString(prefix) {
		return // 非标准前缀（老配置/手工命名）：不动
	}
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		return
	}
	removed := 0
	for _, e := range entries {
		n := e.Name()
		if n == name+".ovpn" || !strings.HasSuffix(n, ".ovpn") || !strings.HasPrefix(n, prefix) {
			continue
		}
		if rmErr := os.Remove(filepath.Join(cfgDir, n)); rmErr == nil {
			removed++
			log("cleanup", n)
		}
	}
	if removed > 0 {
		log("cleanup-done", fmt.Sprintf("%d stale profiles removed (prefix %s)", removed, prefix))
	}
}

// runConnect：已导入配置直接连
func runConnect(name string) {	if name == "" || !nameRe.MatchString(name) {
		log("reject", "profile="+name)
		msg(tr("badprofilename"))
		return
	}
	log("profile", name)

	gui, err := findOpenVPNGui()
	log("gui", gui)
	if err != nil {
		log("no-gui", err.Error())
		msg(fmt.Sprintf(tr("noguiprefix"), portalHint()) + err.Error())
		return
	}
	home, _ := os.UserHomeDir()
	cfg := filepath.Join(home, "OpenVPN", "config", name+".ovpn")
	if _, statErr := os.Stat(cfg); statErr != nil {
		alt := filepath.Join(`C:\Program Files\OpenVPN\config`, name+".ovpn")
		if _, statErr2 := os.Stat(alt); statErr2 != nil {
			msg(fmt.Sprintf(tr("noconfig"), name))
			return
		}
	}

	writeLaunchState() // #120：connecting 态事实源
	log("launch", gui+" --connect "+name)
	if err := startConnect(gui, name); err != nil {
		log("launch-error", err.Error())
		msg(tr("startfail") + err.Error())
		return
	}
	log("connect-ok", name)
	// #118：不再 os.Exit——返回 main 由 listenForever 接管本机监听
}

// startConnect：按白名单字面量路径拉起 GUI 连接。
// 可执行文件路径必须写死字面量（与 findOpenVPNGui 候选一一对应）——动态程序位
// 一律拒绝（防路径劫持/替换）；profile 名已由 nameRe 白名单校验（无 shell 参与）。
func startConnect(gui, name string) error {
	var cmd *exec.Cmd
	switch gui {
	case `C:\Program Files\Modsafe\bin\modsafe-gui.exe`:
		cmd = exec.Command(`C:\Program Files\Modsafe\bin\modsafe-gui.exe`, "--connect", name)
	case `C:\Program Files\Modsafe\bin\openvpn-gui.exe`:
		cmd = exec.Command(`C:\Program Files\Modsafe\bin\openvpn-gui.exe`, "--connect", name)
	case `C:\Program Files\OpenVPN\bin\modsafe-gui.exe`:
		cmd = exec.Command(`C:\Program Files\OpenVPN\bin\modsafe-gui.exe`, "--connect", name)
	case `C:\Program Files\OpenVPN\bin\openvpn-gui.exe`:
		cmd = exec.Command(`C:\Program Files\OpenVPN\bin\openvpn-gui.exe`, "--connect", name)
	case `C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe`:
		cmd = exec.Command(`C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe`, "--connect", name)
	default:
		return fmt.Errorf("gui path not in whitelist")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

// findOpenVPNGui：常见路径 → PATH（modsafe-gui 品牌名优先，兼容官方 openvpn-gui）
func findOpenVPNGui() (string, error) {
	candidates := []string{
		`C:\Program Files\Modsafe\bin\modsafe-gui.exe`,
		`C:\Program Files\Modsafe\bin\openvpn-gui.exe`,
		`C:\Program Files\OpenVPN\bin\modsafe-gui.exe`,
		`C:\Program Files\OpenVPN\bin\openvpn-gui.exe`,
		`C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("modsafe-gui.exe"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("openvpn-gui.exe"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("未在常见路径找到 modsafe-gui.exe")
}

var (
	user32       = syscall.NewLazyDLL("user32.dll")
	pMessageBoxW = user32.NewProc("MessageBoxW")
	kernel32     = syscall.NewLazyDLL("kernel32.dll")

	pSetFileAttributesW = kernel32.NewProc("SetFileAttributesW")
)

// hideDir（#124）：目录设 Windows 隐藏属性（资源管理器默认不可见）；失败仅记日志不阻断连接。
func hideDir(path string) {
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	const FILE_ATTRIBUTE_HIDDEN = 0x2
	if r, _, _ := pSetFileAttributesW.Call(uintptr(unsafe.Pointer(p16)), FILE_ATTRIBUTE_HIDDEN); r == 0 {
		log("hide-error", path)
	} else {
		log("hide", path)
	}
}

// runListener（#115）：常驻状态服务，仅绑 127.0.0.1。
// GET /status → {"connected":bool,"connecting":bool,"ip":"10.8.x.x"}（#120 三态，
// 优先级 connected > connecting > 未连接，判定详见 localStatus 注释）。
// CORS 仅放行企业门户来源（防任意网站探测用户 VPN 状态）；绑定 127.0.0.1 + Server 超时防资源耗尽。
func runListener() {
	watchAdapter() // #121：连接建立即解除 launchstate——断开后实时放行重连
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w, r)
		_, _ = w.Write([]byte("pong"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(localStatus())
	})
	srv := &http.Server{
		Addr:              "127.0.0.1:11443",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log("listen", "127.0.0.1:11443")
	if err := srv.ListenAndServe(); err != nil {
		log("listen-fatal", err.Error())
	}
}

// allowedOrigins：企业门户入口（随 portalBase 动态：env / 深链学习），不内置部署地址
func allowedOrigins() []string {
	if portalBase == "" {
		return nil
	}
	return []string{strings.TrimRight(portalBase, "/")}
}

// setCORS：Origin 在白名单内才回 ACAO（其余来源浏览器侧拦截读取）
func setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	for _, o := range allowedOrigins() {
		if origin == o {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
}

// launchStateTTL：#120 GUI 拉起后视为「连接中」的窗口——覆盖慢扫码认证；期间门户拦截重复发起
//（GUI 自带重连循环，重试由它负责）。连接成功后网卡地址出现，connected 优先级高于本状态。
const launchStateTTL = 120 * time.Second

// writeLaunchState：#120 GUI 拉起前落盘时间戳——一次性实例与常驻监听是两个进程，
// 状态文件是跨进程通道；/status 据此把「已发起但网卡还没拿到地址」报告为 connecting，
// 堵住握手/认证窗口内门户重复发起的穿透（#119 复盘的主洞）。
func writeLaunchState() {
	if err := os.MkdirAll(logDir(), 0o755); err != nil {
		log("launchstate-error", err.Error())
		return
	}
	body := fmt.Sprintf(`{"launched_at":%d}`, time.Now().UnixMilli())
	if err := os.WriteFile(logDir()+`\launchstate.json`, []byte(body), 0o644); err != nil {
		log("launchstate-error", err.Error())
	} else {
		log("launchstate", "written")
	}
}

// adapterConnected：虚拟网卡地址检测——10.8.0.0/16（IPv4 数据面）或
// fdaa:2026:192::/48（IPv6 场景 B）任一存在即连接中；vip=首个 v4 隧道地址（展示用）。
func adapterConnected() (bool, string) {
	connected, vip := false, ""
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			s := a.String()
			if strings.HasPrefix(s, "10.8.") {
				if !connected {
					vip = strings.Split(s, "/")[0]
				}
				connected = true
			} else if strings.HasPrefix(s, "fdaa:2026:192:") {
				connected = true
			}
		}
	}
	return connected, vip
}

// watchAdapter（#121）：监听进程内 3s 轮询隧道网卡——一旦观察到连接建立立即解除 launchstate
//（连接已成功，connecting 义务终结）。没有这一步，「连接成功后用户断开」仍落在 120s 窗口内、
// 网卡又无地址，会被误判为 connecting 挡住实时重连（#121 用户报障：断开后仍提示"正在连接中"）。
func watchAdapter() {
	go func() {
		for {
			if ok, _ := adapterConnected(); ok {
				if err := os.Remove(logDir() + `\launchstate.json`); err == nil {
					log("launchstate-cleared", "connected observed")
				}
			}
			time.Sleep(3 * time.Second)
		}
	}()
}

// localStatus 三态判定（优先级从高到低）：
//   connected  —— 虚拟网卡持有 10.8.0.0/16 或 fdaa:2026:192::/48 地址（连接真相，进程无关——
//                 GUI 退出但适配器未释放亦视为连接中，避免门户在「断开中」窗口期放行重复连接）
//   connecting —— launchstate.json 距今 ≤120s 且无网卡地址（GUI 已拉起、握手/认证进行中；
//                 连接一旦建立 watchAdapter 即解除该文件，此后断开=未连接，实时放行重连）
//   其余        —— 未连接（网卡无地址且无近期发起）
func localStatus() map[string]interface{} {
	connected, vip := adapterConnected()
	connecting := false
	if !connected {
		if body, err := os.ReadFile(logDir() + `\launchstate.json`); err == nil {
			var st struct {
				LaunchedAt int64 `json:"launched_at"`
			}
			if json.Unmarshal(body, &st) == nil && st.LaunchedAt > 0 &&
				time.Since(time.UnixMilli(st.LaunchedAt)) < launchStateTTL {
				connecting = true
			}
		}
	}
	return map[string]interface{}{"connected": connected, "connecting": connecting, "ip": vip}
}

func msg(text string) {
	title, _ := syscall.UTF16PtrFromString(tr("title"))
	body, _ := syscall.UTF16PtrFromString(text)
	_, _, _ = pMessageBoxW.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x40)
}
