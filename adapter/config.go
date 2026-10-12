package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// === 基础配置（对齐 Python 顶部常量与环境变量） ===

const (
	ADAPTER_PORT = 8000

	TOKEN_TTL = 600
	STATE_TTL = 600
)

// envPath：路径环境变量覆盖（安装器 v2 经 /opt/modsafe/etc/modsafe.env 注入归一布局；
// 缺省=历史路径，现网零影响）
func envPath(key, legacy string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return legacy
}

var (
	// 部署拓扑三要素（必填，main→validateConfig 校验，缺失拒绝启动）：
	// 本机基址、oa2 基址、对外门户基址（redirect 白名单/CORS 均由其派生，禁止再写死）
	ADAPTER_BASE    = envOr("ADAPTER_BASE", "")
	OA2_BASE        = envOr("OA2_BASE", "")
	MODSAFE_PORTAL_BASE = envOr("MODSAFE_PORTAL_BASE", "")
	OA2_CLIENT_ID   = envOr("OA2_CLIENT_ID", "")
	OA2_CLIENT_SEC  = envOr("OA2_CLIENT_SECRET", "")
	MOCK_MODE       = envOr("IDP_MOCK", "0") == "1"
	KEY_DIR         = envPath("MODSAFE_KEY_DIR", "/opt/modsafe/idp-adapter")
	KEY_PATH        = KEY_DIR + "/idp_rsa.pem"
	ISSUER          = ADAPTER_BASE
	BRANDING_PATH   = envPath("MODSAFE_BRANDING", "/opt/modsafe/branding.json")
	OA2_CONFIG      = envPath("MODSAFE_OA2_CONFIG", "/etc/openvpn-auth-oauth2/config.yaml")
	OA2_TEMPLATE    = envPath("MODSAFE_OA2_TEMPLATE", "/etc/openvpn-auth-oauth2/template.html")
	OA2_LOG         = envPath("MODSAFE_OA2_LOG", "/var/log/openvpn-auth-oauth2.log")
	IDP_CONFIG_PATH = envPath("MODSAFE_IDP_CONFIG", "/opt/modsafe/idp-config.json")
	CCD_RULES_PATH  = envPath("MODSAFE_CCD_RULES", "/opt/modsafe/ccd-rules.json")
	CCD_OUT_DIR     = envPath("MODSAFE_CCD_OUT", "/etc/openvpn-auth-oauth2/client-config/")

	CONTROL_PLANE_URL     = envOr("CONTROL_PLANE_URL", "http://127.0.0.1:9443")
	AUTH_CHECK_FAIL_MODE  = envOr("AUTH_CHECK_FAIL_MODE", "open") // open|closed
	ADMIN_TOKEN_PATH      = envPath("MODSAFE_ADMIN_TOKEN", "/opt/modsafe/admin-token")
	MODSAFE_ADMIN_PUB_PORT = envOr("MODSAFE_ADMIN_PUBLIC_PORT", "9443")

	// 钉钉凭证兼容旧环境变量（idp-config.json 优先）
	DINGTALK_CLIENT_ID     = os.Getenv("DINGTALK_CLIENT_ID")
	DINGTALK_CLIENT_SECRET = os.Getenv("DINGTALK_CLIENT_SECRET")

	WEB_SESS_HOURS = envOrFloat("MODSAFE_WEB_SESS_HOURS", 8)

	REFRESH_STORE     = envPath("MODSAFE_REFRESH_STORE", "/opt/modsafe/oidc-refresh.json")
	NETWORK_CONF      = envPath("MODSAFE_NETWORK_CONF", "/opt/modsafe/network.json")
	NODE_AGENT_193    = envOr("NODE_AGENT_193", "")
	ALERT_CHANNELS_F  = envPath("MODSAFE_ALERT_CHANNELS", "/opt/modsafe/alert-channels.json")
	NOTIFY_ALLOW_PRIV = os.Getenv("MODSAFE_NOTIFY_ALLOW_PRIVATE") == "1"
	EXTRA_REDIRECTS   = os.Getenv("MODSAFE_EXTRA_REDIRECT_URIS")

	// REDIRECT_URIS 整体替换 redirect 白名单派生条目（EXTRA_REDIRECTS 仍为追加项）
	REDIRECT_URIS = os.Getenv("MODSAFE_REDIRECT_URIS")
	// NAT_IFACE：网段变更 MASQUERADE 出口网卡
	NAT_IFACE = envOr("MODSAFE_NAT_IFACE", "ens18")
	// OVPN_REMOTES：签发 .ovpn 的 remote 端点（逗号分隔的 "host port" 对）；空=签发时报错而非签出不可达配置
	OVPN_REMOTES = envOr("MODSAFE_OVPN_REMOTES", "")
)

// validateConfig：必填配置缺一拒绝启动（fail-fast，不带弱默认运行）
func validateConfig() {
	var missing []string
	for _, kv := range [][2]string{
		{"ADAPTER_BASE", ADAPTER_BASE},
		{"OA2_BASE", OA2_BASE},
	} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "[CONFIG] 缺少必填环境变量: %s（参考 examples/adapter.env.example）\n",
			strings.Join(missing, ", "))
		os.Exit(2)
	}
}

// portalBase：对外门户基址；未配置时回退本机基址（同机 nginx 同源部署形态）
func portalBase() string {
	if MODSAFE_PORTAL_BASE != "" {
		return strings.TrimRight(MODSAFE_PORTAL_BASE, "/")
	}
	return strings.TrimRight(ADAPTER_BASE, "/")
}

func envOrFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// === IdP 元数据（显示名/类型；顺序敏感处用 idpOrder） ===

type idpMeta struct {
	Label string
	Icon  string
	Type  string // oauth | saml | ldap | mock
}

var IDP_META = map[string]idpMeta{
	"dingtalk": {"钉钉扫码", "D", "oauth"},
	"feishu":   {"飞书扫码", "F", "oauth"},
	"wecom":    {"企业微信扫码", "W", "oauth"},
	"saml":     {"企业 SSO（SAML）", "S", "saml"},
	"ldap-ad":  {"AD 域账号", "A", "ldap"},
	"openldap": {"OpenLDAP 账号", "L", "ldap"},
	"mock":     {"模拟扫码（测试）", "M", "mock"},
}

var idpOrder = []string{"dingtalk", "feishu", "wecom", "saml", "ldap-ad", "openldap"}

var DEFAULT_BRANDING = map[string]any{
	"company_name": "modsafe",
	"product_name": "modsafe 安全接入",
	"footer_text":  "Modsafe CE 社区版",
}

// === IdP 配置（合并 json + 环境变量兜底；运行期快照整体替换） ===

var (
	cfgMu   sync.RWMutex
	cfgSnap map[string]map[string]any
)

func loadIDPConfig() map[string]map[string]any {
	raw, ok := loadJSONFile(IDP_CONFIG_PATH)
	if !ok {
		raw = map[string]any{}
	}
	cfg := map[string]map[string]any{}
	for k, v := range raw {
		if m, ok := v.(map[string]any); ok {
			cfg[k] = m
		}
	}
	if DINGTALK_CLIENT_ID != "" && mStr(cfg["dingtalk"], "client_id") == "" {
		if cfg["dingtalk"] == nil {
			cfg["dingtalk"] = map[string]any{}
		}
		cfg["dingtalk"]["client_id"] = DINGTALK_CLIENT_ID
		cfg["dingtalk"]["client_secret"] = DINGTALK_CLIENT_SECRET
		cfg["dingtalk"]["enabled"] = true
	}
	return cfg
}

func initConfigSnapshot() {
	cfgSnap = loadIDPConfig()
}

// idpc：当前配置快照（读多数、写整体替换，对齐 Python clear/update 空窗修复）
func idpc() map[string]map[string]any {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfgSnap
}

func setIDPC(cfg map[string]map[string]any) {
	cfgMu.Lock()
	cfgSnap = cfg
	cfgMu.Unlock()
}

func saveIDPConfig(cfg map[string]map[string]any) error {
	raw := map[string]any{}
	for k, v := range cfg {
		raw[k] = v
	}
	return saveJSONAtomic(IDP_CONFIG_PATH, raw, 0o600)
}

func idpEnabled(pid string) bool {
	return mBool(idpc()[pid], "enabled")
}

func idpLabel(pid string) string {
	if c := idpc()[pid]; c != nil && mStr(c, "label") != "" {
		return mStr(c, "label")
	}
	return IDP_META[pid].Label
}

func enabledIDPs() [][2]string {
	var out [][2]string
	for _, p := range idpOrder {
		if idpEnabled(p) {
			out = append(out, [2]string{p, idpLabel(p)})
		}
	}
	if MOCK_MODE || len(out) == 0 {
		out = append(out, [2]string{"mock", IDP_META["mock"].Label})
	}
	return out
}

// === RSA 密钥（/opt/modsafe/idp-adapter/idp_rsa.pem，缺则生成；JWKS kid 固定） ===

var rsaKey *rsa.PrivateKey
var jwksJSON map[string]any

func initRSAKey() {
	if err := os.MkdirAll(KEY_DIR, 0o755); err != nil {
		log.Fatalf("[adapter] key dir: %v", err)
	}
	if b, err := os.ReadFile(KEY_PATH); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					rsaKey = rk
				}
			}
		}
	}
	if rsaKey == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("[adapter] rsa generate: %v", err)
		}
		rsaKey = k
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		pemB := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(KEY_PATH, pemB, 0o600); err != nil {
			log.Fatalf("[adapter] rsa write: %v", err)
		}
	}
	pub := &rsaKey.PublicKey
	intToB64 := func(n *big.Int) string {
		return b64u(n.Bytes())
	}
	jwksJSON = map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "modsafe-idp-1",
		"n": intToB64(pub.N), "e": intToB64(big.NewInt(int64(pub.E))),
	}}}
}

// === 品牌 ===

func loadBranding() map[string]any {
	out := map[string]any{}
	for k, v := range DEFAULT_BRANDING {
		out[k] = v
	}
	if raw, ok := loadJSONFile(BRANDING_PATH); ok {
		for k, v := range raw {
			out[k] = v
		}
	}
	return out
}

func saveBranding(cfg map[string]any) {
	_ = saveJSONAtomic(BRANDING_PATH, cfg, 0o644)
}

// === 网段配置 ===

func loadNetwork() map[string]any {
	if raw, ok := loadJSONFile(NETWORK_CONF); ok {
		return raw
	}
	return map[string]any{
		"base_cidr": "10.8.0.0/16", "node_prefix": 23,
		"blocks": map[string]any{"1": "10.8.0.0/23", "2": "10.8.2.0/23"},
	}
}

func saveNetwork(cfg map[string]any) {
	_ = saveJSONAtomic(NETWORK_CONF, cfg, 0o644)
}

// ---------- 时间 ----------

func nowUnix() int64 { return time.Now().Unix() }
