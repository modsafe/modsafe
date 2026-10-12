package main

// 加密套件（§国密）：管理台可选 标准套件（AES-256-GCM/SHA256）或 国密套件（SM4-GCM/SM3）。
// 选中即切换：双节点 conf 的 data-ciphers/auth 行改写 + 重启（打断性操作，前端二次确认）。
// 能力前提：服务端二进制为 GM 构建（vanilla OpenSSL 静态链接，--show-ciphers 含 SM4-GCM）；
// 客户端 .ovpn 模板跟随设置——切换后已有客户端需重新下载配置（NCP 协商不再共享 AES）。
// 控制通道 TLS 套件保持标准（官方 Windows 客户端无 TLS 国密套件，属业界通行边界）。

import (
	"net/http"
	"os"
	"regexp"
	"strings"
)

type cryptoSuiteSpec struct {
	DataCiphers string
	Auth        string
	Label       string
}

func cryptoSpec(suite string) cryptoSuiteSpec {
	if suite == "gm" {
		return cryptoSuiteSpec{DataCiphers: "SM4-GCM", Auth: "SM3", Label: "国密套件（SM4-GCM/SM3）"}
	}
	return cryptoSuiteSpec{DataCiphers: "AES-256-GCM:AES-128-GCM", Auth: "SHA256", Label: "标准套件（AES-256-GCM/SHA256）"}
}

func cryptoSuite(a *App) string {
	return getSetting(a, "crypto_suite", "standard")
}

// renderCryptoConf：把 conf 文本中的 data-ciphers/auth 行改写为目标套件。
// 幂等：先移除全部既有 data-ciphers 行，再在 auth 行后插入恰好一行
//（此前 auth 匹配时按"未见过 dc 才插入"，多次交错应用曾把 data-ciphers 写成 5 行重复，2026-09-30 修复）
func renderCryptoConf(content string, spec cryptoSuiteSpec) (string, error) {
	lines := strings.Split(content, "\n")
	authRe := regexp.MustCompile(`^auth [A-Z0-9]`) // 不匹配 auth-gen-token / auth-token-secret（带 -）
	dcRe := regexp.MustCompile(`^data-ciphers .*$`)
	authFound := false
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if dcRe.MatchString(line) {
			continue // 删除全部既有 data-ciphers 行
		}
		if authRe.MatchString(line) {
			out = append(out, "auth "+spec.Auth, "data-ciphers "+spec.DataCiphers)
			authFound = true
			continue
		}
		out = append(out, line)
	}
	if !authFound {
		return "", os.ErrNotExist
	}
	return strings.Join(out, "\n"), nil
}

// applyCryptoSuiteLocal：本机（node-1）conf 改写 + 重启
func applyCryptoSuiteLocal(spec cryptoSuiteSpec) error {
	conf := envOr("MODSAFE_NODE1_CONF", "/etc/openvpn/instances/node-1.conf")
	raw, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	newContent, err := renderCryptoConf(string(raw), spec)
	if err != nil {
		return err
	}
	tmp := conf + ".tmp"
	if err := os.WriteFile(tmp, []byte(newContent), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, conf); err != nil {
		return err
	}
	systemctlRestart("openvpn-modsafe@1")
	return nil
}

// handleCryptoGet：GET /api/v1/settings/crypto
func (a *App) handleCryptoGet(w http.ResponseWriter, r *http.Request) {
	suite := cryptoSuite(a)
	spec := cryptoSpec(suite)
	writeOK(w, r, map[string]interface{}{
		"suite": suite, "label": spec.Label,
		"data_ciphers": spec.DataCiphers, "auth": spec.Auth,
		"nodes": []string{"node-1@180", "node-2@193"},
	})
}

// handleCryptoPut：PUT /api/v1/settings/crypto {suite}（保存 + 双节点应用，打断性）
func (a *App) handleCryptoPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Suite string `json:"suite"`
	}
	if err := jsonDecode(r, &req); err != nil || (req.Suite != "standard" && req.Suite != "gm") {
		failParam(w, r, "suite 必须为 standard|gm")
		return
	}
	spec := cryptoSpec(req.Suite)

	// 先远端（193）后本机（180）：本机失败时远端已切，管理台仍可经 193 观测；顺序与回滚方向一致
	remote := map[string]interface{}{}
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		out, err := agentRequest(nodes[i], "POST", "/crypto", map[string]interface{}{
			"suite":     req.Suite,
			"ciphers":   spec.DataCiphers,
			"auth":      spec.Auth,
		})
		if err != nil {
			failSystem(w, r, "node-2 加密套件下发失败："+err.Error())
			return
		}
		remote = out
	}
	if err := applyCryptoSuiteLocal(spec); err != nil {
		failSystem(w, r, "node-1 加密套件应用失败："+err.Error())
		return
	}
	setSetting(a, "crypto_suite", req.Suite)
	writeOK(w, r, map[string]interface{}{
		"suite": req.Suite, "label": spec.Label,
		"remote_node": remote,
		"notice":      "已切换并重启双节点；已有客户端需重新下载配置才能继续连接（新下载模板已跟随新套件）",
	})
}
