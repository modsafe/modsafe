package main

// 证书与身份绑定（接入安全开关，2026-09-30 #61）：
// off（默认）＝现状：证书仅是准入凭据（verify-client-cert none），扫码者与证书属主可不同人。
// strict＝三层绑定：
//   1) verify-client-cert require——证书必须真实（sub-CA 签发）且未吊销（crl-verify），
//      后台吊销设备从此在 TLS 层即时作废其配置文件；
//   2) oa2 CEL 校验（--oauth2.validate.expression）：openvpn.commonName in token.claims['cert_cns']
//      ——证书 CN 必须属于扫码者名下的有效设备证书列表（列表由 auth-check 实时回传、
//      adapter 注入 id_token claim；他人拿到 .ovpn 用自己账号扫码会被拒绝）；
//   3) CEL 表达式经 oa2 unit drop-in 环境变量注入（OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION）。
// 切换为打断性操作（双节点 openvpn+oa2 重启，~4s），前端二次确认。

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const certBindingCEL = "openvpn.commonName in token.claims['cert_cns']"

func certBinding(a *App) string {
	return getSetting(a, "cert_identity_binding", "off")
}

// generateCRL：全量重生成 CRL（revoked 设备证书 serial 集合，sub-CA 签发，30 天有效）。
// 无吊销条目时生成空 CRL——strict 模式下 crl-verify 指向的文件必须存在。
func generateCRL(a *App) ([]byte, error) {
	if err := pkiInit(); err != nil {
		return nil, err
	}
	rows, err := a.db.Query(`SELECT COALESCE(cert_pem,'') FROM devices
		WHERE status='revoked' AND COALESCE(cert_pem,'')<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []x509.RevocationListEntry{}
	for rows.Next() {
		var certPEM string
		if rows.Scan(&certPEM) != nil {
			continue
		}
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: crt.SerialNumber, RevocationTime: time.Now(),
		})
	}
	now := time.Now()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(63), nil))
	rl := &x509.RevocationList{
		Number:                    serial,
		ThisUpdate:                now,
		NextUpdate:                now.Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	caKey, caCrt, _ := pkiSnapshot() // 锁内快照（ca-renew 重载后 CRL 即由新 sub-CA 签名）
	der, err := x509.CreateRevocationList(rand.Reader, rl, caCrt, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// renderCertBindingConf：conf 改写（幂等：先删全部 verify-client-cert/crl-verify 行再按目标插入）
func renderCertBindingConf(content string, strict bool) string {
	vccRe := regexp.MustCompile(`^verify-client-cert .*$`)
	crlRe := regexp.MustCompile(`^crl-verify .*$`)
	mcaRe := regexp.MustCompile(`^management-client-auth`)
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+2)
	inserted := false
	for _, line := range lines {
		if vccRe.MatchString(line) || crlRe.MatchString(line) {
			continue
		}
		out = append(out, line)
		if mcaRe.MatchString(line) && !inserted {
			if strict {
				out = append(out, "verify-client-cert require",
					"crl-verify "+crlPath)
			} else {
				out = append(out, "verify-client-cert none")
			}
			inserted = true
		}
	}
	if !inserted { // conf 无 management-client-auth 锚点时追加到末尾
		if strict {
			out = append(out, "verify-client-cert require", "crl-verify "+crlPath)
		} else {
			out = append(out, "verify-client-cert none")
		}
	}
	return strings.Join(out, "\n")
}

// node-1 conf/CRL 路径支持 MODSAFE_NODE1_CONF / MODSAFE_PKI_DIR 覆盖（安装器 v2 归一布局）
var (
	nodeConfPath  = envOr("MODSAFE_NODE1_CONF", "/etc/openvpn/instances/node-1.conf")
	crlPath       = envOr("MODSAFE_CRL", envOr("MODSAFE_PKI_DIR", "/root/modsafe-pki2")+"/crl.pem")
	oa2DropInDir  = "/etc/systemd/system/oa2-modsafe@1.service.d"
	oa2DropInFile = oa2DropInDir + "/90-cert-binding.conf"
)

// applyCertBindingLocal：本机 node-1 conf + CRL + oa2 drop-in（CEL）+ 双服务重启
func applyCertBindingLocal(strict bool, crlPEM []byte) error {
	raw, err := os.ReadFile(nodeConfPath)
	if err != nil {
		return err
	}
	tmp := nodeConfPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(renderCertBindingConf(string(raw), strict)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, nodeConfPath); err != nil {
		return err
	}
	if strict {
		if err := os.WriteFile(crlPath, crlPEM, 0o644); err != nil {
			return err
		}
		if err := os.MkdirAll(oa2DropInDir, 0o755); err != nil {
			return err
		}
		env := "[Service]\nEnvironment=\"OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION=" + certBindingCEL + "\"\n"
		if err := os.WriteFile(oa2DropInFile, []byte(env), 0o644); err != nil {
			return err
		}
	} else {
		_ = os.Remove(oa2DropInFile)
		_ = os.Remove(crlPath)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "restart", "oa2-modsafe@1").Run()
	_ = exec.Command("systemctl", "restart", "openvpn-modsafe@1").Run()
	return nil
}

// pushCRL：CRL 全量重生成并推送双节点（吊销设备后即时生效；strict 模式才被 crl-verify 引用）
func (a *App) pushCRL() error {
	crlPEM, err := generateCRL(a)
	if err != nil {
		return err
	}
	if err := os.WriteFile(crlPath, crlPEM, 0o644); err != nil {
		return err
	}
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		if _, err := agentRequest(nodes[i], "POST", "/crl", map[string]interface{}{
			"crl": string(crlPEM),
		}); err != nil {
			return err
		}
	}
	return nil
}

// handleCertBindingGet：GET /api/v1/settings/cert-binding
func (a *App) handleCertBindingGet(w http.ResponseWriter, r *http.Request) {
	b := certBinding(a)
	label := "关闭（证书仅作准入凭据，扫码者与证书属主可为不同人）"
	if b == "strict" {
		label = "严格（证书必须真实有效且属于扫码者本人；吊销设备即时作废其配置）"
	}
	writeOK(w, r, map[string]interface{}{"binding": b, "label": label, "nodes": []string{"node-1@180", "node-2@193"}})
}

// handleCertBindingPut：PUT /api/v1/settings/cert-binding {binding, confirm_impact}
func (a *App) handleCertBindingPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Binding        string `json:"binding"`
		ConfirmImpact  bool   `json:"confirm_impact"`
	}
	if err := jsonDecode(r, &req); err != nil || (req.Binding != "off" && req.Binding != "strict") || !req.ConfirmImpact {
		failParam(w, r, "binding 必须为 off|strict，且需 confirm_impact 确认打断性影响")
		return
	}
	strict := req.Binding == "strict"
	var crlPEM []byte
	if strict {
		var err error
		crlPEM, err = generateCRL(a)
		if err != nil {
			failSystem(w, r, "CRL 生成失败："+err.Error())
			return
		}
	}
	// 先远端（193）后本机，与加密套件切换同序
	for i := range nodes {
		if nodes[i].Kind != "agent" {
			continue
		}
		payload := map[string]interface{}{"strict": strict}
		if strict {
			payload["crl"] = string(crlPEM)
		}
		if _, err := agentRequest(nodes[i], "POST", "/cert-binding", payload); err != nil {
			failSystem(w, r, "node-2 证书绑定下发失败："+err.Error())
			return
		}
	}
	if err := applyCertBindingLocal(strict, crlPEM); err != nil {
		failSystem(w, r, "node-1 证书绑定应用失败："+err.Error())
		return
	}
	setSetting(a, "cert_identity_binding", req.Binding)
	notice := "已切换并重启双节点（openvpn+oa2，约 4 秒中断）。"
	if strict {
		notice += "严格模式生效：证书必须真实且属于扫码者；吊销设备将立即作废其配置文件。"
	} else {
		notice += "已恢复宽松模式：证书仅作准入凭据。"
	}
	writeOK(w, r, map[string]interface{}{"binding": req.Binding, "notice": notice})
}
