package main

// 证书续期（#133/#135）：openvpn PKI（pkiDir）到期处理，管理台 super_admin 操作。
//
// PKI 结构：ca.crt（root，自签）→ server.crt（服务端）+ modsafe-client-subca（客户端签发子 CA，
// certgen 用它在线签客户端证书）；ca-chain.crt = root+subca 束，客户端 .ovpn <ca> 内联。
//
// 两个端点：
//   POST /settings/cert/server-renew —— 只重签服务端证书（同 CA 重签，.ovpn 无需更新）。
//   POST /settings/cert/ca-renew    —— 全链重签：root CA（品牌化主题+10y）→ 服务端证书 →
//                                      client-subca → 重新生成 ca-chain.crt。
// 平滑性说明（2026-10-11 修订）：所有重签**沿用原私钥**（只换证书体），但重签同时
// 更换证书主题 DN（品牌化，modsafe-*→Modsafe）——旧配置内嵌的旧 <ca> 无法为新 DN
// 链建路径，旧客户端证书/旧配置在全链重签后即失效（10-09 真机事故实证：存量证书全部
// TLS VERIFY ERROR），**不存在**"旧配置可用到旧 CA 自然到期"的平滑过渡。续期后须：
// ① 通知全员到门户重新下载配置；② 触发存量设备重签（POST /api/v1/internal/devices-reissue，#149）。
//
// 品牌化（#135）：重签的证书主题统一 Modsafe（此前为 modsafe-*），旧 openSec/modsafe 字样随换发消除。
// 节点 1 重载 = management 口 SIGHUP；节点 2（193）文件不在控制面可达范围 → 返回手工同步指引。
// root CA 旧证书到期（2027-09-26）后旧配置失效——续期后须引导用户重新下载配置。

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// #135：重签证书的品牌化主题（不再使用 modsafe-*/openSec 旧标识）
func brandSubject(cn string) pkix.Name {
	return pkix.Name{Organization: []string{"Modsafe"}, CommonName: cn, Country: []string{"CN"}}
}

const (
	brandCNCA     = "Modsafe CA"
	brandCNServer = "Modsafe Server"
	brandCNSubCA  = "Modsafe Client CA"
)

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("证书 PEM 解码失败: %s", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func readSignerFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("私钥 PEM 解码失败: %s", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("密钥类型不支持签名")
		}
		return s, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("私钥解析失败（PKCS8/PKCS1/EC 均不支持）")
}

// atomicWritePEM：备份原文件（.bak-<ts>）后经 .tmp 原子替换
func atomicWritePEM(path, blockType string, der []byte) error {
	return atomicWriteRaw(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// atomicWriteRaw：原子替换写入（已是最终字节，如多证书 PEM 束）
func atomicWriteRaw(path string, data []byte) error {
	if data, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak-"+time.Now().Format("20060102-150405"), data, 0o644)
	}
	tmp := path + ".renew"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换 %s 失败: %w", filepath.Base(path), err)
	}
	return nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// resolveKeyFile：私钥定位——优先给定目录；根 CA 私钥按安全实践离线保管
//（MODSAFE_PKI_OFFLINE_DIR，默认 /root/modsafe-pki2-offline-backup，仅含 ca.key），
// 续期时从离线目录读入内存签名，**不回写在线目录**（离线保管不破）。
func resolveKeyFile(dir, name string) string {
	if p := filepath.Join(dir, name); fileExists(p) {
		return p
	}
	return filepath.Join(envOr("MODSAFE_PKI_OFFLINE_DIR", "/root/modsafe-pki2-offline-backup"), name)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// reissue：用签发方（证书+密钥）按品牌主题重签一张同密钥证书
func reissue(subject pkix.Name, old *x509.Certificate, pub any, issuerCert *x509.Certificate, issuerKey crypto.Signer, validity time.Duration) ([]byte, *x509.Certificate, error) {
	notBefore := time.Now().Add(-time.Hour)
	notAfter := issuerCert.NotAfter.Add(-24 * time.Hour) // 不得超过签发方有效期
	if d := notBefore.Add(validity); d.Before(notAfter) {
		notAfter = d
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              old.KeyUsage,
		ExtKeyUsage:           old.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  old.IsCA,
		MaxPathLen:            old.MaxPathLen,
		MaxPathLenZero:        old.MaxPathLenZero,
		IPAddresses:           old.IPAddresses,
		DNSNames:              old.DNSNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, pub, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

// renewServerCert：只重签服务端证书（同 CA 重签，.ovpn 内嵌 <ca> 不变，无需重新下发）
func renewServerCert(dir string) (*x509.Certificate, error) {
	caCert, err := readCertFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("读 CA 证书: %w", err)
	}
	caKey, err := readSignerFile(resolveKeyFile(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("读 CA 私钥: %w", err)
	}
	old, err := readCertFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return nil, fmt.Errorf("读服务端证书: %w", err)
	}
	serverKey, err := readSignerFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, fmt.Errorf("读服务端私钥: %w", err)
	}
	der, newCert, err := reissue(brandSubject(brandCNServer), old, serverKey.Public(), caCert, caKey, 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if err := atomicWritePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", der); err != nil {
		return nil, err
	}
	return newCert, nil
}

// renewCACert：全链重签——root CA（自签换发+10y，品牌化主题）→ 服务端证书 → client-subca，
// 并重新生成 ca-chain.crt（root+subca 束，新下载的 .ovpn 内联新链）。
// 旧私钥全部沿用（换发不要求重签已发密钥）；但主题 DN 已换，旧配置/旧证书即时失效
//（非平滑过渡，见文件头注释；调用方须随后 pkiReload 换装控制面内存 PKI）。
func renewCACert(dir string) (caNew, srvNew, subNew *x509.Certificate, err error) {
	caCert, err := readCertFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读 root CA 证书: %w", err)
	}
	caKey, err := readSignerFile(resolveKeyFile(dir, "ca.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读 root CA 私钥: %w", err)
	}
	srvOld, err := readCertFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读服务端证书: %w", err)
	}
	srvKey, err := readSignerFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读服务端私钥: %w", err)
	}
	subOld, err := readCertFile(filepath.Join(dir, "modsafe-client-subca.crt"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读客户端子 CA 证书: %w", err)
	}
	subKey, err := readSignerFile(filepath.Join(dir, "modsafe-client-subca.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读客户端子 CA 私钥: %w", err)
	}

	// ① root CA 换发（自签，品牌化主题，+10 年）
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               brandSubject(brandCNCA),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              caCert.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("重签 root CA 失败: %w", err)
	}
	caNew, err = x509.ParseCertificate(caDer)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := atomicWritePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDer); err != nil {
		return nil, nil, nil, err
	}

	// ② 服务端证书（新 CA 签发）
	srvDer, srvC, err := reissue(brandSubject(brandCNServer), srvOld, srvKey.Public(), caNew, caKey, 10*365*24*time.Hour)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("重签服务端证书: %w", err)
	}
	srvNew = srvC
	if err := atomicWritePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", srvDer); err != nil {
		return nil, nil, nil, err
	}

	// ③ client-subca 换发（同子 CA 私钥，客户端已签证书继续有效）
	subDer, subC, err := reissue(brandSubject(brandCNSubCA), subOld, subKey.Public(), caNew, caKey, 5*365*24*time.Hour)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("重签客户端子 CA: %w", err)
	}
	subNew = subC
	if err := atomicWritePEM(filepath.Join(dir, "modsafe-client-subca.crt"), "CERTIFICATE", subDer); err != nil {
		return nil, nil, nil, err
	}

	// ④ 重新生成 ca-chain.crt（root+subca，与原束同序：root 在前）。
	// 注意：束内已是完整 PEM 块，必须用 atomicWriteRaw 原样写入（atomicWritePEM 会再包一层 PEM=损坏）
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subDer})...)
	if err := atomicWriteRaw(filepath.Join(dir, "ca-chain.crt"), chain); err != nil {
		return nil, nil, nil, err
	}
	return caNew, srvNew, subNew, nil
}

// reloadLocalNode：节点 1 经 management 口 SIGHUP（openvpn 重读证书，客户端瞬断自动重连）
func reloadLocalNode() error {
	if len(nodes) == 0 {
		return fmt.Errorf("无节点配置")
	}
	s, err := acquireMgmtSlot(nodes[0].MgmtSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("management 槽位未获取: %w", err)
	}
	defer s.Close()
	resp, err := mgmtCommand(s, "signal SIGHUP")
	if err != nil {
		return err
	}
	if resp != "" && !strings.Contains(resp, "SUCCESS") && !strings.Contains(resp, "OK") {
		return fmt.Errorf("SIGHUP 响应异常: %s", strings.SplitN(resp, "\n", 2)[0])
	}
	return nil
}

// POST /api/v1/settings/cert/server-renew（super_admin）：
// 只重签服务端证书 + 重载节点 1；节点 2 返回同步指引。
func (a *App) handleCertServerRenew(w http.ResponseWriter, r *http.Request) {
	newCert, err := renewServerCert(pkiDir())
	if err != nil {
		failSystem(w, r, err.Error())
		return
	}
	reloadErr := reloadLocalNode()
	status := "reloaded"
	hint := ""
	if reloadErr != nil {
		status = "renewed-reload-failed"
		hint = "节点 1 重载失败（" + reloadErr.Error() + "），请手工执行：systemctl restart openvpn-modsafe@1"
	}
	hint += " 节点 2（193）需手工同步：scp 本机 " + filepath.Join(pkiDir(), "server.crt") +
		" 到 193 同路径后执行 systemctl restart openvpn-modsafe@2。"
	a.auditAdminAction(r, claimsOf(r).Username, "POST", "/api/v1/settings/cert/server-renew",
		"success "+status+" not_after="+newCert.NotAfter.Format("2006-01-02"), "")
	writeOK(w, r, map[string]interface{}{
		"ok": true, "status": status,
		"not_after":  newCert.NotAfter.Format("2006-01-02 15:04:05"),
		"node2_hint": hint,
	})
}

// POST /api/v1/settings/cert/ca-renew（super_admin）：
// 全链重签（root CA + 服务端证书 + client-subca + ca-chain 束）+ 重载节点 1
// + 重载控制面内存 PKI（SEC-2/BIZ-1：不重载则签发/<ca> 渲染/CRL/到期展示继续用旧 CA）。
// 续期后所有用户必须重新下载配置（主题 DN 已换，旧配置即时失效），并触发 #149 存量设备重签。
func (a *App) handleCertCARenew(w http.ResponseWriter, r *http.Request) {
	caNew, srvNew, subNew, err := renewCACert(pkiDir())
	if err != nil {
		failSystem(w, r, err.Error())
		return
	}
	// 内存 PKI 换装：全链重签已落盘，控制面签发/<ca> 内嵌/CRL 签名/到期展示立即切新
	if rerr := pkiReload(); rerr != nil {
		log.Printf("[ca-renew] 内存 PKI 重载失败（控制面仍用旧 CA，签发/渲染将异常，请重试）: %v", rerr)
	}
	reloadErr := reloadLocalNode()
	status := "reloaded"
	hint := ""
	if reloadErr != nil {
		status = "renewed-reload-failed"
		hint = "节点 1 重载失败（" + reloadErr.Error() + "），请手工执行：systemctl restart openvpn-modsafe@1"
	}
	hint += " 节点 2（193）需手工同步以下文件到同路径并执行 systemctl restart openvpn-modsafe@2：" +
		filepath.Join(pkiDir(), "ca.crt") + "、server.crt、ca-chain.crt、modsafe-client-subca.crt。 " +
		"续期后请立即通知所有用户到门户重新下载配置（重签更换主题 DN，旧配置即时失效），" +
		"并调用 POST /api/v1/internal/devices-reissue 重签存量设备证书。"
	a.auditAdminAction(r, claimsOf(r).Username, "POST", "/api/v1/settings/cert/ca-renew",
		fmt.Sprintf("success %s ca_not_after=%s server_not_after=%s subca_not_after=%s",
			status, caNew.NotAfter.Format("2006-01-02"), srvNew.NotAfter.Format("2006-01-02"), subNew.NotAfter.Format("2006-01-02")), "")
	writeOK(w, r, map[string]interface{}{
		"ok": true, "status": status,
		"ca_not_after":     caNew.NotAfter.Format("2006-01-02 15:04:05"),
		"server_not_after": srvNew.NotAfter.Format("2006-01-02 15:04:05"),
		"subca_not_after":  subNew.NotAfter.Format("2006-01-02 15:04:05"),
		"node2_hint":       hint,
	})
}
