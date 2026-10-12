package main

// CA 轮换后的存量设备证书重签（#149 系统性缺口，2026-10-10）：
// devices 表持久化注册时签发的 cert_pem/key_pem——sub-CA 全链重签后存量证书全部失效
// （10-09 真机事故：一键连接 TLS VERIFY ERROR 卡死）。本接口用各设备**现有私钥**
// 按 certgen 同款模板（O=modsafe / 825天 / clientAuth / 随机素数序列号）以现行
// sub-CA 重签，更新 cert_pem/fingerprint；客户端在门户重新下载配置即恢复连接。
// 触发：POST /api/v1/internal/devices-reissue（internalAuthed 门禁：回环+共享令牌）。
// 注意：重签不影响 CRL（吊销设备保持旧证书失效状态，active 设备新序列号不在 CRL）。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

type deviceReissueResult struct {
	ID    int    `json:"id"`
	CN    string `json:"cn"`
	Error string `json:"error,omitempty"`
}

// reissueDeviceCert：用设备现有私钥重签（模板与 signClientCert 逐字段一致）
func reissueDeviceCert(cn string, key *rsa.PrivateKey) (certPEM, fingerprint string, err error) {
	serial, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return "", "", fmt.Errorf("serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"modsafe"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	caKey, caCrt, _ := pkiSnapshot() // 快照取当前 sub-CA（ca-renew 重载后即为新 CA）
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCrt, &key.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("sign: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sum := sha256.Sum256(der)
	fingerprint = "SHA256:" + hex.EncodeToString(sum[:])
	return certPEM, fingerprint, nil
}

// handleInternalDevicesReissue：重签全部 active 设备证书（幂等，可重复调用）
func (a *App) handleInternalDevicesReissue(w http.ResponseWriter, r *http.Request) {
	if !internalAuthed(r) {
		writeFail(w, r, 30002, http.StatusForbidden, "forbidden")
		return
	}
	if err := pkiInit(); err != nil {
		writeFail(w, r, 30002, http.StatusInternalServerError, "PKI 未就绪: "+err.Error())
		return
	}
	rows, err := a.db.Query(`SELECT id, cert_cn, key_pem FROM devices WHERE status='active'`)
	if err != nil {
		writeFail(w, r, 30002, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var results []deviceReissueResult
	reissued := 0
	for rows.Next() {
		var id int
		var cn, keyPEM string
		if err := rows.Scan(&id, &cn, &keyPEM); err != nil {
			continue
		}
		res := deviceReissueResult{ID: id, CN: cn}
		blk, _ := pem.Decode([]byte(keyPEM))
		if blk == nil {
			res.Error = "key pem 解码失败"
			results = append(results, res)
			continue
		}
		key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			res.Error = "key 解析失败（非 RSA PKCS1）"
			results = append(results, res)
			continue
		}
		certPEM, fp, err := reissueDeviceCert(cn, key)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		if _, err := a.db.Exec(`UPDATE devices SET cert_pem=?, fingerprint=? WHERE id=?`,
			certPEM, fp, id); err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		reissued++
		results = append(results, res)
	}
	writeOK(w, r, map[string]interface{}{
		"reissued": reissued,
		"results":  results,
	})
}
