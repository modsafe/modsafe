package main

// §15 客户端配置自动生成：sub-CA 在线签发客户端证书（root 离线，sub-CA 仅签客户端）
// PKI 路径：/root/modsafe-pki2/（env MODSAFE_PKI_DIR 可覆盖）
//   modsafe-client-subca.key/.crt  在线签发用
//   ca-chain.crt                  root+subca 链束（客户端 <ca> 内联）
//   ta.key                        tls-auth（客户端 direction 1）

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	pkiMu    sync.Mutex // 保护下列全局的换装：ca-renew 后 pkiReload 重载，读方经 pkiSnapshot 取快照（SEC-2/BIZ-1）
	pkiOnce  sync.Once
	pkiReady error
	subcaKey *rsa.PrivateKey
	subcaCrt *x509.Certificate
	caChain  []byte // PEM（root+subca）
	taKey    []byte // tls-auth static key
)

func pkiDir() string { return envOr("MODSAFE_PKI_DIR", "/root/modsafe-pki2") }

func loadPKI() error {
	keyPEM, err := os.ReadFile(filepath.Join(pkiDir(), "modsafe-client-subca.key"))
	if err != nil {
		return fmt.Errorf("read subca key: %w", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return fmt.Errorf("subca key PEM decode 失败")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey) // 类型断言带检查：非 RSA 密钥直接报错而非 panic
		if !ok {
			return fmt.Errorf("subca key 不是 RSA 私钥")
		}
		key = rk
	} else if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		key = k
	} else {
		return fmt.Errorf("subca key 解析失败（PKCS1/PKCS8 均不支持）")
	}

	crtPEM, err := os.ReadFile(filepath.Join(pkiDir(), "modsafe-client-subca.crt"))
	if err != nil {
		return fmt.Errorf("read subca crt: %w", err)
	}
	cb, _ := pem.Decode(crtPEM)
	if cb == nil {
		return fmt.Errorf("subca crt PEM decode 失败")
	}
	crt, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fmt.Errorf("parse subca crt: %w", err)
	}

	chain, err := os.ReadFile(filepath.Join(pkiDir(), "ca-chain.crt"))
	if err != nil {
		return fmt.Errorf("read ca-chain: %w", err)
	}
	ta, err := os.ReadFile(filepath.Join(pkiDir(), "ta.key"))
	if err != nil {
		return fmt.Errorf("read ta.key: %w", err)
	}
	// 全部解析成功后才锁内换装内存全局（读方 pkiSnapshot 持同一把锁取快照，杜绝撕裂读）
	pkiMu.Lock()
	subcaKey, subcaCrt, caChain, taKey = key, crt, chain, ta
	pkiMu.Unlock()
	return nil
}

func pkiInit() error {
	pkiOnce.Do(func() { pkiReady = loadPKI() })
	return pkiReady
}

// pkiReload：重载内存 PKI（ca-renew 全链重签落盘后必须调用，SEC-2/BIZ-1 根因修复：
// 此前 sync.Once 一次性加载、renew 后从不重载，签发/<ca> 渲染/CRL/到期展示会继续
// 用旧 sub-CA/旧链直到进程重启）
func pkiReload() error { return loadPKI() }

// pkiSnapshot：读取当前内存 PKI（锁内拷贝引用；与 pkiReload 的换装互斥）
func pkiSnapshot() (*rsa.PrivateKey, *x509.Certificate, []byte) {
	pkiMu.Lock()
	defer pkiMu.Unlock()
	return subcaKey, subcaCrt, caChain
}

// signClientCert：CN=username，825 天，KU/EKU 严格 clientAuth（M0 踩坑修复项）
// 返回 certPEM / keyPEM / 指纹
func signClientCert(username string) (certPEM, keyPEM, fingerprint string, err error) {
	if err := pkiInit(); err != nil {
		return "", "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	serial, _ := rand.Prime(rand.Reader, 128)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"modsafe"},
			CommonName:   username,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	caKey, caCrt, _ := pkiSnapshot() // 快照取当前 sub-CA（ca-renew 后为重载的新 CA）
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCrt, &key.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("sign: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	sum := sha256.Sum256(der)
	fingerprint = "SHA256:" + hex.EncodeToString(sum[:])
	return certPEM, keyPEM, fingerprint, nil
}
