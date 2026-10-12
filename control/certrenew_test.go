package main

// 证书续期单测（#133/#135）：
// TestRenewServerCert —— 只重签服务端证书：签发者=CA、公钥不变、SAN 保留、有效期封顶、链验证、落盘。
// TestRenewCACertChain —— 全链重签：新 CA 品牌化主题、服务端/子 CA 随签、ca-chain 束重生成、
//                        旧私钥沿用（客户端证书在新链下继续有效=平滑过渡的关键断言）。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestKey(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestCert(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeTestPKI：生成临时 PKI——root CA（1 年，CN=modsafe-CA）+ 服务端证书 + client-subca（5 年）。
// 返回 CA 私钥（供离线回退测试使用）与各证书。
func makeTestPKI(t *testing.T, dir string) (caKey *rsa.PrivateKey, caCert *x509.Certificate, subcaKey *rsa.PrivateKey, srvKey *rsa.PrivateKey, now time.Time) {
	t.Helper()
	now = time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "modsafe-CA", Organization: []string{"modsafe"}, Country: []string{"CN"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, filepath.Join(dir, "ca.key"), caKey)
	writeTestCert(t, filepath.Join(dir, "ca.crt"), caDer)

	subcaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	subTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "modsafe-ClientSubCA", Organization: []string{"modsafe"}, Country: []string{"CN"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	subDer, err := x509.CreateCertificate(rand.Reader, subTmpl, caCert, &subcaKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, filepath.Join(dir, "modsafe-client-subca.key"), subcaKey)
	writeTestCert(t, filepath.Join(dir, "modsafe-client-subca.crt"), subDer)

	srvKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "modsafe-server", Organization: []string{"modsafe"}, Country: []string{"CN"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("198.51.100.10"), net.ParseIP("198.51.100.12")},
		DNSNames:     []string{"ac.t.example.com"},
	}
	srvDer, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, filepath.Join(dir, "server.key"), srvKey)
	writeTestCert(t, filepath.Join(dir, "server.crt"), srvDer)

	// ca-chain 束（root+subca，与生产一致——续期前就存在）
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subDer})...)
	if err := os.WriteFile(filepath.Join(dir, "ca-chain.crt"), chain, 0o644); err != nil {
		t.Fatal(err)
	}
	return caKey, caCert, subcaKey, srvKey, now
}

func TestRenewServerCert(t *testing.T) {
	dir := t.TempDir()
	_, caCert, _, srvKey, now := makeTestPKI(t, dir)

	newCert, err := renewServerCert(dir)
	if err != nil {
		t.Fatalf("renewServerCert: %v", err)
	}

	// 品牌化主题 + 签发者=CA、公钥不变、SAN 保留
	if newCert.Subject.CommonName != brandCNServer || newCert.Subject.Organization[0] != "Modsafe" {
		t.Fatalf("主题未品牌化: %v", newCert.Subject)
	}
	if newCert.Issuer.CommonName != caCert.Subject.CommonName {
		t.Fatalf("issuer = %v", newCert.Issuer)
	}
	oldKeyPub := srvKey.PublicKey.N
	if newCert.PublicKey.(*rsa.PublicKey).N.Cmp(oldKeyPub) != 0 {
		t.Fatal("公钥必须保持不变（SPKI 稳定）")
	}
	if len(newCert.IPAddresses) != 2 || newCert.DNSNames[0] != "ac.t.example.com" {
		t.Fatalf("SAN 丢失: %v %v", newCert.IPAddresses, newCert.DNSNames)
	}
	if !newCert.NotAfter.Before(caCert.NotAfter.Add(-23 * time.Hour)) {
		t.Fatalf("NotAfter %v 未封顶到 CA 到期-24h", newCert.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := newCert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		t.Fatalf("新证书链验证失败: %v", err)
	}
	again, err := readCertFile(filepath.Join(dir, "server.crt"))
	if err != nil || again.SerialNumber.Cmp(newCert.SerialNumber) != 0 {
		t.Fatal("落盘文件未替换")
	}
}

func TestRenewCACertChain(t *testing.T) {
	dir := t.TempDir()
	_, oldCA, subcaKey, srvKey, now := makeTestPKI(t, dir)

	caNew, srvNew, subNew, err := renewCACert(dir)
	if err != nil {
		t.Fatalf("renewCACert: %v", err)
	}

	// 新 CA：品牌化主题 + 10 年 + 自签（同密钥）
	if caNew.Subject.CommonName != brandCNCA || caNew.Subject.Organization[0] != "Modsafe" {
		t.Fatalf("新 CA 主题未品牌化: %v", caNew.Subject)
	}
	if !caNew.NotAfter.After(now.Add(9 * 365 * 24 * time.Hour)) {
		t.Fatalf("新 CA 有效期不足 10 年: %v", caNew.NotAfter)
	}
	if caNew.PublicKey.(*rsa.PublicKey).N.Cmp(oldCA.PublicKey.(*rsa.PublicKey).N) != 0 {
		t.Fatal("CA 私钥必须沿用（下游签名继续有效的关键）")
	}

	// 服务端/子 CA：新 CA 签发、公钥不变、品牌化主题
	if srvNew.Issuer.CommonName != brandCNCA || srvNew.Subject.CommonName != brandCNServer {
		t.Fatalf("服务端证书主题/签发者异常: %v / %v", srvNew.Issuer, srvNew.Subject)
	}
	if srvNew.PublicKey.(*rsa.PublicKey).N.Cmp(srvKey.PublicKey.N) != 0 {
		t.Fatal("服务端公钥必须保持不变")
	}
	if subNew.Subject.CommonName != brandCNSubCA || !subNew.IsCA {
		t.Fatalf("子 CA 主题/属性异常: %v IsCA=%v", subNew.Subject, subNew.IsCA)
	}
	if subNew.PublicKey.(*rsa.PublicKey).N.Cmp(subcaKey.PublicKey.N) != 0 {
		t.Fatal("子 CA 公钥必须保持不变")
	}

	// ca-chain 束：恰含新 CA + 新子 CA 两块
	chainData, err := os.ReadFile(filepath.Join(dir, "ca-chain.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(chainData), "BEGIN CERTIFICATE"); got != 2 {
		t.Fatalf("ca-chain 应含 2 张证书，实际 %d", got)
	}

	// 平滑过渡的关键断言：用子 CA 私钥新签一张客户端证书，
	// 仅凭新 ca-chain（无旧 CA）即可完成链验证（certgen 续期后继续签发可用）
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "client-test"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDer, err := x509.CreateCertificate(rand.Reader, clientTmpl, subNew, &clientKey.PublicKey, subcaKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientDer)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟客户端 <ca> 内联：解析 ca-chain 束的两张证书作为锚
	roots := x509.NewCertPool()
	rest := chainData
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(c)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("续期后客户端证书链验证失败: %v", err)
	}

	// 旧证书备份应存在
	for _, f := range []string{"ca.crt", "server.crt", "modsafe-client-subca.crt", "ca-chain.crt"} {
		if m, _ := filepath.Glob(filepath.Join(dir, f+".bak-*")); len(m) == 0 {
			t.Fatalf("%s 缺少续期前备份", f)
		}
	}
}

// #136 生产故障回归：根 CA 私钥离线保管（在线目录无 ca.key），续期必须从
// MODSAFE_PKI_OFFLINE_DIR 读入内存签名——不回写在线目录（离线保管不破）。
func TestRenewWithOfflineCAKey(t *testing.T) {
	dir := t.TempDir()
	offline := t.TempDir()
	caKey, _, subcaKey, srvKey, now := makeTestPKI(t, dir)

	// 在线目录移除 ca.key（模拟生产：根密钥离线保管），离线目录放入匹配的 ca.key
	os.Remove(filepath.Join(dir, "ca.key"))
	writeTestKey(t, filepath.Join(offline, "ca.key"), caKey)

	// 环境变量指向离线目录
	t.Setenv("MODSAFE_PKI_OFFLINE_DIR", offline)

	caNew, srvNew, subNew, err := renewCACert(dir)
	if err != nil {
		t.Fatalf("离线密钥续期失败: %v", err)
	}
	if caNew.Subject.CommonName != brandCNCA || srvNew.Subject.CommonName != brandCNServer || subNew.Subject.CommonName != brandCNSubCA {
		t.Fatalf("主题未品牌化: %v / %v / %v", caNew.Subject, srvNew.Subject, subNew.Subject)
	}
	// 离线目录的密钥未被复制回在线目录（离线保管不破）
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(err) {
		t.Fatal("根 CA 私钥不得回写在线目录")
	}
	// 新链可验证
	roots := x509.NewCertPool()
	roots.AddCert(caNew)
	if _, err := srvNew.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		t.Fatalf("新服务端证书链验证失败: %v", err)
	}
	_ = subcaKey
	_ = srvKey
}
