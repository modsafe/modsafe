package main

// reissueDeviceCert 单测：临时 sub-CA + 设备密钥 → 重签 → 链验证/指纹/模板字段断言

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testSubCA(t *testing.T) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	oldSubcaCrt, oldSubcaKey := subcaCrt, subcaKey
	subcaCrt, subcaKey = crt, caKey
	t.Cleanup(func() { subcaCrt, subcaKey = oldSubcaCrt, oldSubcaKey })
}

func TestReissueDeviceCert(t *testing.T) {
	testSubCA(t)
	devKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certPEM, fp, err := reissueDeviceCert("卢致榕", devKey)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatal("pem decode fail")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if crt.Subject.CommonName != "卢致榕" || len(crt.Subject.Organization) != 1 || crt.Subject.Organization[0] != "modsafe" {
		t.Fatalf("subject bad: %v", crt.Subject)
	}
	if !crt.BasicConstraintsValid || crt.IsCA {
		t.Fatal("basicConstraints bad")
	}
	if len(crt.ExtKeyUsage) != 1 || crt.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("EKU bad")
	}
	crtPub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok || crtPub.N.Cmp(devKey.N) != 0 {
		t.Fatal("cert public key mismatch with device key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(subcaCrt)
	if _, err := crt.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+64 {
		t.Fatalf("fingerprint format bad: %s", fp)
	}
	sum := sha256.Sum256(blk.Bytes)
	if fp != "SHA256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint value mismatch")
	}
}
