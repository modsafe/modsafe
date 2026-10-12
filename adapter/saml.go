package main

// §22 SAML 2.0 SP（对客户 IdP；对 oa2 仍是 OIDC——防腐层翻译）
// 验签走 crewjam/saml v0.5.1（goxmldsig；等价于 Python 版的 signxml+IdP 证书钉死），
// 覆盖：断言/响应级签名、Audience、Recipient、Destination、时间窗、InResponseTo、
// StatusCode=Success、防 Signature Wrapping。断言 ID 重放缓存（5min）为本模块自持。

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

var cryptoSHA256 = crypto.SHA256

var (
	samlSPCertPath = KEY_DIR + "/saml_sp.crt"
	samlSPKeyPath  = KEY_DIR + "/saml_sp.key"

	samlSigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	samlClockSkewDefault = 90
)

type samlAuthError struct{ msg string }

func (e *samlAuthError) Error() string { return e.msg }

func samlErr(format string, args ...any) error {
	return &samlAuthError{msg: fmt.Sprintf(format, args...)}
}

func samlCfg() map[string]any {
	c := idpc()["saml"]
	if c == nil {
		c = map[string]any{}
	}
	return c
}

func samlPublicBase() string {
	base := mStr(samlCfg(), "redirect_base")
	if base == "" {
		base = ADAPTER_BASE
	}
	return strings.TrimRight(base, "/")
}

func samlACSURL() string      { return samlPublicBase() + "/saml/acs" }
func samlMetadataURL() string { return samlPublicBase() + "/saml/metadata" }

func samlSPEntityID() string {
	e := strings.TrimSpace(mStr(samlCfg(), "sp_entity_id"))
	if e == "" {
		e = samlMetadataURL()
	}
	return e
}

// ---- SP 自签证书（AuthnRequest 重定向签名 + metadata KeyDescriptor；首次自动生成 10 年） ----

var spCertMu sync.Mutex

type spCertPair struct {
	certPEM string
	cert    *x509.Certificate
	key     *rsa.PrivateKey
}

func ensureSPCert() (spCertPair, error) {
	spCertMu.Lock()
	defer spCertMu.Unlock()

	keyPEM, kerr := os.ReadFile(samlSPKeyPath)
	certPEM, cerr := os.ReadFile(samlSPCertPath)
	if kerr == nil && cerr == nil {
		if blk, _ := pem.Decode(keyPEM); blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					if cb, _ := pem.Decode(certPEM); cb != nil {
						if c, err := x509.ParseCertificate(cb.Bytes); err == nil {
							return spCertPair{string(certPEM), c, rk}, nil
						}
					}
				}
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return spCertPair{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "modsafe-saml-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return spCertPair{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return spCertPair{}, err
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(samlSPKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return spCertPair{}, err
	}
	certPEMs := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := os.WriteFile(samlSPCertPath, []byte(certPEMs), 0o644); err != nil {
		return spCertPair{}, err
	}
	logf("SAML SP self-signed certificate generated: %s", samlSPCertPath)
	return spCertPair{certPEMs, cert, key}, nil
}

// samlSignQuery：SAML HTTP-Redirect 查询串签名（§3.4.4.1；RSASSA-PKCS1-v1_5(SHA256)）
func samlSignQuery(queryWithoutSignature string) ([]byte, error) {
	if _, err := ensureSPCert(); err != nil {
		return nil, err
	}
	spCertMu.Lock()
	defer spCertMu.Unlock()
	keyPEM, err := os.ReadFile(samlSPKeyPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("sp key pem invalid")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("sp key not rsa")
	}
	// SAML 规范 = RSASSA-PKCS1-v1_5(SHA256)：Go 需自行哈希（Python cryptography 内部哈希）
	digest := sha256.Sum256([]byte(queryWithoutSignature))
	return rsa.SignPKCS1v15(rand.Reader, rk, cryptoSHA256, digest[:])
}

// samlRedirectURL：HTTP-Redirect binding（raw-deflate+base64 AuthnRequest + 查询串签名）
func samlRedirectURL(internalState string) (string, error) {
	cfg := samlCfg()
	reqID := "_" + internalState // xsd:ID 不能以数字开头
	reqXML := samlBuildAuthnRequest(reqID, cfg)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(reqXML))
	_ = fw.Close()
	samlReq := base64.StdEncoding.EncodeToString(buf.Bytes())

	qs := "SAMLRequest=" + url.QueryEscape(samlReq) +
		"&RelayState=" + url.QueryEscape(internalState)
	signedQS := qs + "&SigAlg=" + url.QueryEscape(samlSigAlg)
	if mStr(cfg, "sign_requests") != "0" {
		sig, err := samlSignQuery(signedQS)
		if err != nil {
			return "", err
		}
		signedQS += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sso := mStr(cfg, "sso_url")
	sep := "?"
	if strings.Contains(sso, "?") {
		sep = "&"
	}
	return sso + sep + signedQS, nil
}

func samlBuildAuthnRequest(reqID string, cfg map[string]any) string {
	nidFmt := strings.TrimSpace(mStr(cfg, "name_id_format"))
	nid := `<samlp:NameIDPolicy AllowCreate="true"/>`
	if nidFmt != "" {
		nid = fmt.Sprintf(`<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>`, esc(nidFmt))
	}
	return fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" `+
			`ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s">`+
			`<saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest>`,
		esc(reqID), time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		esc(mStr(cfg, "sso_url")), esc(samlACSURL()),
		esc(samlSPEntityID()), nid)
}

// samlNormalizeCert：管理员输入容错（裸 base64 / PEM 取首张）→ 标准 PEM
func samlNormalizeCert(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	body := raw
	if strings.Contains(raw, "-----BEGIN CERTIFICATE-----") {
		start := strings.Index(raw, "-----BEGIN CERTIFICATE-----")
		end := strings.Index(raw[start:], "-----END CERTIFICATE-----")
		if end == -1 {
			return "", samlErr("IdP 证书 PEM 不完整")
		}
		body = raw[start+len("-----BEGIN CERTIFICATE-----") : start+end]
	}
	b64 := strings.Join(strings.Fields(body), "")
	if b64 == "" {
		return "", samlErr("IdP 证书为空")
	}
	var sb strings.Builder
	sb.WriteString("-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(b64); i += 64 {
		j := i + 64
		if j > len(b64) {
			j = len(b64)
		}
		sb.WriteString(b64[i:j])
		sb.WriteString("\n")
	}
	sb.WriteString("-----END CERTIFICATE-----")
	return sb.String(), nil
}

// ---- ACS 断言全量校验（通过返回 userinfo {sub,name,email,_groups}） ----
// form 取自 r（调用方先 r.ParseForm()，body 只读一次）

func samlValidateACS(r *http.Request, internalState string) (map[string]any, error) {
	form := r.PostForm
	if len(form) == 0 {
		form = r.Form
	}
	cfg := samlCfg()
	for _, k := range []string{"entity_id", "sso_url", "idp_certificate"} {
		if strings.TrimSpace(mStr(cfg, k)) == "" {
			return nil, samlErr("SAML 认证源未配置完整，请联系管理员")
		}
	}
	respB64 := form.Get("SAMLResponse")
	relay := form.Get("RelayState")
	if respB64 == "" || relay == "" {
		return nil, samlErr("缺少 SAMLResponse 或 RelayState")
	}
	if relay != internalState {
		return nil, samlErr("RelayState 与发起请求不匹配")
	}
	raw, err := base64.StdEncoding.DecodeString(respB64)
	if err != nil {
		return nil, samlErr("SAMLResponse 编码不合法")
	}
	if bytes.Contains(raw, []byte("EncryptedAssertion")) {
		return nil, samlErr("暂不支持加密断言（EncryptedAssertion），请让 IdP 以明文断言+签名发送")
	}

	pair, err := ensureSPCert()
	if err != nil {
		return nil, samlErr("SAML 组件初始化失败")
	}
	skew := samlClockSkewDefault
	if v := mInt(cfg, "clock_skew"); v > 0 {
		skew = v
	}
	saml.MaxClockSkew = time.Duration(skew) * time.Second

	acsURL, _ := url.Parse(samlACSURL())
	mdURL, _ := url.Parse(samlMetadataURL())
	idpCertB64, err := samlNormalizeCert(mStr(cfg, "idp_certificate"))
	if err != nil {
		return nil, err
	}
	idpB64 := strings.Join(strings.Fields(strings.TrimSuffix(
		strings.TrimPrefix(idpCertB64, "-----BEGIN CERTIFICATE-----"), "-----END CERTIFICATE-----")), "")

	sp := &saml.ServiceProvider{
		EntityID:    samlSPEntityID(),
		Key:         pair.key,
		Certificate: pair.cert,
		AcsURL:      *acsURL,
		MetadataURL: *mdURL,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: strings.TrimSpace(mStr(cfg, "entity_id")),
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					KeyDescriptors: []saml.KeyDescriptor{{Use: "signing",
						KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
							X509Certificates: []saml.X509Certificate{{Data: idpB64}},
						}}},
					},
				}},
				SingleSignOnServices: []saml.Endpoint{
					{Binding: saml.HTTPRedirectBinding, Location: mStr(cfg, "sso_url")},
					{Binding: saml.HTTPPostBinding, Location: mStr(cfg, "sso_url")},
				},
			}},
		},
	}
	assertion, err := sp.ParseResponse(r, []string{"_" + internalState})
	if err != nil {
		logf("saml signature verify FAILED: %v", err)
		return nil, samlMapVerifyError(err)
	}
	// Issuer 钉死（防"证书可信但断言来自别的实体"）
	if assertion.Issuer.Value != "" &&
		strings.TrimSpace(assertion.Issuer.Value) != strings.TrimSpace(mStr(cfg, "entity_id")) {
		return nil, samlErr("断言 Issuer 与配置的 entityID 不匹配")
	}
	// 重放：断言 ID 去重（不同 RelayState 重放同断言在此拦截）
	aid := assertion.ID
	if aid == "" {
		return nil, samlErr("断言缺少 ID")
	}
	if samlAssertionSeen(aid) {
		return nil, samlErr("断言重放被拒绝")
	}
	// 提取（只取验签后元素）
	sub := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		sub = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	if sub == "" {
		return nil, samlErr("断言缺少 NameID")
	}
	attrs := map[string][]string{}
	for _, st := range assertion.AttributeStatements {
		for _, a := range st.Attributes {
			var vals []string
			for _, v := range a.Values {
				vv := strings.TrimSpace(v.Value)
				if vv != "" {
					vals = append(vals, vv)
				}
			}
			if len(vals) > 0 {
				attrs[a.Name] = vals
			}
		}
	}
	first := func(names ...string) string {
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if vals, ok := attrs[n]; ok && len(vals) > 0 {
				return vals[0]
			}
		}
		return ""
	}
	name := first(mStr(cfg, "attr_name"), "displayName", "name", "commonName")
	if name == "" {
		name = sub
	}
	email := first(mStr(cfg, "attr_email"), "email", "mail", "emailAddress")

	groupKeys := []string{}
	for _, k := range strings.Split(mStr(cfg, "attr_groups"), ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			groupKeys = append(groupKeys, k)
		}
	}
	groupKeys = append(groupKeys, "groups", "memberOf")
	var groups []string
	for _, gk := range groupKeys {
		for _, v := range attrs[gk] {
			dup := false
			for _, g := range groups {
				if g == v {
					dup = true
					break
				}
			}
			if !dup {
				groups = append(groups, v)
			}
		}
	}
	var cleaned []string
	for _, g := range groups {
		if strings.Contains(g, "=") { // DN 形态（AD memberOf）→ 取 CN 段
			for _, part := range strings.Split(g, ",") {
				p := strings.TrimSpace(part)
				if len(p) >= 3 && strings.EqualFold(p[:3], "cn=") {
					g = p[3:]
					break
				}
			}
		}
		if g == "" {
			continue
		}
		dup := false
		for _, c := range cleaned {
			if c == g {
				dup = true
				break
			}
		}
		if !dup {
			cleaned = append(cleaned, g)
		}
	}
	if len(cleaned) > 50 {
		cleaned = cleaned[:50]
	}
	return map[string]any{"sub": sub, "name": name, "email": email, "_groups": cleaned}, nil
}

// samlMapVerifyError：crewjam 校验错误 → 用户可读文案（措辞不泄露内部细节）
func samlMapVerifyError(err error) error {
	msg := err.Error()
	var badStatus saml.ErrBadStatus
	if errors.As(err, &badStatus) {
		return samlErr("身份提供方返回认证未成功")
	}
	switch {
	case strings.Contains(msg, "Destination"):
		return samlErr("Destination 不匹配")
	case strings.Contains(msg, "InResponseTo"):
		return samlErr("InResponseTo 与发起请求不匹配")
	case strings.Contains(msg, "Audience"):
		return samlErr("Audience 与本系统 entityID 不匹配")
	case strings.Contains(msg, "expired"):
		return samlErr("断言已过期（检查服务器时钟）")
	case strings.Contains(msg, "not yet valid"):
		return samlErr("断言尚未生效（检查服务器时钟）")
	case strings.Contains(msg, "Issuer") || strings.Contains(msg, "issuer"):
		return samlErr("断言 Issuer 与配置的 entityID 不匹配")
	default:
		return samlErr("断言验签失败（签名与 IdP 证书不匹配或内容被篡改）")
	}
}

// ---- SP metadata（客户 IdP 管理员导入） ----

func samlSPMetadataXML() (string, error) {
	pair, err := ensureSPCert()
	if err != nil {
		return "", err
	}
	var b64 strings.Builder
	for _, line := range strings.Split(pair.certPEM, "\n") {
		if !strings.Contains(line, "-----") {
			b64.WriteString(strings.TrimSpace(line))
		}
	}
	return fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">`+"\n"+
			`  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`+"\n"+
			`    <md:KeyDescriptor use="signing">`+"\n"+
			`      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`+"\n"+
			`    </md:KeyDescriptor>`+"\n"+
			`    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>`+"\n"+
			`    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>`+"\n"+
			`    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>`+"\n"+
			`  </md:SPSSODescriptor>`+"\n"+
			`</md:EntityDescriptor>`,
		esc(samlSPEntityID()), b64.String(), esc(samlACSURL())), nil
}

// ---- §22.5 客户 IdP metadata 解析（管理台预填；encoding/xml 不处理外部实体，无 XXE 面） ----

type mdSSOService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type mdKeyDescriptor struct {
	Use     string `xml:"use,attr"`
	KeyInfo struct {
		X509Data struct {
			X509Certificates []struct {
				Data string `xml:",chardata"`
			} `xml:"X509Certificate"`
		} `xml:"X509Data"`
	} `xml:"KeyInfo"`
}

type mdIDPSSODescriptor struct {
	SingleSignOnServices []mdSSOService    `xml:"SingleSignOnService"`
	KeyDescriptors       []mdKeyDescriptor `xml:"KeyDescriptor"`
}

type mdEntityDescriptor struct {
	XMLName           xml.Name             `xml:"EntityDescriptor"`
	EntityID          string               `xml:"entityID,attr"`
	IDPSSODescriptors []mdIDPSSODescriptor `xml:"IDPSSODescriptor"`
}

type mdEntitiesDescriptor struct {
	XMLName  xml.Name             `xml:"EntitiesDescriptor"`
	Entities []mdEntityDescriptor `xml:"EntityDescriptor"`
}

func samlParseIDPMetadata(xmlText string) (map[string]any, error) {
	var ed mdEntityDescriptor
	if err := xml.Unmarshal([]byte(xmlText), &ed); err != nil || ed.EntityID == "" {
		var eds mdEntitiesDescriptor
		if err2 := xml.Unmarshal([]byte(xmlText), &eds); err2 != nil || len(eds.Entities) == 0 {
			return nil, fmt.Errorf("缺少 EntityDescriptor（确认上传的是 IdP metadata XML）")
		}
		ed = eds.Entities[0]
	}
	if len(ed.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("缺少 IDPSSODescriptor（不是 IdP metadata？）")
	}
	idp := ed.IDPSSODescriptors[0]
	ssoRedirect, ssoPost := "", ""
	for _, svc := range idp.SingleSignOnServices {
		if strings.HasSuffix(svc.Binding, "HTTP-Redirect") && ssoRedirect == "" {
			ssoRedirect = svc.Location
		} else if strings.HasSuffix(svc.Binding, "HTTP-POST") && ssoPost == "" {
			ssoPost = svc.Location
		}
	}
	ssoURL := firstNonEmpty(ssoRedirect, ssoPost)
	certB64 := ""
	for _, kd := range idp.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		certs := kd.KeyInfo.X509Data.X509Certificates
		if len(certs) > 0 && strings.TrimSpace(certs[0].Data) != "" {
			if strings.Contains(certs[0].Data, "-----BEGIN") {
				certB64 = strings.TrimSpace(certs[0].Data) // PEM 形态（非常见但容错）
			} else {
				certB64 = strings.Join(strings.Fields(certs[0].Data), "") // 裸 base64（标准形态）
			}
			break
		}
	}
	if ed.EntityID == "" || ssoURL == "" || certB64 == "" {
		return nil, fmt.Errorf("解析结果不完整（entityID/SSO/签名证书缺一不可）")
	}
	certPEM, err := samlNormalizeCert(certB64)
	if err != nil {
		return nil, fmt.Errorf("%s", err.(*samlAuthError).msg)
	}
	certNotAfter := ""
	if blk, _ := pem.Decode([]byte(certPEM)); blk != nil {
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			certNotAfter = c.NotAfter.Format("2006-01-02")
		}
	}
	return map[string]any{
		"entity_id":       strings.TrimSpace(ed.EntityID),
		"sso_url":         ssoURL,
		"idp_certificate": certPEM,
		"cert_not_after":  certNotAfter,
	}, nil
}
