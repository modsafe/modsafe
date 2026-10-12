package main

// 多通道告警通知（notify.py 的 Go 移植，与 modsafe-adapter/notify.go 同源同语义）：
// wecom/dingtalk/feishu/generic webhook + email；SSRF 边界（环回/链路本地/私网默认拒绝）。

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var alertChannelsFile = "/opt/modsafe/alert-channels.json"

var NOTIFY_ALLOW_PRIV = false // 由 main 按环境变量初始化

func init() {
	alertChannelsFile = envPath("MODSAFE_ALERT_CHANNELS", alertChannelsFile)
}

func loadChannels() map[string]any {
	if raw, ok := loadJSONFile(alertChannelsFile); ok {
		return raw
	}
	return map[string]any{"channels": []any{}, "email": map[string]any{"enabled": false}}
}

func ssrfReject(target string) string {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "invalid url (only http/https)"
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return "dns resolve failed"
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return "loopback/link-local blocked"
		}
		if ip.IsPrivate() && !NOTIFY_ALLOW_PRIV {
			return "private target blocked (MODSAFE_NOTIFY_ALLOW_PRIVATE=1 to allow)"
		}
	}
	return ""
}

func postJSONWebhook(target string, obj any, timeout time.Duration) string {
	if reason := ssrfReject(target); reason != "" {
		return "blocked: " + reason
	}
	resp, err := httpJSON(target, "POST", map[string]string{"Content-Type": "application/json"}, obj, timeout)
	if err != nil {
		return "FAILED: " + err.Error()
	}
	s := truncateStr(fmt.Sprintf("%v", resp), 200)
	if s == "" || s == "map[]" {
		return "ok"
	}
	return s
}

func sendWecom(url_, text string) string {
	return "wecom: " + postJSONWebhook(url_, map[string]any{
		"msgtype": "markdown", "markdown": map[string]any{"content": text}}, 10*time.Second)
}

func sendDingtalk(url_, text string) string {
	return "dingtalk: " + postJSONWebhook(url_, map[string]any{
		"msgtype": "markdown", "markdown": map[string]any{"title": "modsafe 告警", "text": text}}, 10*time.Second)
}

func sendFeishu(url_, text string) string {
	return "feishu: " + postJSONWebhook(url_, map[string]any{
		"msg_type": "text", "content": map[string]any{"text": text}}, 10*time.Second)
}

func sendGeneric(url_, level, message string, ts int64) string {
	return "generic: " + postJSONWebhook(url_, map[string]any{
		"level": level, "message": message, "ts": ts}, 10*time.Second)
}

func sendEmail(emailCfg map[string]any, subject, text string) (string, error) {
	host := mStr(emailCfg, "smtp_host")
	if host == "" {
		return "", fmt.Errorf("smtp_host empty")
	}
	port := 465
	if p := mInt(emailCfg, "smtp_port"); p > 0 {
		port = p
	}
	useSSL := port == 465
	if b, ok := emailCfg["smtp_ssl"].(bool); ok {
		useSSL = b
	}
	addr := host + ":" + strconv.Itoa(port)
	from := mStr(emailCfg, "from_addr")
	toAny, _ := emailCfg["to_addrs"].([]any)
	var toAddrs []string
	for _, t := range toAny {
		if s := fmt.Sprintf("%v", t); s != "" {
			toAddrs = append(toAddrs, s)
		}
	}
	if len(toAddrs) == 0 {
		return "", fmt.Errorf("to_addrs empty")
	}

	var conn net.Conn
	var err error
	if useSSL {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return "", err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer client.Close()
	if !useSSL {
		client.Hello("localhost")
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return "", err
			}
		}
	}
	if user := mStr(emailCfg, "username"); user != "" {
		auth := smtp.PlainAuth("", user, mStr(emailCfg, "password"), host)
		if err := client.Auth(auth); err != nil {
			return "", err
		}
	}
	if err := client.Mail(from); err != nil {
		return "", err
	}
	for _, rcpt := range toAddrs {
		if err := client.Rcpt(rcpt); err != nil {
			return "", err
		}
	}
	wr, err := client.Data()
	if err != nil {
		return "", err
	}
	b64Body := base64.StdEncoding.EncodeToString([]byte(text))
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + strings.Join(toAddrs, ", ") + "\r\n")
	sb.WriteString("Subject: " + mimeQEncoding(subject) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	for i := 0; i < len(b64Body); i += 76 {
		j := i + 76
		if j > len(b64Body) {
			j = len(b64Body)
		}
		sb.WriteString(b64Body[i:j] + "\r\n")
	}
	if _, err := wr.Write([]byte(sb.String())); err != nil {
		return "", err
	}
	if err := wr.Close(); err != nil {
		return "", err
	}
	if err := client.Quit(); err != nil {
		return "", err
	}
	return "email: sent to " + strings.Join(toAddrs, ", "), nil
}

func mimeQEncoding(s string) string {
	needs := false
	for _, ch := range s {
		if ch > 127 || ch < 32 {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var out strings.Builder
	out.WriteString("=?utf-8?q?")
	for _, b := range []byte(s) {
		switch {
		case b == ' ':
			out.WriteByte('_')
		case b == '=' || b == '?' || b == '_':
			out.WriteString(fmt.Sprintf("=%02X", b))
		case b >= 33 && b <= 126:
			out.WriteByte(b)
		default:
			out.WriteString(fmt.Sprintf("=%02X", b))
		}
	}
	out.WriteString("?=")
	return out.String()
}

// notifyAll：向所有启用通道分发告警，返回各通道结果列表
func notifyAll(level, message string, ts int64) []string {
	var results []string
	tag := "严重"
	if level == "warn" {
		tag = "警告"
	}
	title := fmt.Sprintf("[modsafe %s] %s", tag, truncateStr(firstLine(message), 60))
	icon := "🔴 严重"
	if level == "warn" {
		icon = "⚠️ 警告"
	}
	text := fmt.Sprintf("**[modsafe %s]**\n\n%s\n\n时间：%d", icon, message, ts)
	cfg := loadChannels()
	channels, _ := cfg["channels"].([]any)
	for _, it := range channels {
		ch, _ := it.(map[string]any)
		if ch == nil || !mBool(ch, "enabled") {
			continue
		}
		t := mStr(ch, "type")
		webhook := mStr(ch, "webhook")
		var r string
		switch t {
		case "wecom":
			r = sendWecom(webhook, text)
		case "dingtalk":
			r = sendDingtalk(webhook, text)
		case "feishu":
			r = sendFeishu(webhook, text)
		default:
			r = sendGeneric(webhook, level, message, ts)
		}
		if strings.HasPrefix(r, "FAILED") || strings.HasPrefix(r, "blocked") {
			results = append(results, fmt.Sprintf("%s(%s) FAILED: %s", t, mStr(ch, "name"), r))
		} else {
			results = append(results, r)
		}
	}
	email, _ := cfg["email"].(map[string]any)
	if email != nil && mBool(email, "enabled") {
		toAny, _ := email["to_addrs"].([]any)
		if len(toAny) > 0 {
			if _, err := sendEmail(email, title, message); err != nil {
				results = append(results, "email FAILED: "+err.Error())
			} else {
				var addrs []string
				for _, t := range toAny {
					addrs = append(addrs, fmt.Sprintf("%v", t))
				}
				results = append(results, "email: sent to "+strings.Join(addrs, ", "))
			}
		}
	}
	return results
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
