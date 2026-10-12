package main

// 契约自测：status v3 解析 / conf 逐行编辑器 / 会话结算正则 / conntrack flows 过滤 /
// collector SQLite+API / agent HTTP 鉴权与 /ccd。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 注意：与 Python 版契约一致——status 日志为 TAB 分隔（本构建 status-version 配置所致）
const sampleStatusV3 = "OpenVPN STATISTICS\n" +
	"Updated,Mon Oct  9 17:00:00 2026\n" +
	"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tUsername\tClient ID\tBytes Received\tBytes Sent\tConnected Since\n" +
	"CLIENT_LIST\talice\tudp4:1.2.3.4:5000\t10.8.0.10\talice\t7\t1048576\t2097152\t2026-10-09 16:00:00\n" +
	"CLIENT_LIST\tbob\t5.6.7.8:5001\t10.8.0.11\tbob\t8\t100\t200\t2026-10-09 16:30:00\n" +
	"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\n" +
	"ROUTING_TABLE\t10.8.0.10\talice\t1.2.3.4:5000\t2026-10-09 16:00:00\n" +
	"END\n"

func TestParseStatus3(t *testing.T) {
	rows := parseStatus3Text(sampleStatusV3)
	if len(rows) != 2 {
		t.Fatalf("expect 2 clients, got %d", len(rows))
	}
	if rows[0]["Common Name"] != "alice" || rows[0]["Client ID"] != "7" {
		t.Fatalf("column mapping bad: %v", rows[0])
	}
	if stripProto(rows[0]["Real Address"]) != "1.2.3.4:5000" {
		t.Fatalf("stripProto bad: %s", rows[0]["Real Address"])
	}
	if stripProto("10.8.0.11:5001") != "10.8.0.11:5001" {
		t.Fatal("bare addr must pass through")
	}
}

func TestStatusSummary(t *testing.T) {
	tmp := t.TempDir()
	old := nodeStatusLog
	nodeStatusLog = filepath.Join(tmp, "status.log")
	defer func() { nodeStatusLog = old }()
	if err := os.WriteFile(nodeStatusLog, []byte(sampleStatusV3), 0o644); err != nil {
		t.Fatal(err)
	}
	m := statusSummary()
	if m["online"] != 2 {
		t.Fatalf("online bad: %v", m["online"])
	}
	if m["bytes_rx"] != 1048676 { // 1048576 + 100（int 类型）
		t.Fatalf("rx bad: %v", m["bytes_rx"])
	}
	sessions, _ := m["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("sessions bad: %v", len(sessions))
	}
	s0 := sessions[0].(map[string]any)
	if s0["username"] != "alice" || s0["cid"] != "7" {
		t.Fatalf("session row bad: %v", s0)
	}
}

func TestConfReplaceAuthToken(t *testing.T) {
	txt := "port 11941\nauth-gen-token 3600 external-auth\nserver 10.8.0.0 255.255.254.0\n"
	out, n := confReplaceAuthToken(txt, 7200)
	if n != 1 || !strings.Contains(out, "auth-gen-token 7200 external-auth") {
		t.Fatalf("replace bad: n=%d out=%s", n, out)
	}
	if !strings.Contains(out, "server 10.8.0.0 255.255.254.0") {
		t.Fatal("other lines must survive")
	}
}

func TestConfSetDataCiphers(t *testing.T) {
	txt := "data-ciphers AES-256-GCM:SM4-GCM\nauth SHA256\nauth-gen-token 3600 external-auth\ndata-ciphers OLD\n"
	out, n := confSetDataCiphers(txt, "SM4-GCM:AES-256-GCM")
	if n != 1 {
		t.Fatalf("auth anchor count bad: %d", n)
	}
	if strings.Contains(out, "data-ciphers OLD") || strings.Contains(out, "data-ciphers AES-256-GCM:SM4-GCM\n") {
		t.Fatalf("old data-ciphers lines must be removed: %s", out)
	}
	if !strings.Contains(out, "auth SHA256\ndata-ciphers SM4-GCM:AES-256-GCM") {
		t.Fatalf("insert position bad: %s", out)
	}
	if !strings.Contains(out, "auth-gen-token 3600 external-auth") {
		t.Fatal("auth-gen-token must not anchor insertion")
	}
}

func TestConfSetCertBinding(t *testing.T) {
	txt := "verify-client-cert require\ncrl-verify /root/modsafe-pki2/crl.pem\nmanagement-client-auth\nverb 3\n"
	out, n := confSetCertBinding(txt, "verify-client-cert none")
	if n != 1 || !strings.Contains(out, "management-client-auth\nverify-client-cert none") {
		t.Fatalf("cert binding edit bad: n=%d out=%s", n, out)
	}
	if strings.Contains(out, "crl-verify") {
		t.Fatal("old crl-verify must be removed in non-strict")
	}
}

func TestConfSetServerIPv6(t *testing.T) {
	txt := "server 10.8.0.0 255.255.254.0\nserver-ipv6 fdaa:2026:192:9::/64\n"
	out, changed := confSetServerIPv6(txt, true, "fdaa:2026:192:2::/64")
	if !changed || strings.Contains(out, "192:9::/64") || !strings.Contains(out, "server-ipv6 fdaa:2026:192:2::/64") {
		t.Fatalf("ipv6 enable bad: %s", out)
	}
	out2, changed2 := confSetServerIPv6(out, false, "")
	// Python 语义：disable 时 txt2 != txt（行确实被移除）→ changed=true 且不再含 server-ipv6
	if !changed2 || strings.Contains(out2, "server-ipv6") {
		t.Fatalf("ipv6 disable bad: changed=%v out=%s", changed2, out2)
	}
}

func TestConfReplaceServerLine(t *testing.T) {
	txt := "server 10.8.0.0 255.255.254.0\npush \"route 1.2.3.4\"\n"
	out, ok := confReplaceServerLine(txt, "10.8.2.0", "255.255.254.0")
	if !ok || !strings.Contains(out, "server 10.8.2.0 255.255.254.0") {
		t.Fatalf("server line replace bad: %s", out)
	}
}

func TestSessionLineRe(t *testing.T) {
	line1 := "2026-10-09 17:00:00 DISCONNECT username=alice common_name=alice trusted_ip=1.2.3.4:5000 vpn_ip=10.8.0.10 bytes_received=1024 bytes_sent=2048 duration=300"
	m := sessionLineRe.FindStringSubmatch(line1)
	if m == nil || m[1] != "alice" || m[2] != "alice" || m[3] != "1.2.3.4:5000" ||
		m[4] != "1024" || m[5] != "2048" || m[6] != "300" {
		t.Fatalf("with-username parse bad: %v", m)
	}
	line2 := "DISCONNECT common_name=cert-only trusted_ip=5.6.7.8:5001 bytes_received=10 bytes_sent=20 duration=5"
	m2 := sessionLineRe.FindStringSubmatch(line2)
	if m2 == nil || m2[1] != "" || m2[2] != "cert-only" {
		t.Fatalf("no-username parse bad: %v", m2)
	}
}

func TestParseFlows(t *testing.T) {
	text := "ipv4 2 tcp 6 120 TIME_WAIT src=10.8.0.5 dst=93.184.216.34 sport=40000 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=10.8.0.5 sport=443 dport=40000 packets=8 bytes=300\n" +
		"ipv6 2 udp 17 30 src=fdaa:2026:192:1::5 dst=2001:4860:4860::8888 sport=50000 dport=53 protocol=udp packets=2 bytes=160\n" +
		"ipv4 2 tcp 6 10 src=198.51.100.14 dst=8.8.8.8 sport=1 dport=53 bytes=99\n"
	flows := parseFlows(text)
	if len(flows) != 2 {
		t.Fatalf("expect 2 vpn flows, got %d: %v", len(flows), flows)
	}
	if flows[0]["src"] != "10.8.0.5" || flows[0]["proto"] != "tcp" ||
		flows[0]["port"] != 443 || flows[0]["bytes"] != 1500 {
		t.Fatalf("v4 flow bad: %v", flows[0])
	}
	if flows[1]["proto"] != "udp" || flows[1]["port"] != 53 {
		t.Fatalf("v6 flow bad: %v", flows[1])
	}
}

func TestCollectorDBAndAPI(t *testing.T) {
	tmp := t.TempDir()
	old := monitorDB
	monitorDB = filepath.Join(tmp, "monitor.db")
	defer func() { monitorDB = old }()
	if err := initDB(); err != nil {
		t.Fatal(err)
	}
	defer cdb.Close() // Windows 下不关句柄 TempDir 清理会失败
	if err := dbExec("INSERT INTO metrics(ts,node,active,online,bytes_rx,bytes_tx) VALUES(?,?,?,?,?,?)",
		nowUnix(), "node-1@180", 1, 3, 100, 200); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(collectorAPI())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	nodes, _ := out["nodes"].(map[string]any)
	n1, _ := nodes["node-1@180"].(map[string]any)
	if n1 == nil || n1["online"] != float64(3) || n1["bytes_rx_h"] != "0.0MB" {
		t.Fatalf("summary bad: %v", n1)
	}
	resp2, err := http.Get(srv.URL + "/sessions")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
}

func TestAgentAuthAndCCD(t *testing.T) {
	tmp := t.TempDir()
	oldTok, oldCcd := agentTokenFile, ccdDir
	agentTokenFile = filepath.Join(tmp, "admin-token")
	ccdDir = filepath.Join(tmp, "ccd")
	defer func() { agentTokenFile, ccdDir = oldTok, oldCcd }()
	if err := os.WriteFile(agentTokenFile, []byte("tok-xyz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ccdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(agentMux())
	defer srv.Close()

	// /healthz：Windows/Linux 下 systemctl is-active 非 active → 503（JSON 形状校验）
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var hz map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&hz)
	resp.Body.Close()
	if hz["service"] == nil {
		t.Fatalf("healthz shape bad: %v", hz)
	}

	// /flows 无令牌 → 403
	resp403, err := http.Get(srv.URL + "/flows")
	if err != nil {
		t.Fatal(err)
	}
	resp403.Body.Close()
	if resp403.StatusCode != 403 {
		t.Fatalf("flows no-token expect 403, got %d", resp403.StatusCode)
	}

	// /ccd 写入+删除（带令牌）
	req, _ := http.NewRequest("POST", srv.URL+"/ccd",
		strings.NewReader(`{"token":"tok-xyz","filename":"alice.conf","content":"push \"route 1.2.3.4\"\n"}`))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ccdOut map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&ccdOut)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || ccdOut["action"] != "written" {
		t.Fatalf("ccd write bad: %d %v", resp2.StatusCode, ccdOut)
	}
	if _, err := os.Stat(filepath.Join(ccdDir, "alice.conf")); err != nil {
		t.Fatal("ccd file missing:", err)
	}
	// 路径穿越文件名拒绝
	req2, _ := http.NewRequest("POST", srv.URL+"/ccd",
		strings.NewReader(`{"token":"tok-xyz","filename":"../evil.conf","content":"x"}`))
	resp3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 400 {
		t.Fatalf("traversal filename expect 400, got %d", resp3.StatusCode)
	}
	// 删除
	req3, _ := http.NewRequest("POST", srv.URL+"/ccd",
		strings.NewReader(`{"token":"tok-xyz","filename":"alice.conf","delete":true}`))
	resp4, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if _, err := os.Stat(filepath.Join(ccdDir, "alice.conf")); !os.IsNotExist(err) {
		t.Fatal("ccd delete failed")
	}
}
