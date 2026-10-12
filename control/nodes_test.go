package main

// status 解析卫生单测（2026-10-08 导出脏数据修复）：
// DCO 启用后 Real Address 带 udp4:/tcp6: 等协议前缀，解析层必须剥离为裸 IP:port

import "testing"

func TestStripAddrProto(t *testing.T) {
	cases := map[string]string{
		"udp4:171.34.236.222:25293": "171.34.236.222:25293",
		"udp6:[fd00::1]:1194":       "[fd00::1]:1194",
		"tcp4:198.51.100.13:62998":  "198.51.100.13:62998",
		"tcp6:[::ffff:1.2.3.4]:443": "[::ffff:1.2.3.4]:443",
		"198.51.100.13:50825":       "198.51.100.13:50825", // 无前缀原样
		"":                          "",
		"weird:1.2.3.4:80":          "weird:1.2.3.4:80", // 非协议前缀不剥
	}
	for in, want := range cases {
		if got := stripAddrProto(in); got != want {
			t.Fatalf("stripAddrProto(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStatusBytesStripsProto(t *testing.T) {
	status := "HEADER,CLIENT_LIST\n" +
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tUsername\tBytes Received\tBytes Sent\tConnected Since\n" +
		"CLIENT_LIST\tu1-cn\tudp4:1.2.3.4:5555\t10.8.2.2\tu1\t100\t200\t2026-10-08 20:00:00\n"
	rows := parseStatusBytes([]byte(status))
	if len(rows) != 1 {
		t.Fatalf("expect 1 row, got %d", len(rows))
	}
	if got := rows[0]["trusted_ip"].(string); got != "1.2.3.4:5555" {
		t.Fatalf("trusted_ip = %q, want 1.2.3.4:5555", got)
	}
	if got := rows[0]["username"].(string); got != "u1" {
		t.Fatalf("username = %q", got)
	}
}
