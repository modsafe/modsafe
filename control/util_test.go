package main

// remoteIP 单测（#124 审计来源 IP 修复）：
// 优先级 X-Real-IP → X-Forwarded-For 首跳 → RemoteAddr；
// 多级 XFF 取首跳；X-Real-IP 存在时压过 XFF（nginx 显式覆盖不可伪造）。

import (
	"net/http/httptest"
	"testing"
)

func TestRemoteIPForwarded(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xrip   string
		xff    string
		want   string
	}{
		{"no headers uses RemoteAddr", "10.1.2.3:5678", "", "", "10.1.2.3"},
		{"x-real-ip wins", "127.0.0.1:1", "203.0.113.7", "198.51.100.1, 10.0.0.1", "203.0.113.7"},
		{"xff first hop", "127.0.0.1:1", "", "198.51.100.1, 10.0.0.1", "198.51.100.1"},
		{"xff single value", "127.0.0.1:1", "", "192.0.2.9", "192.0.2.9"},
		{"xff trimmed", "127.0.0.1:1", "", " 192.0.2.9 , 10.0.0.2", "192.0.2.9"},
		{"no port remoteaddr fallback", "10.9.9.9", "", "", "10.9.9.9"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xrip != "" {
			r.Header.Set("X-Real-IP", tc.xrip)
		}
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := remoteIP(r); got != tc.want {
			t.Errorf("%s: remoteIP=%s want %s", tc.name, got, tc.want)
		}
	}
}
