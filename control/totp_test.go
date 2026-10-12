package main

// TOTP 与参考实现的对照测试（Python 侧同 secret 同时刻应产出相同码）

import (
	"encoding/base32"
	"fmt"
	"testing"
)

func TestTotpVector(t *testing.T) {
	// RFC 6238 附录 B 测试密钥（SHA1，8 位数字口径）：
	// T=59 → 94287082；用 6 位口径应为 287082
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	got := totpCode(key, 59)
	want := "287082"
	if got != want {
		t.Fatalf("RFC6238 vector mismatch: got=%s want=%s", got, want)
	}
	fmt.Println("vector OK:", got)
}
