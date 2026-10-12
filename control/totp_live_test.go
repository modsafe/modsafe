package main

// 与 Python 参考实现的现时对照：同 secret 当前时刻码，打印供外部比对

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

func TestTotpLiveCompare(t *testing.T) {
	secret := "XXG4PBSHKKYUWPSCSXWKRIHPE4K2RYHO"
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, w := range []int64{-1, 0, 1} {
		fmt.Printf("win=%+d code=%s (t=%d)\n", w, totpCode(key, now+w*30), (now+w*30)/30)
	}
}
