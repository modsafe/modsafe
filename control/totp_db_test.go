package main

// 现场对照：命令行传入 secret 与时间窗，打印三窗口码（供与服务器 Python 输出比对）
// go test -run TestTotpDump -v -args XXG4... 59706967

import (
	"encoding/base32"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestTotpDump(t *testing.T) {
	args := os.Args
	// 末参必须是十进制时间窗，否则视为普通 go test 运行（旗标会混入 os.Args）→ 跳过
	var w0 int64
	if len(args) < 3 {
		t.Skip("need secret")
	}
	if _, err := fmt.Sscanf(args[len(args)-1], "%d", &w0); err != nil {
		t.Skip("need -args <secret> <window>")
	}
	secret := args[len(args)-2]
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []int64{-1, 0, 1} {
		fmt.Printf("win=%d code=%s\n", w0+w, totpCode(key, (w0+w)*30))
	}
	_ = time.Now()
}
