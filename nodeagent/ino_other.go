//go:build !linux

package main

import "os"

// 非 Linux 平台无 syscall.Stat_t.Ino——轮转退化为仅 size 判定
func fileIno(st os.FileInfo) uint64 { return 0 }
