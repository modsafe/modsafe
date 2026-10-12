//go:build linux

package main

import (
	"os"
	"syscall"
)

// fileIno：Linux 取 inode（日志轮转 inode+size 双判）
func fileIno(st os.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}
