package main

// 轻量限速（内存滑动窗口）：登录暴破防护与自助门户高频操作冷却。
// 定位是纵深防御的一层，不追求精确——重启清零可接受。

import (
	"sync"
	"time"
)

type rlBucket struct {
	events []time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
	window  time.Duration
	limit   int
}

var (
	loginLimiter  = newRL(5*time.Minute, 10)  // 登录失败窗口限：10 次/5min
	selfGenCooler = newRL(1*time.Minute, 2)   // 门户自助生成配置：2 次/min（防 generate↔revoke 循环 DoS）
)

func newRL(window time.Duration, limit int) *rateLimiter {
	return &rateLimiter{buckets: map[string]*rlBucket{}, window: window, limit: limit}
}

// allow：滑动窗口内第 limit+1 次返回 false
func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &rlBucket{}
		l.buckets[key] = b
	}
	keep := b.events[:0]
	for _, t := range b.events {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	b.events = keep
	if len(b.events) >= l.limit {
		return false
	}
	b.events = append(b.events, now)
	if len(l.buckets) > 10000 { // 防键空间无限膨胀
		l.buckets = map[string]*rlBucket{}
	}
	return true
}

// 限速键约定（各调用点内联构造）：
//   admin|IP          管理台登录
//   portal|IP|用户名   门户本地登录（NAT 共享 IP 下按用户名分桶，避免互相锁死）
//   internal|用户名    oa2 验密反查（调用方恒为 127.0.0.1，IP 维度无意义）
