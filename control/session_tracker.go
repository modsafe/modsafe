package main

// 会话追踪器：每 5s 对 liveSessions() 做 diff，控制平面自持会话台账。
// 相比 collector 的 disconnect 脚本 tail（只覆盖 node-1 本机日志），
// 本方案用户名归属来自 status 的 Username 列（准确），且天然覆盖全部节点。

import (
	"log"
	"time"
)

// trackerInterval：diff 周期（DSF-6，P2 轻量收紧：15s→5s）。
// 依据：DSF-3（explicit-exit-notify 3）生效后，UDP 客户端主动断开即时通知服务端 →
// 服务端立刻摘会话、status 文件 10s 内刷新 → tracker 5s diff，端到端约 15s 内可感知；
// 未带该指令的存量配置走服务端 keepalive 兜底（默认 ping 10 / ping-restart 30），
// 约 40s 内可感知。只改采样密度，不改 diff/结算语义。
const trackerInterval = 5 * time.Second

type sessKey struct {
	node        string
	vip         string
	connectedAt string // 重连接口复用同一 VIP，必须纳入键才能区分"被踢→重连"
}

type trackedSess struct {
	username     string
	trustedIP    string
	connectedAt  string
	in, out      int64
	dbID         int64
	lastActivity time.Time // 最后一次字节增长时刻（空闲自动断开的依据）；重启后重置为 now=宽限
}

// idlePolicySettings：每次 tick 读取（1 query/5s，代价可忽略）
func (a *App) idlePolicySettings() (timeoutMinutes int, ignoreUsers map[string]bool) {
	ignoreUsers = map[string]bool{}
	if v := getSetting(a, "session_idle_timeout", "0"); v != "" {
		n := 0
		ok := true
		for _, c := range v { // 单循环累加，遇非数字整体判无效（双循环曾把 "12x" 解析成 192）
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if ok {
			timeoutMinutes = n
		}
	}
	for _, u := range splitCommaList(getSetting(a, "session_idle_ignore_users", "ha-test-client")) {
		if u != "" {
			ignoreUsers[u] = true
		}
	}
	return timeoutMinutes, ignoreUsers
}

func splitCommaList(s string) []string {
	out := []string{}
	cur := ""
	for _, c := range s {
		if c == ',' || c == '，' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}

// StartSessionTracker：周期 diff 快照，维护 sessions 台账（active→settled）
func (a *App) StartSessionTracker() {
	prev := map[sessKey]*trackedSess{}
	for {
		cur := map[sessKey]*trackedSess{}
		deltas := map[string][]dailyDelta{} // day -> []{username, in, out}（每 tick 批量落库）
		for _, s := range liveSessions() {
			username, _ := s["username"].(string)
			node, _ := s["node"].(string)
			vip, _ := s["virtual_ip"].(string)
			if username == "" || vip == "" {
				continue
			}
			in, _ := s["bytes_in"].(int64)
			out, _ := s["bytes_out"].(int64)
			if fin, ok := s["bytes_in"].(float64); ok {
				in = int64(fin)
			}
			if fout, ok := s["bytes_out"].(float64); ok {
				out = int64(fout)
			}
			trustedIP, _ := s["trusted_ip"].(string)
			connectedAt, _ := s["connected_at"].(string)
			cur[sessKey{node, vip, connectedAt}] = &trackedSess{
				username: username, trustedIP: trustedIP, connectedAt: connectedAt,
				in: in, out: out, lastActivity: time.Now(),
			}
		}

		// 僵尸在账自愈（2026-10-08）：崩溃窗口可能跳过"消失结算"，留下永久"在线"行
		//（污染在线数与导出）。活会话每 5s 刷 last_seen，48h 阈值绝不误伤真在线
		_, _ = a.db.Exec(`UPDATE sessions SET settled=1 WHERE settled=0
			AND COALESCE(last_seen,'') <> '' AND last_seen < datetime('now','localtime','-48 hours')`)

		// 存续会话：流量有增长 → 刷新活动时刻（空闲判定依据）；无增长 → 继承 prev 的时刻
		for k, s := range cur {
			if p, ok := prev[k]; ok {
				s.dbID = p.dbID
				if s.in == p.in && s.out == p.out {
					s.lastActivity = p.lastActivity
				}
				// 按日增量记账（§流量按日归属）：本 tick 的字节增量记入当天。
				// 仅有 prev 时才计（重启后首 tick 以当前计数为基线，杜绝双计）；
				// 跨午夜会话的每 5s 增量自然归属各自当天。
				if s.in > p.in || s.out > p.out {
					deltas[dayKey()] = append(deltas[dayKey()],
						dailyDelta{username: s.username, in: s.in - p.in, out: s.out - p.out})
				}
			}
		}

		// 空闲自动断开（§会话策略）：默认关闭（timeout=0）；ignore 名单跳过（机器通道等）
		timeoutMin, ignored := a.idlePolicySettings()
		if timeoutMin > 0 {
			now := time.Now()
			for k, s := range cur {
				if s.username == "" || ignored[s.username] {
					continue
				}
				if idle := now.Sub(s.lastActivity); idle > time.Duration(timeoutMin)*time.Minute {
					log.Printf("[idle-kick] %s@%s 空闲 %s 超过阈值 %d 分钟，执行断开",
						s.username, k.node, idle.Round(time.Second), timeoutMin)
					nodeCfg := findNode(k.node)
					if nodeCfg != nil {
						// 传 VIP 做会话级精确踢线：同用户多设备时只断空闲的那台
						res := kickOnNode(*nodeCfg, "", false, k.vip)
						log.Printf("[idle-kick] %s@%s 结果: %v", s.username, k.node, res)
					}
					// 防止客户端重连完成前每个 tick 重复踢
					s.lastActivity = now
				}
			}
		}

		// 新出现的会话：入库（cid 用纳秒时间戳保证唯一）
		for k, s := range cur {
			if _, ok := prev[k]; ok {
				continue
			}
			var existing int64
			_ = a.db.QueryRow(`SELECT cid FROM sessions WHERE username=? AND virtual_ip=? AND settled=0`,
				s.username, k.vip).Scan(&existing)
			if existing > 0 {
				// 已有未结算台账（如进程重启丢快照）：复用
				s.dbID = existing
				continue
			}
			cid := time.Now().UnixNano()
			_, err := a.db.Exec(`INSERT INTO sessions(cid, username, virtual_ip, trusted_ip, connected_at,
				bytes_in, bytes_out, cipher, node, last_seen, settled) VALUES(?,?,?,?,?,?,?,?,?,datetime('now','localtime'),0)`,
				cid, s.username, k.vip, s.trustedIP, s.connectedAt, s.in, s.out, "", k.node)
			if err != nil {
				log.Printf("[tracker] insert: %v", err)
				continue
			}
			s.dbID = cid
		}
		// 存续会话：更新流量
		for k, s := range cur {
			if s.dbID == 0 {
				_ = a.db.QueryRow(`SELECT cid FROM sessions WHERE username=? AND virtual_ip=? AND connected_at=? AND settled=0`,
					s.username, k.vip, k.connectedAt).Scan(&s.dbID)
			}
			if s.dbID > 0 {
				_, _ = a.db.Exec(`UPDATE sessions SET bytes_in=?, bytes_out=?, last_seen=datetime('now','localtime')
					WHERE cid=? AND settled=0`, s.in, s.out, s.dbID)
			}
		}
		// 消失的会话：结算。红线（DSF-1）：数据不可用节点的会话本轮一律跳过——
		// 节点监控路径故障 ≠ 用户断开（保留 2026-09-29 防误结算语义；节点恢复后
		// 会话重新出现在快照，走既有未结算行复用，不丢账）
		noData := staleNodes()
		for k, s := range prev {
			if _, ok := cur[k]; ok {
				continue
			}
			if noData[k.node] {
				continue
			}
			// 结算优先按行主键（BIZ-7，2026-10-11）：进程重启窗口内「断开→重连」复用旧行时，
			// 行内 connected_at 与新会话不一致，按三元组匹配 UPDATE 不到该行 → 卡 settled=0
			// 「在线」最长 48h 才被僵尸自愈。dbID 经 insert/复用/兜底查询三路都会赋值，
			// 仅极罕见的 0 值回退旧三元组条件。
			var err error
			if s.dbID > 0 {
				_, err = a.db.Exec(`UPDATE sessions SET bytes_in=?, bytes_out=?, settled=1,
					last_seen=datetime('now','localtime') WHERE cid=? AND settled=0`, s.in, s.out, s.dbID)
			} else {
				_, err = a.db.Exec(`UPDATE sessions SET bytes_in=?, bytes_out=?, settled=1,
					last_seen=datetime('now','localtime') WHERE username=? AND virtual_ip=? AND connected_at=? AND settled=0`,
					s.in, s.out, s.username, k.vip, k.connectedAt)
			}
			if err != nil {
				log.Printf("[tracker] settle: %v", err)
			}
		}
		prev = cur
		a.flushDailyDeltas(deltas)
		time.Sleep(trackerInterval)
	}
}

// dailyDelta：单会话单 tick 的字节增量
type dailyDelta struct {
	username string
	in, out  int64
}

func dayKey() string {
	return time.Now().Format("2006-01-02")
}

// flushDailyDeltas：把本 tick 的按日增量批量写入 traffic_daily（事务，失败仅记日志不影响台账）
func (a *App) flushDailyDeltas(deltas map[string][]dailyDelta) {
	if len(deltas) == 0 {
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		log.Printf("[tracker] daily tx begin: %v", err)
		return
	}
	defer tx.Rollback()
	n := 0
	for day, list := range deltas {
		for _, d := range list {
			if _, err := tx.Exec(`INSERT INTO traffic_daily(username, day, bytes_in, bytes_out) VALUES(?,?,?,?)
				ON CONFLICT(username, day) DO UPDATE SET
				bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out`,
				d.username, day, d.in, d.out); err != nil {
				log.Printf("[tracker] daily upsert: %v", err)
				return
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tracker] daily commit: %v", err)
		return
	}
	log.Printf("[tracker] daily deltas: %d 条已入账", n)
}
