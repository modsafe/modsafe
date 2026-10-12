package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// lsLastGood：每节点最近一次成功快照。数据源瞬断（agent 重启/5xx/超时、status 文件
// 被 logrotate 瞬时替换）时沿用上次数据，而不是把"整节点会话消失"当作真实断开
// ——否则 tracker 一个周期就误结算全部会话、恢复后重复建行（2026-09-29 修复）。
// 2026-10-11（DSF-1）：缓存从"无限期沿用"收紧为 TTL——超龄后该节点本轮无数据，
// 杜绝 openvpn 停止/status 文件残留导致的"永远在线"；local 节点增加 mtime 新鲜度校验。
//
// 三个阈值集中定义，相互关系：statusFreshTTL 判定"本轮回传数据是否可信"（status
// 文件约 10s 刷新一次，60s 未动 = openvpn 大概率已停止，残留内容不可信）；
// lsCacheTTL 决定"数据不可用后旧快照最多再顶多久"（须 > statusFreshTTL，否则一次
// 判死过快），超龄后该节点本轮无数据（列表少该节点，台账不结算其会话）；
// onlineFreshTTL 供 DSF-2 台账口径在线判定（sessions.last_seen 距今超限不算在线），
// 须 ≥ trackerInterval(5s) 的数倍，容忍台账周期刷新的抖动。
const (
	lsCacheTTL     = 90 * time.Second // 数据源失败后，上次成功快照最多沿用 90s，超龄即弃用
	statusFreshTTL = 60 * time.Second // local 节点 status 文件 mtime 超过 60s 视为过期（等价数据不可用）
	onlineFreshTTL = 60 * time.Second // 在线判定新鲜度（DSF-2：sessions.last_seen 阈值）
)

var (
	lsMu          sync.Mutex
	lsLastGood    = map[string][]map[string]interface{}{}
	lsLastGoodAt  = map[string]time.Time{} // 每节点最后成功拉取时刻（缓存 TTL 判定基准）
	lsUnavailable = map[string]bool{}      // 本轮数据不可用的节点（staleNodes 暴露给 tracker）
)

// staleNodes：最近一轮 liveSessions 中数据不可用的节点（拷贝快照）。
// tracker 的「消失结算」必须跳过这些节点的会话——节点监控路径故障 ≠ 用户断开。
func staleNodes() map[string]bool {
	lsMu.Lock()
	defer lsMu.Unlock()
	out := make(map[string]bool, len(lsUnavailable))
	for k := range lsUnavailable {
		out[k] = true
	}
	return out
}

// onlineFreshCond：DSF-2 台账口径在线判定的 last_seen 新鲜度 SQL 片段（阈值同 onlineFreshTTL）
func onlineFreshCond() string {
	return fmt.Sprintf("datetime('now','localtime','-%d seconds')", int(onlineFreshTTL.Seconds()))
}

// liveSessions：聚合全部节点实时在线会话（node-1 读 status 文件；node-2 走 node-agent /sessions）
func liveSessions() []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, node := range nodes {
		var list []map[string]interface{}
		ok := false
		reason := ""
		if node.Kind == "agent" {
			out0, err := agentRequest(node, "GET", "/sessions", nil)
			if err != nil {
				reason = "agent 拉取失败: " + err.Error()
			} else {
				sessions, _ := out0["sessions"].([]interface{})
				for _, raw := range sessions {
					m, alright := raw.(map[string]interface{})
					if !alright {
						continue
					}
					list = append(list, map[string]interface{}{
						"username":     m["username"],
						"common_name":  m["common_name"],
						"virtual_ip":   m["virtual_address"],
						"trusted_ip":   m["real_address"],
						"connected_at": m["connected_since"],
						"bytes_in":     m["bytes_received"],
						"bytes_out":    m["bytes_sent"],
						"node":         node.Name,
					})
				}
				ok = true
			}
		} else {
			list, ok = parseStatusFileChecked(node.StatusFile)
			if !ok {
				reason = "status 文件读取/解析失败"
			} else if fi, serr := os.Stat(node.StatusFile); serr != nil {
				// mtime 新鲜度校验（DSF-1）：openvpn 停止后 status 文件残留最后内容，
				// mtime 过期 = 数据不可用，与读取失败走同一缓存/TTL 路径
				ok = false
				list = nil
				reason = "status 文件 stat 失败: " + serr.Error()
			} else if time.Since(fi.ModTime()) > statusFreshTTL {
				ok = false
				list = nil
				reason = "status 文件 mtime 超过新鲜度阈值（openvpn 可能已停止，残留内容不可信）"
			}
			for _, m := range list {
				m["node"] = node.Name
			}
		}
		now := time.Now()
		lsMu.Lock()
		if ok {
			lsLastGood[node.Name] = list
			lsLastGoodAt[node.Name] = now
			lsUnavailable[node.Name] = false
			lsMu.Unlock()
		} else {
			firstDown := !lsUnavailable[node.Name] // 只在 可用→不可用 跃迁时 warn 一条，避免每 tick 刷屏
			lsUnavailable[node.Name] = true
			cached := lsLastGood[node.Name]
			cachedAt := lsLastGoodAt[node.Name]
			lsMu.Unlock()
			if firstDown {
				log.Printf("[liveSessions] WARN 节点 %s 本轮数据不可用：%s", node.Name, reason)
			}
			if cached == nil || now.Sub(cachedAt) > lsCacheTTL {
				continue // 从未成功过或缓存超过 TTL：该节点本轮无数据（不再无限期沿用旧快照）
			}
			list = cached
		}
		out = append(out, list...)
	}
	return out
}

// handleSessionList：在线会话列表（DSF-2）：改读 sessions 台账（settled=0 +
// last_seen 新鲜度，与 /self/me 同口径），不再实时聚合 liveSessions()——数据源
// 故障时不再出现空列表/僵尸列表。字段保持原 liveSessions 口径（username/virtual_ip/
// trusted_ip/bytes_in/bytes_out/connected_at/node），新增 cid（行主键，前端 rowKey）
// 与 last_seen（additive）。
func (a *App) handleSessionList(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	cond := `settled=0 AND virtual_ip<>'' AND last_seen>=` + onlineFreshCond()
	var total int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE ` + cond).Scan(&total)
	rows, err := a.db.Query(`SELECT cid, username, virtual_ip, COALESCE(trusted_ip,''),
		bytes_in, bytes_out, COALESCE(connected_at,''), node, COALESCE(last_seen,'')
		FROM sessions WHERE `+cond+` ORDER BY connected_at DESC LIMIT ? OFFSET ?`,
		pageSize, (page-1)*pageSize)
	if err != nil {
		failSystem(w, r, "查询在线会话失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var cid int64
		var username, vip, tip, conn, node, seen string
		var bi, bo int64
		if rows.Scan(&cid, &username, &vip, &tip, &bi, &bo, &conn, &node, &seen) == nil {
			list = append(list, map[string]interface{}{
				"cid": cid, "username": username, "virtual_ip": vip, "trusted_ip": tip,
				"bytes_in": bi, "bytes_out": bo, "connected_at": conn, "node": node, "last_seen": seen,
			})
		}
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

func (a *App) handleSessionKick(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Node     string `json:"node"`
	}
	if err := jsonDecode(r, &req); err != nil || req.Username == "" {
		failParam(w, r, "username 必填")
		return
	}
	var node *NodeConfig
	if req.Node != "" {
		node = findNode(req.Node)
		if node == nil {
			notFound(w, r, "节点")
			return
		}
		result := kickOnNode(*node, req.Username, false)
		writeOK(w, r, result)
		return
	}
	// 未指定节点：跨全部节点踢
	results := []map[string]interface{}{}
	for i := range nodes {
		res := kickOnNode(nodes[i], req.Username, false)
		results = append(results, map[string]interface{}{"node": nodes[i].Name, "result": res})
	}
	writeOK(w, r, map[string]interface{}{"results": results})
}
