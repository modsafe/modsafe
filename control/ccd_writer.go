package main

// CCD 下发闭环（§14.2 步骤⑤的落地）：
// 规则（SQLite）→ 合并引擎渲染 → 写 oa2 client-config 目录 → oa2 认证时读取下推。
//
// 多节点拓扑：每个节点的 oa2 只读本节点目录（实测 193 oa2 日志 "no client config found in CCD"）。
//   - local 节点（180）：直写本机 /etc/openvpn-auth-oauth2/client-config/
//   - agent 节点（193）：经 node-agent POST /ccd 推送，manifest 表（ccd_pushed）记录已推指纹，
//     重启后据此补推/回收，不误删 adapter 侧历史用户文件（DB 外用户文件一律保留）。

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ccdSyncMu sync.Mutex

func ccdDir() string {
	if d := envOr("MODSAFE_CCD_DIR", ""); d != "" {
		return d
	}
	if _, err := os.Stat("/etc/openvpn-auth-oauth2/client-config"); err == nil {
		return "/etc/openvpn-auth-oauth2/client-config"
	}
	return "data/ccd" // 开发环境兜底
}

func sanitizeCCDName(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", "..", "_", " ", "_")
	return r.Replace(strings.TrimSpace(name))
}

func atomicWrite(dir, name, content string) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

func contentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// desiredCCDFiles：计算期望的 {文件名: 内容} 全集（所有启用用户）
func (a *App) desiredCCDFiles() map[string]string {
	desired := map[string]string{}
	rows, err := a.db.Query(`SELECT id, username FROM users WHERE status='active' ORDER BY id`)
	if err != nil {
		return desired
	}
	defer rows.Close()
	type uinfo struct {
		id   int64
		name string
	}
	var users []uinfo
	for rows.Next() {
		var u uinfo
		if err := rows.Scan(&u.id, &u.name); err == nil {
			users = append(users, u)
		}
	}
	rows.Close()
	for _, u := range users {
		preview, ok := a.buildPreview(u.id)
		if !ok {
			continue
		}
		content, _ := preview["ccd_content"].(string)
		if content == "" {
			continue // 无命中规则：不生成文件（oa2 无文件即无额外 push）
		}
		desired[sanitizeCCDName(u.name)+".conf"] = content
	}
	return desired
}

func (a *App) manifestLoad(node string) map[string]string {
	out := map[string]string{}
	rows, err := a.db.Query(`SELECT fname, hash FROM ccd_pushed WHERE node=?`, node)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var f, h string
		if rows.Scan(&f, &h) == nil {
			out[f] = h
		}
	}
	return out
}

func (a *App) manifestSave(node, fname, hash string) {
	_, _ = a.db.Exec(`INSERT INTO ccd_pushed(node,fname,hash) VALUES(?,?,?)
		ON CONFLICT(node,fname) DO UPDATE SET hash=excluded.hash`, node, fname, hash)
}

func (a *App) manifestDelete(node, fname string) {
	_, _ = a.db.Exec(`DELETE FROM ccd_pushed WHERE node=? AND fname=?`, node, fname)
}

// syncCCDFiles：全量同步。返回（本地写入数, 本地/远端回收数, 远端推送数, 错误）
func (a *App) syncCCDFiles() (written, removed, pushed int, err error) {
	ccdSyncMu.Lock()
	defer ccdSyncMu.Unlock()

	desired := a.desiredCCDFiles()

	for _, node := range nodes {
		switch node.Kind {
		case "local":
			dir := ccdDir()
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				continue
			}
			// 写/更新
			for fname, content := range desired {
				target := filepath.Join(dir, fname)
				if old, rErr := os.ReadFile(target); rErr == nil && string(old) == content {
					continue
				}
				if wErr := atomicWrite(dir, fname, content); wErr != nil {
					log.Printf("[ccd] local write %s: %v", fname, wErr)
					continue
				}
				written++
			}
			// 回收：禁用/删除/无规则用户在本地目录中的残留
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				n := e.Name()
				if !strings.HasSuffix(n, ".conf") || strings.HasPrefix(n, ".") {
					continue
				}
				if _, want := desired[n]; want {
					continue
				}
				// DB 中不存在该用户 → 不删（可能是 adapter 侧历史用户，②对齐前保守处理）
				base := strings.TrimSuffix(n, ".conf")
				var cnt int
				_ = a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, base).Scan(&cnt)
				if cnt == 0 {
					continue
				}
				if rmErr := os.Remove(filepath.Join(dir, n)); rmErr == nil {
					removed++
				}
			}
		case "agent":
			manifest := a.manifestLoad(node.Name)
			for fname, content := range desired {
				h := contentHash(content)
				if manifest[fname] == h {
					continue
				}
				out, pErr := agentRequest(node, "POST", "/ccd", map[string]interface{}{
					"filename": fname, "content": content})
				if pErr != nil {
					log.Printf("[ccd] agent push %s@%s: %v", fname, node.Name, pErr)
					continue
				}
				if ok, _ := out["ok"].(bool); !ok {
					log.Printf("[ccd] agent push %s@%s 失败: %v", fname, node.Name, out)
					continue
				}
				a.manifestSave(node.Name, fname, h)
				pushed++
			}
			for fname := range manifest {
				if _, want := desired[fname]; want {
					continue
				}
				var cnt int
				base := strings.TrimSuffix(fname, ".conf")
				_ = a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, base).Scan(&cnt)
				if cnt == 0 {
					continue // DB 外用户：保留（保守）
				}
				// 删除成功（ok=true）才清 manifest，失败保留记录待下次重试
				//（此前不校验结果即清，失败后文件永久残留节点，2026-09-29 修复）
				out, pErr := agentRequest(node, "POST", "/ccd", map[string]interface{}{
					"filename": fname, "delete": true})
				if pErr == nil {
					if ok, _ := out["ok"].(bool); ok {
						a.manifestDelete(node.Name, fname)
						removed++
					}
				}
			}
		}
	}
	// 服务端路由强制：CCD 变化即重编程 FORWARD 白名单（本机 + agent）
	go a.syncForwardGuard()
	return written, removed, pushed, nil
}

// syncCCDForUser：认证链路（②）的单用户同步——auth-check 之后、oa2 client-auth 之前调用，
// 保证该用户的 CCD 文件在本次认证中即被 oa2 读取（本地直写 + agent 推送 + manifest 更新）。
func (a *App) syncCCDForUser(userID int64) {
	ccdSyncMu.Lock()
	defer ccdSyncMu.Unlock()

	var username, status string
	if err := a.db.QueryRow(`SELECT username, COALESCE(status,'active') FROM users WHERE id=?`,
		userID).Scan(&username, &status); err != nil {
		return
	}
	fname := sanitizeCCDName(username) + ".conf"
	preview, ok := a.buildPreview(userID)
	content := ""
	if ok {
		content, _ = preview["ccd_content"].(string)
	}
	dir := ccdDir()
	_ = os.MkdirAll(dir, 0o755)
	target := filepath.Join(dir, fname)

	if status != "active" || content == "" {
		if _, statErr := os.Stat(target); statErr == nil {
			_ = os.Remove(target)
		}
	} else if old, rErr := os.ReadFile(target); rErr != nil || string(old) != content {
		if wErr := atomicWrite(dir, fname, content); wErr != nil {
			log.Printf("[ccd] auth sync %s: %v", fname, wErr)
			return
		}
	}

	h := contentHash(content)
	for _, node := range nodes {
		if node.Kind != "agent" {
			continue
		}
		if status != "active" || content == "" {
			out, _ := agentRequest(node, "POST", "/ccd", map[string]interface{}{
				"filename": fname, "delete": true})
			if ok, _ := out["ok"].(bool); ok { // 成功才清 manifest，失败下次认证重试
				a.manifestDelete(node.Name, fname)
			}
			continue
		}
		if a.manifestLoad(node.Name)[fname] == h {
			continue
		}
		out, pErr := agentRequest(node, "POST", "/ccd", map[string]interface{}{
			"filename": fname, "content": content})
		if pErr == nil {
			if ok, _ := out["ok"].(bool); ok {
				a.manifestSave(node.Name, fname, h)
			}
		}
	}
}

// syncCCDAsync：异步触发（API 响应不被文件 IO 拖慢）
func (a *App) syncCCDAsync() {
	go func() {
		w, r, p, err := a.syncCCDFiles()
		if err != nil {
			log.Printf("[ccd] sync: %v", err)
			return
		}
		if w+r+p > 0 {
			log.Printf("[ccd] synced: local %d written/%d removed, agent %d pushed", w, r, p)
		}
	}()
}

func (a *App) handleCcdSync(w http.ResponseWriter, r *http.Request) {
	written, removed, pushed, err := a.syncCCDFiles()
	if err != nil {
		failSystem(w, r, "同步失败: "+err.Error())
		return
	}
	writeOK(w, r, map[string]interface{}{
		"local_written": written,
		"local_removed": removed,
		"agent_pushed":  pushed,
		"dir":           ccdDir(),
	})
}
