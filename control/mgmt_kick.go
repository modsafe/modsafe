package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// 本地节点踢线：受控窗口 = 停 oa2（释放 management 槽位，单客户端限制）
// → status 3 解析 CID → client-kill → 回启 oa2（systemd 显式 start）。
// 窗口内新认证会失败（秒级）；全局 kickMutex 串行化，避免并发窗口。
func localKick(node NodeConfig, username string, killAll bool, virtualIP string) map[string]interface{} {
	kickMutex.Lock()
	defer kickMutex.Unlock()

	result := map[string]interface{}{"ok": false, "killed": []map[string]string{}, "errors": []string{}}
	killed := []map[string]string{}
	errors := []string{}

	stop := exec.Command("systemctl", "stop", node.Oa2Unit).Run()

	s, err := acquireMgmtSlot(node.MgmtSocket, 5*time.Second)
	if err != nil {
		errors = append(errors, "management 槽位未获取: "+err.Error())
		finishKick(node, result, killed, errors)
		return result
	}
	defer s.Close()

	_ = stop
	rows, err := mgmtReadStatus(s)
	if err != nil {
		errors = append(errors, "status 3 读取失败: "+err.Error())
		finishKick(node, result, killed, errors)
		return result
	}
	for _, row := range rows {
		// virtualIP 优先：会话级精确踢线（空闲断开不再一刀全踢该用户全部设备）
		match := killAll ||
			(virtualIP != "" && row["Virtual Address"] == virtualIP) ||
			(virtualIP == "" && username != "" && (row["Username"] == username || row["Common Name"] == username))
		if !match {
			continue
		}
		cid := row["Client ID"]
		if cid == "" {
			continue
		}
		resp, err := mgmtCommand(s, fmt.Sprintf("client-kill %s", cid))
		if err == nil && strings.Contains(resp, "SUCCESS") {
			killed = append(killed, map[string]string{"cid": cid, "username": row["Username"]})
		} else {
			msg := "client-kill 失败"
			if err != nil {
				msg += ": " + err.Error()
			} else {
				msg += ": " + strings.TrimSpace(resp)
			}
			errors = append(errors, msg)
		}
	}
	finishKick(node, result, killed, errors)
	return result
}

func finishKick(node NodeConfig, result map[string]interface{}, killed []map[string]string, errors []string) {
	start := exec.Command("systemctl", "start", node.Oa2Unit).Run()
	if start != nil {
		errors = append(errors, "oa2 回启失败: "+start.Error())
	}
	time.Sleep(300 * time.Millisecond)
	result["killed"] = killed
	result["errors"] = errors
	result["ok"] = len(killed) > 0
}

func acquireMgmtSlot(socketPath string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.Dial("unix", socketPath)
		if err == nil {
			c.SetDeadline(time.Now().Add(10 * time.Second))
			return c, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func mgmtReadStatus(c net.Conn) ([]map[string]string, error) {
	// 本构建 management status 3 为 TAB 分隔；踢线用的 CID 列名为 "Client ID"
	if _, err := c.Write([]byte("status 3\n")); err != nil {
		return nil, err
	}
	var cols []string
	rows := []map[string]string{}
	reader := bufio.NewReader(c)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return rows, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "END" {
			return rows, nil
		}
		p := strings.Split(line, "\t")
		if len(p) >= 3 && p[0] == "HEADER" && p[1] == "CLIENT_LIST" {
			cols = p[2:]
			continue
		}
		if len(p) > 1 && p[0] == "CLIENT_LIST" {
			row := map[string]string{}
			for i, name := range cols {
				if i+1 < len(p) {
					row[name] = p[i+1]
				}
			}
			rows = append(rows, row)
		}
	}
}

func mgmtCommand(c net.Conn, cmd string) (string, error) {
	if _, err := c.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	// 命令应答为单行 SUCCESS/ERROR
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	c.SetReadDeadline(time.Time{})
	return resp, nil
}

func agentKick(node NodeConfig, username string, killAll bool, virtualIP string) map[string]interface{} {
	body := map[string]interface{}{"all": killAll}
	if username != "" {
		body["username"] = username
	}
	if virtualIP != "" {
		body["virtual_ip"] = virtualIP
	}
	out, err := agentRequest(node, "POST", "/kick", body)
	if err != nil {
		return map[string]interface{}{"ok": false, "errors": []string{err.Error()}}
	}
	return out
}

// kickOnNode：按节点类型路由踢线（virtualIP 可选：会话级精确匹配）
func kickOnNode(node NodeConfig, username string, killAll bool, virtualIPs ...string) map[string]interface{} {
	vip := ""
	if len(virtualIPs) > 0 {
		vip = virtualIPs[0]
	}
	if node.Kind == "agent" {
		return agentKick(node, username, killAll, vip)
	}
	return localKick(node, username, killAll, vip)
}
