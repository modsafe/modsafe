package main

// 设备/证书管理 API（§12 证书管理页数据源）：
//   GET  /devices/{id}      设备详情（证书 PEM 预览/指纹）
//   POST /devices/{id}/revoke  吊销（软吊销+全节点踢线+禁再下载；
//   cert_identity_binding=strict 时同步重推 CRL，TLS 层即时作废——见 #61）
//   GET  /certs/ca          链束与 sub-CA 信息（到期天数）

import (
	"net/http"
	"strconv"
)

// handleDeviceList 已在 audit.go（/api/v1/devices 聚合）。此处补详情与吊销。

func (a *App) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var userID int64
	var certCN, fp, platform, name, status, createdAt, certPEM string
	var lastSeen *string
	err := a.db.QueryRow(`SELECT user_id, cert_cn, COALESCE(fingerprint,''), COALESCE(platform,''),
		COALESCE(device_name,''), status, COALESCE(created_at,''), COALESCE(cert_pem,''), last_used_at
		FROM devices WHERE id=?`, id).
		Scan(&userID, &certCN, &fp, &platform, &name, &status, &createdAt, &certPEM, &lastSeen)
	if err != nil {
		notFound(w, r, "设备")
		return
	}
	writeOK(w, r, map[string]interface{}{
		"id": id, "user_id": userID, "cert_cn": certCN, "fingerprint": fp,
		"platform": platform, "device_name": name, "status": status,
		"created_at": createdAt, "last_used_at": lastSeen,
		"cert_pem": certPEM,
	})
}

// handleDeviceRevoke：软吊销（status=revoked）+ 全节点踢线。
// cert_identity_binding=strict 时同步重生成 CRL 推双节点——crl-verify 使该证书
// TLS 层即时作废（配置文件连握手都过不去，#61 补齐"吊销有实际阻断力"）；
// off 模式维持软吊销语义（不再签发+踢线，TLS 层不拦截）。
func (a *App) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var certCN string
	err := a.db.QueryRow(`SELECT cert_cn FROM devices WHERE id=? AND status='active'`, id).Scan(&certCN)
	if err != nil {
		notFound(w, r, "设备（或已吊销）")
		return
	}
	_, _ = a.db.Exec(`UPDATE devices SET status='revoked' WHERE id=?`, id)
	a.syncCCDAsync()
	kicked := []map[string]interface{}{}
	for i := range nodes {
		res := kickOnNode(nodes[i], certCN, false)
		kicked = append(kicked, map[string]interface{}{"node": nodes[i].Name, "result": res})
	}
	notice := "已标记吊销并全节点踢线"
	if certBinding(a) == "strict" {
		if err := a.pushCRL(); err != nil {
			notice += "；⚠️ CRL 推送失败（" + err.Error() + "）——TLS 层拦截未更新，请重试吊销或检查节点"
		} else {
			notice += "；CRL 已更新推送双节点，该证书配置文件即时作废（TLS 层拒绝）"
		}
	} else {
		notice += "；当前为宽松模式，TLS 层不拦截（可在 系统设置→接入安全 开启严格绑定）"
	}
	writeOK(w, r, map[string]interface{}{
		"revoked": true, "cert_cn": certCN, "kick_results": kicked,
		"notice": notice,
	})
}

// handleCertDevices：设备证书台账（devices 表 join users，证书管理页数据源）
func (a *App) handleCertDevices(w http.ResponseWriter, r *http.Request) {
	page, pageSize := pageParams(r)
	var total int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&total)
	rows, err := a.db.Query(`SELECT d.id, d.user_id, d.cert_cn, COALESCE(d.platform,''),
		COALESCE(d.device_name,''), d.status, COALESCE(d.created_at,''), COALESCE(u.username,'')
		FROM devices d LEFT JOIN users u ON u.id=d.user_id
		ORDER BY d.id DESC LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		failSystem(w, r, "查询设备失败")
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	for rows.Next() {
		var id, uid int64
		var cn, platform, name, status, createdAt, username string
		if rows.Scan(&id, &uid, &cn, &platform, &name, &status, &createdAt, &username) == nil {
			list = append(list, map[string]interface{}{
				"id": id, "user_id": uid, "cert_cn": cn, "platform": platform,
				"device_name": name, "status": status, "created_at": createdAt,
				"username": username,
			})
		}
	}
	writeOK(w, r, pageData(list, total, page, pageSize))
}

// handleCertsInfo：CA 链与 sub-CA 到期信息（证书管理页头部卡片）
func (a *App) handleCertsInfo(w http.ResponseWriter, r *http.Request) {
	if err := pkiInit(); err != nil {
		failSystem(w, r, "PKI 未就绪: "+err.Error())
		return
	}
	_, caCrt, _ := pkiSnapshot() // 锁内快照：ca-renew 重载后展示的即新 sub-CA 到期信息
	daysLeft := int(timeUntil(caCrt.NotAfter).Hours() / 24)
	writeOK(w, r, map[string]interface{}{
		"subca_cn":         "modsafe-ClientSubCA",
		"subca_not_after":  caCrt.NotAfter.Format("2006-01-02"),
		"subca_days_left":  daysLeft,
		"root_offline":     true,
		"chain_block_count": 2,
	})
}
