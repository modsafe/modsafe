package main

import (
	"database/sql"
	"net/http"
)

// App 聚合依赖（SQLite 单实例）
type App struct {
	db *sql.DB
}

func registerAPI(mux *http.ServeMux, a *App) {

	// ── 认证（§12.4）──
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", a.requireAuth(a.handleMe))
	mux.HandleFunc("POST /api/v1/auth/change-password", a.requireAuth(a.handleChangePassword))

	// ── TOTP 双因素（P1-e：本人绑定/解绑需验证码；super_admin 可为他人解绑）──
	mux.HandleFunc("GET /api/v1/auth/totp/setup", a.requireAuth(a.handleTotpSetup))
	mux.HandleFunc("POST /api/v1/auth/totp/enable", a.requireAuth(a.handleTotpEnable))
	mux.HandleFunc("POST /api/v1/auth/totp/disable", a.requireAuth(a.handleTotpDisable))
	mux.HandleFunc("POST /api/v1/admins/{id}/totp-reset", a.requireAuth(a.requireRoles("super_admin")(a.handleTotpAdminReset)))

	// ── TOTP 系统级开关（#109：super_admin；强制=全员必须绑定）──
	mux.HandleFunc("GET /api/v1/settings/totp", a.requireAuth(a.requireRoles("super_admin")(a.handleTotpSettingsGet)))
	mux.HandleFunc("PUT /api/v1/settings/totp", a.requireAuth(a.requireRoles("super_admin")(a.handleTotpSettingsPut)))

	// ── 多管理员账号管理（P0-3：仅 super_admin；写操作经 requireRoles 钩子自动审计）──
	mux.HandleFunc("GET /api/v1/admins", a.requireAuth(a.requireRoles("super_admin")(a.handleAdminList)))
	mux.HandleFunc("POST /api/v1/admins", a.requireAuth(a.requireRoles("super_admin")(a.handleAdminCreate)))
	mux.HandleFunc("PUT /api/v1/admins/{id}", a.requireAuth(a.requireRoles("super_admin")(a.handleAdminUpdate)))
	mux.HandleFunc("POST /api/v1/admins/{id}/password", a.requireAuth(a.requireRoles("super_admin")(a.handleAdminPasswordReset)))
	mux.HandleFunc("DELETE /api/v1/admins/{id}", a.requireAuth(a.requireRoles("super_admin")(a.handleAdminDelete)))

	// ── 认证源管理（§18）──
	mux.HandleFunc("GET /api/v1/auth/config", a.requireAuth(a.handleAuthConfigGet))
	mux.HandleFunc("PUT /api/v1/auth/config", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleAuthConfigPut)))

	// ── 内部端点（adapter 反查，共享令牌鉴权）──
	mux.HandleFunc("POST /api/v1/internal/auth-check", a.handleInternalAuthCheck)
	mux.HandleFunc("GET /api/v1/internal/auth-config", a.handleInternalAuthConfig)
	mux.HandleFunc("POST /api/v1/internal/auth-local", a.handleInternalAuthLocal)
	mux.HandleFunc("GET /api/v1/internal/portal-whoami", a.handleInternalPortalWhoami)
	// B 方案：网页一键连接一次性 ticket 核销（adapter 反查，internalAuthed 门禁）
	mux.HandleFunc("GET /api/v1/internal/connect-grant", a.handleInternalConnectGrant)
	// CA 轮换后存量设备证书批量重签（#149 系统性缺口；internalAuthed 门禁）
	mux.HandleFunc("POST /api/v1/internal/devices-reissue", a.handleInternalDevicesReissue)

	// ── 认证源凭证（§12.2；本体在 adapter idp-config.json，代理 + 角色鉴权）──
	mux.HandleFunc("GET /api/v1/auth/idp-credentials", a.requireAuth(a.handleIdpCredentialsGet))
	mux.HandleFunc("PUT /api/v1/auth/idp-credentials", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleIdpCredentialsPut)))
	// §22.5 SAML IdP metadata 解析（管理台「验证 metadata」，adapter 执行解析）
	mux.HandleFunc("POST /api/v1/auth/saml/parse-metadata", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleSamlParseMetadata)))

	// ── 总览 ──
	mux.HandleFunc("GET /api/v1/dashboard/summary", a.requireAuth(a.handleDashboardSummary))
	mux.HandleFunc("GET /api/v1/dashboard/trend", a.requireAuth(a.handleDashboardTrend))

	// ── 用户 ──
	mux.HandleFunc("GET /api/v1/users", a.requireAuth(a.handleUserList))
	mux.HandleFunc("POST /api/v1/users", a.requireAuth(a.requireRoles("super_admin")(a.handleUserCreate)))
	mux.HandleFunc("GET /api/v1/users/{id}", a.requireAuth(a.handleUserGet))
	mux.HandleFunc("GET /api/v1/users/{id}/sessions", a.requireAuth(a.handleUserSessions))
	mux.HandleFunc("GET /api/v1/users/{id}/traffic", a.requireAuth(a.handleUserTraffic))
	// 用户设备列表（用户详情页设备 Tab）
	mux.HandleFunc("GET /api/v1/users/{id}/devices", a.requireAuth(a.handleUserDevices))
	mux.HandleFunc("POST /api/v1/users/{id}/client-config", a.requireAuth(a.requireRoles("super_admin")(a.handleClientConfigGen)))

	// §15 客户端配置下载（token 即凭证，5 分钟单次，无需登录态）
	mux.HandleFunc("GET /api/v1/client-config/{token}", a.handleClientConfigDownload)
	mux.HandleFunc("POST /api/v1/client-config/download", a.handleClientConfigDownloadByBody)
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.requireAuth(a.requireRoles("super_admin")(a.handleUserDelete)))
	mux.HandleFunc("POST /api/v1/users/{id}/status", a.requireAuth(a.requireRoles("super_admin")(a.handleUserStatus)))
	// 踢线是破坏性写操作：纳入角色矩阵与写审计（此前仅 requireAuth，纯 auditor 可执行且不留痕——2026-09-29 修复）
	mux.HandleFunc("POST /api/v1/users/{id}/kick", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleUserKick)))
	mux.HandleFunc("PUT /api/v1/users/{id}/password", a.requireAuth(a.requireRoles("super_admin")(a.handleUserPasswordReset)))

	// ── 组 ──
	mux.HandleFunc("GET /api/v1/groups", a.requireAuth(a.handleGroupList))
	mux.HandleFunc("POST /api/v1/groups", a.requireAuth(a.requireRoles("super_admin")(a.handleGroupCreate)))
	mux.HandleFunc("GET /api/v1/groups/{id}", a.requireAuth(a.handleGroupGet))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", a.requireAuth(a.requireRoles("super_admin")(a.handleGroupDelete)))
	mux.HandleFunc("POST /api/v1/groups/{id}/members", a.requireAuth(a.requireRoles("super_admin")(a.handleGroupMembers)))
	mux.HandleFunc("POST /api/v1/groups/{id}/resources", a.requireAuth(a.requireRoles("super_admin", "security_admin")(a.handleGroupResources)))

	// ── 资源 ──
	mux.HandleFunc("GET /api/v1/resources", a.requireAuth(a.handleResourceList))
	mux.HandleFunc("POST /api/v1/resources", a.requireAuth(a.requireRoles("security_admin")(a.handleResourceCreate)))
	mux.HandleFunc("DELETE /api/v1/resources/{id}", a.requireAuth(a.requireRoles("security_admin")(a.handleResourceDelete)))

	// ── CCD 策略（写操作 = security_admin，§12.3 矩阵）──
	mux.HandleFunc("GET /api/v1/ccd/rules", a.requireAuth(a.handleCcdList))
	mux.HandleFunc("POST /api/v1/ccd/rules", a.requireAuth(a.requireRoles("security_admin")(a.handleCcdCreate)))
	mux.HandleFunc("PUT /api/v1/ccd/rules/{id}", a.requireAuth(a.requireRoles("security_admin")(a.handleCcdUpdate)))
	mux.HandleFunc("DELETE /api/v1/ccd/rules/{id}", a.requireAuth(a.requireRoles("security_admin")(a.handleCcdDelete)))
	mux.HandleFunc("POST /api/v1/ccd/rules/validate", a.requireAuth(a.requireRoles("security_admin")(a.handleCcdValidate)))
	mux.HandleFunc("POST /api/v1/ccd/preview", a.requireAuth(a.handleCcdPreview))
	mux.HandleFunc("GET /api/v1/ccd/effective/{userId}", a.requireAuth(a.handleCcdEffective))
	mux.HandleFunc("POST /api/v1/ccd/apply", a.requireAuth(a.requireRoles("security_admin")(a.handleCcdApply)))
	mux.HandleFunc("POST /api/v1/ccd/sync", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleCcdSync)))

	// ── 监控 ──
	mux.HandleFunc("GET /api/v1/monitor/sessions", a.requireAuth(a.handleSessionList))
	mux.HandleFunc("POST /api/v1/monitor/sessions/kick", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleSessionKick)))
	mux.HandleFunc("GET /api/v1/monitor/nodes", a.requireAuth(a.handleMonitorNodes))
	// 服务端路由强制策略状态（登录可读）
	mux.HandleFunc("GET /api/v1/monitor/fwd-guard", a.requireAuth(a.handleFwdRulesStatus))
	mux.HandleFunc("GET /api/v1/monitor/audit/flows", a.requireAuth(a.handleAuditFlows))
	mux.HandleFunc("GET /api/v1/monitor/audit/dns", a.requireAuth(a.handleAuditDNS))
	mux.HandleFunc("GET /api/v1/monitor/audit/history", a.requireAuth(a.handleAuditHistory))
	mux.HandleFunc("GET /api/v1/settings/ipv6", a.requireAuth(a.handleIPv6Get))
	mux.HandleFunc("PUT /api/v1/settings/ipv6", a.requireAuth(a.requireRoles("super_admin")(a.handleIPv6Put)))
	mux.HandleFunc("GET /api/v1/monitor/traffic", a.requireAuth(a.handleMonitorTraffic))

	// ── 系统设置（§12.2；品牌/渠道本体在 adapter，此处鉴权代理）──
	mux.HandleFunc("GET /api/v1/settings/general", a.requireAuth(a.handleSettingsGet))
	mux.HandleFunc("PUT /api/v1/settings/general", a.requireAuth(a.requireRoles("super_admin")(a.handleSettingsPut)))
	// 加密套件（国密切换；super_admin，打断性双节点重启）
	mux.HandleFunc("GET /api/v1/settings/crypto", a.requireAuth(a.handleCryptoGet))
	mux.HandleFunc("PUT /api/v1/settings/crypto", a.requireAuth(a.requireRoles("super_admin")(a.handleCryptoPut)))
	mux.HandleFunc("GET /api/v1/settings/cert-binding", a.requireAuth(a.handleCertBindingGet))
	mux.HandleFunc("PUT /api/v1/settings/cert-binding", a.requireAuth(a.requireRoles("super_admin")(a.handleCertBindingPut)))
	mux.HandleFunc("GET /api/v1/settings/notify-channels", a.requireAuth(a.handleNotifyChannelsGet))
	mux.HandleFunc("POST /api/v1/settings/notify-channels", a.requireAuth(a.requireRoles("super_admin")(a.handleNotifyChannelSave)))
	mux.HandleFunc("DELETE /api/v1/settings/notify-channels/{id}", a.requireAuth(a.requireRoles("super_admin")(a.handleNotifyChannelDelete)))
	mux.HandleFunc("POST /api/v1/settings/notify-channels/test", a.requireAuth(a.requireRoles("super_admin")(a.handleNotifyTest)))
	mux.HandleFunc("GET /api/v1/settings/notify-email", a.requireAuth(a.handleNotifyEmailGet))
	mux.HandleFunc("PUT /api/v1/settings/notify-email", a.requireAuth(a.requireRoles("super_admin")(a.handleNotifyEmailPut)))
	mux.HandleFunc("GET /api/v1/settings/session", a.requireAuth(a.handleSessionPolicyGet))
	mux.HandleFunc("PUT /api/v1/settings/session", a.requireAuth(a.requireRoles("super_admin")(a.handleSessionPolicyPut)))
	mux.HandleFunc("POST /api/v1/settings/session/apply", a.requireAuth(a.requireRoles("super_admin")(a.handleSessionApply)))

	// ── License（§17；状态全员可见作横幅，导入仅 super_admin）──
	mux.HandleFunc("GET /api/v1/settings/license", a.requireAuth(a.handleLicenseGet))
	mux.HandleFunc("POST /api/v1/settings/license", a.requireAuth(a.requireRoles("super_admin")(a.handleLicensePost)))

	// ── 告警规则引擎（§20：生命周期/规则目录/维护模式）──
	mux.HandleFunc("GET /api/v1/alerts/rules", a.requireAuth(a.handleAlertRulesGet))
	mux.HandleFunc("PUT /api/v1/alerts/rules/{id}", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleAlertRulePut)))
	mux.HandleFunc("GET /api/v1/alerts/active", a.requireAuth(a.handleAlertsActiveGet))
	mux.HandleFunc("GET /api/v1/alerts/history", a.requireAuth(a.handleAlertsHistoryGet))
	mux.HandleFunc("POST /api/v1/alerts/maintenance", a.requireAuth(a.requireRoles("super_admin")(a.handleAlertMaintenancePost)))
	mux.HandleFunc("DELETE /api/v1/alerts/maintenance", a.requireAuth(a.requireRoles("super_admin")(a.handleAlertMaintenanceDelete)))

	// ── 目录同步（§23 拉取式：IM 通讯录导入用户/组，dry-run 预览 + 事务应用）──
	mux.HandleFunc("POST /api/v1/directory/preview", a.requireAuth(a.requireRoles("super_admin")(a.handleDirectoryPreview)))
	mux.HandleFunc("POST /api/v1/directory/sync", a.requireAuth(a.requireRoles("super_admin")(a.handleDirectorySync)))

	// ── 用户自助门户（§16；/self/* 主体恒取门户 JWT，与管理台 API 完全隔离）──
	mux.HandleFunc("GET /api/v1/self/branding", a.handleSelfBranding)
	mux.HandleFunc("GET /api/v1/self/login", a.handlePortalLogin)
	mux.HandleFunc("GET /api/v1/self/callback", a.handlePortalCallback)
	mux.HandleFunc("POST /api/v1/self/login-local", a.handlePortalLoginLocal)
	mux.HandleFunc("POST /api/v1/self/logout", a.handlePortalLogout)
	mux.HandleFunc("GET /api/v1/self/me", a.requirePortal(a.handleSelfMe))
	// 客户端/门户乐观下线（断开感知 DSF-4）：主体恒取门户 JWT，body 可选 virtual_ip
	mux.HandleFunc("POST /api/v1/self/disconnect", a.requirePortal(a.handleSelfDisconnect))
	mux.HandleFunc("GET /api/v1/self/devices", a.requirePortal(a.handleSelfDevices))
	mux.HandleFunc("POST /api/v1/self/devices/client-config", a.requirePortal(a.handleSelfClientConfig))
	mux.HandleFunc("DELETE /api/v1/self/devices/{id}", a.requirePortal(a.handleSelfDeviceDelete))
	mux.HandleFunc("POST /api/v1/self/devices/delete", a.requirePortal(a.handleSelfDeviceDeleteByBody))
	mux.HandleFunc("GET /api/v1/self/sessions", a.requirePortal(a.handleSelfSessions))
	mux.HandleFunc("GET /api/v1/self/usage", a.requirePortal(a.handleSelfUsage))
	mux.HandleFunc("POST /api/v1/self/password", a.requirePortal(a.handleSelfPassword))
	// 用户侧双因素（2026-10-06；策略 user_totp_policy，受限会话经 requirePortal 只放行 me/totp）
	mux.HandleFunc("GET /api/v1/self/totp/setup", a.requirePortal(a.handleSelfTotpSetup))
	mux.HandleFunc("POST /api/v1/self/totp/enable", a.requirePortal(a.handleSelfTotpEnable))
	mux.HandleFunc("POST /api/v1/self/totp/disable", a.requirePortal(a.handleSelfTotpDisable))
	// 租户策略开关 + 用户 TOTP 重置（管理台，super_admin）
	mux.HandleFunc("GET /api/v1/settings/user-totp", a.requireAuth(a.requireRoles("super_admin")(a.handleUserTotpSettingsGet)))
	mux.HandleFunc("PUT /api/v1/settings/user-totp", a.requireAuth(a.requireRoles("super_admin")(a.handleUserTotpSettingsPut)))
	mux.HandleFunc("POST /api/v1/users/{id}/totp-reset", a.requireAuth(a.requireRoles("super_admin")(a.handleUserTotpReset)))
	// #133：openvpn 服务端证书续期（super_admin；重签+节点1 SIGHUP 重载，节点2 返回同步指引）
	mux.HandleFunc("POST /api/v1/settings/cert/server-renew", a.requireAuth(a.requireRoles("super_admin")(a.handleCertServerRenew)))
	// #135：CA 全链重签（root CA+服务端证书+client-subca+ca-chain 束；super_admin；用户侧需重新下载配置）
	mux.HandleFunc("POST /api/v1/settings/cert/ca-renew", a.requireAuth(a.requireRoles("super_admin")(a.handleCertCARenew)))

	// ── 设备/来源（会话台账聚合）──
	mux.HandleFunc("GET /api/v1/devices", a.requireAuth(a.handleDevices))
	mux.HandleFunc("GET /api/v1/devices/{id}", a.requireAuth(a.handleDeviceGet))
	mux.HandleFunc("POST /api/v1/devices/{id}/revoke", a.requireAuth(a.requireRoles("security_admin", "super_admin")(a.handleDeviceRevoke)))

	// ── 证书管理 ──
	mux.HandleFunc("GET /api/v1/certs/info", a.requireAuth(a.handleCertsInfo))
	mux.HandleFunc("GET /api/v1/certs/devices", a.requireAuth(a.handleCertDevices))

	// ── 审计（§19：auditor 只读可看，其他角色无权）──
	mux.HandleFunc("GET /api/v1/audit/auth-logs", a.requireAuth(a.handleAuditAuthLogs))
	mux.HandleFunc("GET /api/v1/audit/session-logs", a.requireAuth(a.handleAuditSessionLogs))
	mux.HandleFunc("GET /api/v1/audit/admin-logs", a.requireAuth(a.requireRoles("auditor")(a.handleAuditAdminLogs)))

	// ── 合规报表 CSV 导出（P1-a：GET 下载，权限对齐查询端点）──
	mux.HandleFunc("GET /api/v1/audit/auth-logs/export", a.requireAuth(a.requireRoles("auditor")(a.handleExportAuthLogs)))
	mux.HandleFunc("GET /api/v1/audit/session-logs/export", a.requireAuth(a.requireRoles("auditor")(a.handleExportSessionLogs)))
	mux.HandleFunc("GET /api/v1/audit/admin-logs/export", a.requireAuth(a.requireRoles("auditor")(a.handleExportAdminLogs)))
	mux.HandleFunc("GET /api/v1/monitor/audit/dns/export", a.requireAuth(a.requireRoles("auditor")(a.handleExportDNS)))

	// ── 健康检查（部署层探测用）──
	mux.HandleFunc("GET /api/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w, r, map[string]string{"status": "ok"})
	})
}
