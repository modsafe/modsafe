package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

func mustOpenDB(dataDir string) *sql.DB {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dataDir, "modsafe.db")) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(8) // WAL 允许多读；写并发由 busy_timeout 兜底（单连接曾在 syscall 挂死时阻塞全部请求）
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	createSchema(db)
	return db
}

func createSchema(db *sql.DB) {
	// 系统设置（§18：primary_idp 单选 + 本地兜底开关；§17 License 亦将挂此）
	mustExec(db, `CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT
	)`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		roles TEXT NOT NULL,                    -- JSON: ["super_admin","security_admin","auditor"]
		must_change_password INTEGER DEFAULT 0,
		totp_enabled INTEGER DEFAULT 0,
		totp_secret TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	// TOTP 列补齐（存量库 ALTER 幂等，2026-10-05 P1-e）
	_ = execIgnoreDup(db, `ALTER TABLE admins ADD COLUMN totp_enabled INTEGER DEFAULT 0`)
	_ = execIgnoreDup(db, `ALTER TABLE admins ADD COLUMN totp_secret TEXT DEFAULT ''`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		display_name TEXT DEFAULT '',
		email TEXT DEFAULT '',
		source TEXT NOT NULL DEFAULT 'local',   -- local|ldap|ldap-ad|dingtalk|wecom|feishu
		external_id TEXT,
		union_id TEXT DEFAULT '',               -- IM unionId（扫码 OAuth sub；2026-09-30 同名支持）
		status TEXT NOT NULL DEFAULT 'active',
		password_hash TEXT,                     -- 仅本地账号
		device_quota INTEGER DEFAULT 3,
		totp_enabled INTEGER DEFAULT 0,         -- 用户侧双因素（租户策略 user_totp_policy：off|local_only|all）
		totp_secret TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime')),
		last_login_at TEXT,
		UNIQUE(source, username)
	)`)
	// 存量库补列（新装库建表已含）
	_ = execIgnoreDup(db, "ALTER TABLE users ADD COLUMN union_id TEXT DEFAULT ''")
	// 用户侧 TOTP 列补齐（存量库幂等，2026-10-06；复用管理台 totp.go 纯函数）
	_ = execIgnoreDup(db, "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
	_ = execIgnoreDup(db, "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''")
	mustExec(db, `CREATE TABLE IF NOT EXISTS user_groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		idp_ref TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS group_members (
		group_id INTEGER NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(group_id, user_id)
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS resources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		cidr TEXT NOT NULL,
		description TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS group_resources (
		group_id INTEGER NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
		resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
		UNIQUE(group_id, resource_id)
	)`)
	// §14 CCD 规则表（与 §3.2 Schema 一致）
	mustExec(db, `CREATE TABLE IF NOT EXISTS ccd_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL,                     -- route|dns|redirect_gateway|iroute|route_metric
		value TEXT NOT NULL,
		priority INTEGER DEFAULT 0,
		group_id INTEGER,
		user_id INTEGER,
		enabled INTEGER DEFAULT 1,
		created_by INTEGER,
		created_at TEXT DEFAULT (datetime('now','localtime')),
		updated_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	mustExec(db, `CREATE INDEX IF NOT EXISTS idx_ccd_group ON ccd_rules(group_id)`)
	mustExec(db, `CREATE INDEX IF NOT EXISTS idx_ccd_user ON ccd_rules(user_id)`)
	// 控制平面自有会话追踪表（session_tracker 生成，username 归属准确）
	// §20 告警规则引擎
	mustExec(db, `CREATE TABLE IF NOT EXISTS alert_rules (
		id TEXT PRIMARY KEY,
		level TEXT NOT NULL,
		description TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		cooldown_minutes INTEGER DEFAULT 240
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS alert_state (
		dedup_key TEXT PRIMARY KEY,
		rule_id TEXT NOT NULL,
		level TEXT NOT NULL,
		fired_at TEXT,
		last_notified_at TEXT,
		detail_json TEXT DEFAULT ''
	)`)

	// §17 License（历史保留供审计；当前生效 = 最新一条）
	mustExec(db, `CREATE TABLE IF NOT EXISTS license (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		raw TEXT NOT NULL,
		payload TEXT DEFAULT '',
		signature TEXT DEFAULT '',
		installed_by TEXT DEFAULT '',
		installed_at TEXT DEFAULT (datetime('now','localtime'))
	)`)
	// §15 设备表（证书即设备：cert_pem/key_pem 入库，下载直取）
	mustExec(db, `CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		cert_cn TEXT NOT NULL,
		fingerprint TEXT DEFAULT '',
		platform TEXT DEFAULT '',
		device_name TEXT DEFAULT '',
		status TEXT DEFAULT 'active',
		cert_pem TEXT DEFAULT '',
		key_pem TEXT DEFAULT '',
		created_at TEXT DEFAULT (datetime('now','localtime')),
		last_used_at TEXT
	)`)
	mustExec(db, `CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)`)
	// CCD 跨节点推送清单（agent 节点的文件指纹，重启恢复用）
	mustExec(db, `CREATE TABLE IF NOT EXISTS ccd_pushed (
		node TEXT NOT NULL,
		fname TEXT NOT NULL,
		hash TEXT NOT NULL,
		PRIMARY KEY(node, fname)
	)`)
	// 在线会话（真实数据源：collector 解析 status v3 回写；骨架期空表）
	mustExec(db, `CREATE TABLE IF NOT EXISTS sessions (
		cid INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		virtual_ip TEXT, trusted_ip TEXT,
		connected_at TEXT,
		bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
		cipher TEXT DEFAULT '', node TEXT DEFAULT ''
	)`)
	// tracker 扩展列：必须在 CREATE sessions 之后 ALTER（全新库先 ALTER 会因表不存在被静默吞掉，
	// 导致新部署的台账 INSERT 全部失败——2026-09-29 复核修复）
	for _, col := range []string{"last_seen TEXT", "settled INTEGER DEFAULT 0", "last_activity TEXT"} {
		_ = execIgnoreDup(db, "ALTER TABLE sessions ADD COLUMN "+col)
	}
	// 按日流量台账（2026-09-30）：session_tracker 每 15s 增量入账；门户 usage 直接读本表，
	// 修复"一次会话全部流量记入 last_seen 当天"的跨天失真
	mustExec(db, `CREATE TABLE IF NOT EXISTS traffic_daily (
		username TEXT NOT NULL,
		day TEXT NOT NULL,
		bytes_in INTEGER DEFAULT 0,
		bytes_out INTEGER DEFAULT 0,
		PRIMARY KEY(username, day)
	)`)
	// 流量审计（#70）：flow_daily=按 用户/目的/端口/协议 聚合的连接字节增量；
	// flow_live=最近一轮 conntrack 快照（采集器全量替换）
	mustExec(db, `CREATE TABLE IF NOT EXISTS flow_daily (
		username TEXT NOT NULL,
		day TEXT NOT NULL,
		dst TEXT NOT NULL,
		port INTEGER NOT NULL,
		proto TEXT NOT NULL,
		bytes INTEGER NOT NULL DEFAULT 0,
		conns INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (username, day, dst, port, proto)
	)`)
	// #73：域名维度 + 最近活动时间（既有表补列用 execIgnoreDup）
	_ = execIgnoreDup(db, "ALTER TABLE flow_daily ADD COLUMN domain TEXT DEFAULT ''")
	_ = execIgnoreDup(db, "ALTER TABLE flow_daily ADD COLUMN last_seen TEXT DEFAULT ''")
	mustExec(db, `CREATE TABLE IF NOT EXISTS flow_live (
		node TEXT, src TEXT, dst TEXT, proto TEXT, port INTEGER,
		bytes INTEGER, username TEXT, domain TEXT DEFAULT ''
	)`)
	_ = execIgnoreDup(db, "ALTER TABLE flow_live ADD COLUMN domain TEXT DEFAULT ''")
	_ = execIgnoreDup(db, "ALTER TABLE flow_live ADD COLUMN first_seen TEXT DEFAULT ''")
	_ = execIgnoreDup(db, "ALTER TABLE flow_live ADD COLUMN last_seen TEXT DEFAULT ''")
	_ = execIgnoreDup(db, "ALTER TABLE flow_live ADD COLUMN trusted_ip TEXT DEFAULT ''")
	// DNS 查询记录（#71）：dnsmasq 查询日志解析入库（ts 分钟粒度+src+domain 去重）
	mustExec(db, `CREATE TABLE IF NOT EXISTS dns_queries (
		ts TEXT NOT NULL,
		src TEXT NOT NULL,
		domain TEXT NOT NULL,
		qtype TEXT NOT NULL DEFAULT '',
		UNIQUE(ts, src, domain, qtype)
	)`)
	// 一次性回填：既有 sessions 行按旧口径（last_seen 日）折算入日账，保证切换日总量连续
	var backfilled int
	_ = db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='traffic_daily_backfilled'`).Scan(&backfilled)
	if backfilled == 0 {
		if _, err := db.Exec(`INSERT INTO traffic_daily(username, day, bytes_in, bytes_out)
			SELECT username, date(COALESCE(NULLIF(last_seen,''), connected_at)), SUM(bytes_in), SUM(bytes_out)
			FROM sessions GROUP BY username, 2`); err == nil {
			mustExec(db, `INSERT INTO settings(key, value) VALUES('traffic_daily_backfilled', '1')`)
			log.Println("[store] traffic_daily 历史回填完成")
		}
	}
	// 会话台账一次性清洗（2026-10-08，用户报障导出脏数据）：
	// a) DCO 启用后 status "Real Address" 带 udp4:/tcp4: 协议前缀——存量行剥前缀
	//    （"udp4:"/"tcp4:" 等 5 字节，substr 从第 6 位起）
	// b) 幽灵进程时代（#5）产生的全列完全重复行——去重留最小 cid
	// c) 僵尸在账（崩溃窗口遗留的永久 settled=0 行）——last_seen 超 48h 即结算
	var ledgerCleaned int
	_ = db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='sessions_ledger_cleaned'`).Scan(&ledgerCleaned)
	if ledgerCleaned == 0 {
		mustExec(db, `UPDATE sessions SET trusted_ip = substr(trusted_ip, 6)
			WHERE trusted_ip LIKE 'udp4:%' OR trusted_ip LIKE 'udp6:%'
			   OR trusted_ip LIKE 'tcp4:%' OR trusted_ip LIKE 'tcp6:%'`)
		mustExec(db, `DELETE FROM sessions WHERE cid NOT IN
			(SELECT MIN(cid) FROM sessions GROUP BY username, virtual_ip, connected_at, trusted_ip,
			 bytes_in, bytes_out, last_seen, settled, node)`)
		mustExec(db, `UPDATE sessions SET settled=1 WHERE settled=0 AND COALESCE(last_seen,'') <> ''
			AND last_seen < datetime('now','localtime','-48 hours')`)
		mustExec(db, `UPDATE sessions SET settled=1 WHERE settled=0 AND COALESCE(last_seen,'') = ''
			AND COALESCE(connected_at,'') < datetime('now','localtime','-48 hours')`)
		mustExec(db, `INSERT INTO settings(key, value) VALUES('sessions_ledger_cleaned', '1')`)
		log.Println("[store] sessions 台账清洗完成（协议前缀/重复行/僵尸结算）")
	}
	// 防重建护栏：同 (username, virtual_ip, connected_at) 只允许一条未结算行
	//（tracker 重启复用按此语义；已结算历史行不受限）。若存量脏数据致建索引失败，
	// 上面的清洗 + tracker 僵尸自愈收敛后下次启动自然建成
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_unsettled
		ON sessions(username, virtual_ip, connected_at) WHERE settled = 0`); err != nil {
		log.Printf("[store] sessions 未结算唯一索引暂不可建（存量脏数据待自愈）: %v", err)
	}
	// §19 审计（月表，写时建）
}

func auditTable(day time.Time) string {
	return "audit_auth_" + day.Format("200601")
}

func ensureAuditTable(db *sql.DB, table string) {
	mustExec(db, `CREATE TABLE IF NOT EXISTS `+table+` (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time TEXT DEFAULT (datetime('now','localtime')),
		username TEXT, user_id INTEGER,
		idp_source TEXT, result TEXT, reason TEXT,
		trusted_ip TEXT, device_cn TEXT, trace_id TEXT
	)`)
}

func seedAdmin(db *sql.DB) {
	// §18 默认设置：primary 未设（初始化向导阶段 → adapter 显示选择页），本地兜底开；
	// vpn_remote 种子来自 env（不再内置任何部署地址），env 空=不种，签发时明确报错
	for _, kv := range [][2]string{
		{"primary_idp", ""},
		{"local_auth_enabled", "1"},
		{"hide_local_link", "0"},
	} {
		_, _ = db.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)`, kv[0], kv[1])
	}
	if v := os.Getenv("MODSAFE_VPN_REMOTE"); v != "" {
		_, _ = db.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES('vpn_remote', ?)`, v)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	if n > 0 {
		return
	}
	password := os.Getenv("MODSAFE_ADMIN_PASSWORD")
	if password == "" {
		// 安全加固（2026-09-29 审计复核）：不再使用源码内已知默认口令，改为随机生成并打印一次；
		// 产品化（§13.3）将替换为向导式首启改密
		b := make([]byte, 9)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("generate admin password: %v", err)
		}
		password = base64.RawURLEncoding.EncodeToString(b)
		log.Println("[INIT] 未设置 MODSAFE_ADMIN_PASSWORD，已生成随机初始管理员密码（请立即登录并修改）：admin / " + password)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("bcrypt: %v", err)
	}
	_, err = db.Exec(`INSERT INTO admins(username, password_hash, roles) VALUES(?,?,?)`,
		"admin", string(hash), `["super_admin","security_admin","auditor"]`)
	if err != nil {
		log.Fatalf("seed admin: %v", err)
	}
	log.Println("已初始化管理员：admin")
}

func getAdminRoles(db *sql.DB, username string) ([]string, error) {
	var rolesJSON string
	err := db.QueryRow(`SELECT roles FROM admins WHERE username=?`, username).Scan(&rolesJSON)
	if err != nil {
		return nil, fmt.Errorf("query admin: %w", err)
	}
	return jsonDecodeStringSlice(rolesJSON), nil
}
