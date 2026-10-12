package main

// watchdog 角色：ha-watchdog.py 的 Go 移植（180 与 193 同一二进制）。
// 职责一（双机）：探测 node-1/node-2 openvpn 健康，动态调整本机 IPVS 权重
//   （修复静态 IPVS 表无健康检查的缺口）；首轮强制应用实现重启自愈。
// 职责二（仅 193）：主节点 180 宿主机级守护——控制面(9443)+adapter(经 80 口)
//   连续 3 轮同时不可达 → critical 告警（30 分钟重提醒 + 恢复通知）。
// 安全边界：探测目标为集群固定拓扑字面量 URL（拓扑/CA 锚可经 env 覆盖，见下）；TLS 验证=集群 CA 锚链式校验
//   （/etc/pki/ca-trust/source/anchors/opensec-web.crt，#143 信任锚；免主机名/IP SAN，
//   CA 续期安全），严格强于原 Python 的跳过校验。

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// 集群拓扑：全部经 env 配置（不内置任何部署地址）；未配置时 watchdog 自禁用（见 runWatchdog）。
//（口径同 collector 的 NODE_AGENT_193 / agent 的 envPath 系列）
var (
	watchVIPPort = envOr("MODSAFE_WATCH_VIP", "")
	watchRS1     = envOr("MODSAFE_WATCH_RS1", "")
	watchRS2     = envOr("MODSAFE_WATCH_RS2", "")
	// 控制面健康探测完整 URL（如 https://portal.example.com:9443/api/v1/healthz）；
	// 未配置=跳过该探测（视为可达，避免 IPVS 权重误摘），启动时 log 提醒
	controlHealthz = envOr("MODSAFE_CONTROL_HEALTHZ", "")

	clusterAnchorCert = envPath("MODSAFE_CLUSTER_ANCHOR_CERT",
		"/etc/pki/ca-trust/source/anchors/opensec-web.crt")

	rs1IP, rs2IP = hostOf(watchRS1), hostOf(watchRS2)
)

// hostOf：从 "ip:port" 取 host 部分（集群拓扑为 IPv4，不处理裸 IPv6）
func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

var clusterRoots *x509.CertPool

var (
	watchMu   sync.Mutex
	watchST   = map[string]any{} // key -> 状态，仅在变化时操作 IPVS/告警
	watchSelf string
)

func initClusterRoots() {
	pemBytes, err := os.ReadFile(clusterAnchorCert)
	if err != nil {
		logf("watchdog: 集群 CA 锚不可读（%v），TLS 探测回退系统根", err)
		return
	}
	pool := x509.NewCertPool()
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(crt)
	}
	clusterRoots = pool
}

// insecureTransport：VerifyConnection 集群 CA 链校验（免 IP SAN），不禁用证书验证
func watchHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no peer certificate")
				}
				roots := clusterRoots
				if roots == nil {
					roots, _ = x509.SystemCertPool()
				}
				opts := x509.VerifyOptions{Roots: roots} // 空 DNSName=只验链不验主机名（内网 IP 探测）
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		},
	}}
}

func getStatus(target string) (int, error) {
	client := watchHTTPClient(5 * time.Second)
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func detectRole() string {
	if rs1IP != "" && strings.Contains(" "+hostnameI()+" ", " "+rs1IP+" ") {
		return rs1IP
	}
	return rs2IP
}

func probe180Summary() map[string]any {
	if rs1IP == "" {
		return nil
	}
	m, err := httpGetJSON("http://"+rs1IP+":7505/summary", 5*time.Second)
	if err != nil {
		return nil
	}
	return m
}

func node1VPNAlive(selfIP string) bool {
	if selfIP == rs1IP {
		return svcActive("openvpn-modsafe@1") == "active"
	}
	// 对端经 node-1 collector 摘要判断；collector 不可达视为主机级故障（由守护告警覆盖）
	d := probe180Summary()
	if d == nil {
		return false
	}
	nodes, _ := d["nodes"].(map[string]any)
	n1, _ := nodes["node-1@180"].(map[string]any)
	if n1 == nil {
		return false
	}
	return int(mF64(n1, "active")) == 1
}

func node2VPNAlive(selfIP string) bool {
	if selfIP == rs2IP {
		return svcActive("openvpn-modsafe@2") == "active"
	}
	if rs2IP == "" {
		return false
	}
	code, err := getStatus("http://" + rs2IP + ":7503/healthz")
	return err == nil && code == 200
}

func probeControlPlane180() bool {
	if controlHealthz == "" {
		logf("watchdog: MODSAFE_CONTROL_HEALTHZ 未配置，跳过控制面探测（视为可达）")
		return true
	}
	code, err := getStatus(controlHealthz)
	return err == nil && code == 200
}

func probeAdapterVia80() bool {
	if rs1IP == "" {
		return false
	}
	code, err := getStatus("https://" + rs1IP + "/healthz")
	return err == nil && code == 200
}

func ipvsEdit(rs string, weight int) {
	// UDP 服务用 -u；-m 与 keepalived 建立的 Masq 转发标志一致（2026-09-29 实测定论）
	_, rc, err := ipvsadmEdit(watchVIPPort, rs, weight)
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 120 {
			msg = msg[:120]
		}
	}
	logf("IPVS %s weight -> %d (rc=%d %s)", rs, weight, rc, msg)
}

func boolWeight(b bool) int {
	if b {
		return 1
	}
	return 0
}

func updateRS(rs string, alive bool, key string) {
	watchMu.Lock()
	prev, has := watchST[key]
	watchMu.Unlock()
	if !has || alive != prev.(bool) {
		// 首轮强制应用：重启后 STATE 归零，若表里残留误权重（前进程留下的 0）也能自愈
		ipvsEdit(rs, boolWeight(alive))
		if alive {
			logf("%s 恢复", key)
		} else {
			logf("%s 不可用 → IPVS 权重摘除", key)
		}
	}
	watchMu.Lock()
	watchST[key] = alive
	watchMu.Unlock()
}

func watchStateGet(key string) (any, bool) {
	watchMu.Lock()
	defer watchMu.Unlock()
	v, has := watchST[key]
	return v, has
}

func watchStateSet(key string, v any) {
	watchMu.Lock()
	watchST[key] = v
	watchMu.Unlock()
}

func notify180Host(down bool) {
	// 193 侧：主节点宿主机级告警（down 触发一次 + 30 分钟重提醒 + 恢复通知）
	notify180Log := func(level, msg string) {
		results := notifyAll(level, msg, nowUnix())
		logf("180-host 告警投递[%s]: %v", level, results)
	}
	const key = "watchdog:180-host"
	prev, has := watchStateGet(key)
	lastAny, _ := watchStateGet("watchdog:180-host-last")
	last, _ := lastAny.(int64)
	now := nowUnix()
	if down {
		if !has || prev != false {
			notify180Log("critical",
				"主节点 180 不可达：控制面(9443)+adapter(8000) 连续探测失败，"+
					"VPN 数据面 VIP 将由 keepalived 切换至 193；"+
					"控制面/License/目录同步暂不可用，请尽快排查")
			watchStateSet("watchdog:180-host-last", now)
		} else if now-last > 1800 {
			notify180Log("critical", "主节点 180 不可达（持续超 30 分钟，仍未恢复）")
			watchStateSet("watchdog:180-host-last", now)
		}
		watchStateSet(key, false)
	} else {
		if has && prev == false {
			notify180Log("warn", "主节点 180 已恢复可达")
		}
		watchStateSet(key, true)
	}
}

func runWatchdog() {
	if watchVIPPort == "" || watchRS1 == "" || watchRS2 == "" {
		logf("ha-watchdog disabled: 需配置 MODSAFE_WATCH_VIP / MODSAFE_WATCH_RS1 / MODSAFE_WATCH_RS2")
		return
	}
	NOTIFY_ALLOW_PRIV = os.Getenv("MODSAFE_NOTIFY_ALLOW_PRIVATE") == "1"
	initClusterRoots()
	watchSelf = detectRole()
	logf("ha-watchdog start: self=%s", watchSelf)
	fail180 := 0
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logf("watchdog round panic: %v", r)
				}
			}()
			updateRS(watchRS1, node1VPNAlive(watchSelf), "node1")
			updateRS(watchRS2, node2VPNAlive(watchSelf), "node2")

			if watchSelf == rs2IP {
				// 主节点宿主机级探测：控制面 + adapter 同时失联才判 down（3 轮=90s）
				if !probeControlPlane180() && !probeAdapterVia80() {
					fail180++
				} else {
					fail180 = 0
				}
				notify180Host(fail180 >= 3)
			}
		}()
		time.Sleep(30 * time.Second)
	}
}
