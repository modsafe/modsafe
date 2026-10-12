// modsafe-control：商业化企业 VPN 控制平面（§12 架构，Go + SQLite）
// 骨架阶段实现 §12.4 一期 API + embed 前端；OpenVPN management 对接与 TLS 由部署层（§13）补齐。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// validateConfig：必填配置缺一拒绝启动（fail-fast，不带弱默认运行）。
// 三元组是门户登录 OAuth 跳转/交换的最小集，错误在启动时暴露好过用户登录时白屏。
func validateConfig() {
	var missing []string
	for _, kv := range [][2]string{
		{"MODSAFE_ADAPTER_PUBLIC_URL", adapterPublicBase},
		{"MODSAFE_PORTAL_CLIENT_ID", portalClientID},
		{"MODSAFE_PORTAL_CLIENT_SECRET", portalClientSecret},
	} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		log.Printf("[CONFIG] 缺少必填环境变量: %s（参考 examples/control.env.example）", strings.Join(missing, ", "))
		os.Exit(2)
	}
}

func main() {
	// 必填配置缺一拒绝启动（fail-fast）：门户 OAuth 跳转三元组
	validateConfig()
	addr := envOr("MODSAFE_ADDR", "127.0.0.1:9443")

	db := mustOpenDB(envOr("MODSAFE_DATA_DIR", "data"))
	defer db.Close()
	seedAdmin(db)
	loadNodes(envOr("MODSAFE_DATA_DIR", "data"))

	mux := http.NewServeMux()
	app := &App{db: db}
	registerAPI(mux, app)
	registerWeb(mux)
	// License 试用计时必须在启动时激活（否则无人打开 License 页时 trial_started_at 永不写入，
	// 试用期成为无限期——2026-09-29 复核修复）
	app.licenseState()
	go func() {
		if _, _, _, err := app.syncCCDFiles(); err != nil {
			log.Printf("[ccd] startup sync: %v", err)
		}
	}() // 启动时全量同步 CCD 下发文件
	go app.StartSessionTracker() // 会话台账（控制平面自持，username 归属准确）
	go app.startFlowCollector()  // 流量审计采集器（#70，30s 周期 conntrack 轮询）
	go func() {                  // 启动即应用服务端路由强制（节点重启自愈）
		time.Sleep(3 * time.Second)
		app.syncForwardGuard()
	}()
	app.initSeedAlertRules()     // §20 告警规则种子数据
	go func() {                  // §20 告警定期检查（5min）
		for {
			app.RunAlertChecks()
			time.Sleep(5 * time.Minute)
		}
	}()

	srv := &http.Server{Addr: addr, Handler: accessLog(mux)}

	go func() {
		log.Printf("modsafe-control listening on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM) // systemd stop 发 SIGTERM，需优雅退出
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
