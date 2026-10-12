package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// 前端构建产物（构建前由 scripts/copy-web 同步 modsafe-web/dist → web/dist）
//
//go:embed all:web/dist
var webDist embed.FS

func registerWeb(mux *http.ServeMux) {
	sub, err := fs.Sub(webDist, "web/dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		isPortal := p == "portal" || p == "portal/"
		// 门户入口（§16）：/portal 与 /portal/（尾斜杠）都精确服务 portal.html（不落入管理台 index.html 回退）
		if isPortal {
			if b, err := fs.ReadFile(sub, "portal.html"); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(b)
				return
			}
		}
		// /portal/xxx（尾斜杠入口下 ./assets/... 的相对引用）映射回 dist 根：重写请求路径后再交给 fileServer
		if trimmed := strings.TrimPrefix(p, "portal/"); trimmed != p {
			isPortal = true
			p = trimmed
			r2, u := *r, *r.URL
			u.Path = "/" + p
			r2.URL = &u
			r = &r2
		}
		if p != "" {
			if f, err := sub.Open(p); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// HashRouter：所有无文件路径回退（门户前缀路径回退 portal.html，其余回退管理台 index.html）
		name := "index.html"
		if isPortal {
			name = "portal.html"
		}
		index, err := fs.ReadFile(sub, name)
		if err != nil {
			http.Error(w, "前端未构建（web/dist 缺失，先运行 scripts/copy-web）", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
