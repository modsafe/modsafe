package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// ── 统一返回体（§12.4 规范：{code,message,data,traceId}）──

type Envelope struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	TraceID string      `json:"traceId,omitempty"`
}

func traceID(r *http.Request) string {
	if v := r.Header.Get("X-Trace-Id"); v != "" {
		return v
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, body Envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOK(w http.ResponseWriter, r *http.Request, data interface{}) {
	writeJSON(w, http.StatusOK, Envelope{Code: 0, Message: "ok", Data: data, TraceID: traceID(r)})
}

// failCode 用 §12.4 错误码段；httpStatus 按 REST 语义映射
func writeFail(w http.ResponseWriter, r *http.Request, code int, httpStatus int, msg string) {
	writeJSON(w, httpStatus, Envelope{Code: code, Message: msg, TraceID: traceID(r)})
}

func failParam(w http.ResponseWriter, r *http.Request, msg string) {
	writeFail(w, r, 10001, http.StatusBadRequest, msg)
}

func failBiz(w http.ResponseWriter, r *http.Request, code int, msg string) {
	writeFail(w, r, code, http.StatusBadRequest, msg)
}

func failSystem(w http.ResponseWriter, r *http.Request, msg string) {
	writeFail(w, r, 50001, http.StatusInternalServerError, msg)
}

// ── 通用工具 ──

func pageParams(r *http.Request) (page, pageSize int) {
	page = atoiDefault(r.URL.Query().Get("page"), 1)
	pageSize = atoiDefault(r.URL.Query().Get("pageSize"), 20)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return page, pageSize
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

func pageData(list interface{}, total, page, pageSize int) map[string]interface{} {
	return map[string]interface{}{
		"list": list, "total": total, "page": page, "pageSize": pageSize,
	}
}

func mustExec(db *sql.DB, q string, args ...interface{}) {
	if _, err := db.Exec(q, args...); err != nil {
		log.Fatalf("schema exec: %v\nsql: %s", err, q)
	}
}

// execIgnoreDup：ALTER TABLE 已存在列时静默（幂等迁移）
func execIgnoreDup(db *sql.DB, q string) error {
	_, err := db.Exec(q)
	if err != nil && strings.Contains(err.Error(), "duplicate column") {
		return nil
	}
	return err
}

func notFound(w http.ResponseWriter, r *http.Request, what string) {
	writeFail(w, r, 20001, http.StatusNotFound, what+"不存在")
}

// contentDisposition（#125）：RFC 6266/5987 双参数下载文件名。
// HTTP 头本身是 Latin-1 语义——直接 filename="中文" 会被浏览器按 CP1252 解读成乱码
// （#125：卢致榕 → å?¢è?´æ??）。filename* 携带 UTF-8 百分号编码（现代浏览器据此还原
// 中文名），filename 给 ASCII 回退（老旧客户端）。filename 含引号/控制符时按纯回退处理。
func contentDisposition(filename string) string {
	// ASCII 回退名：剥离非 ASCII 字符（旧浏览器/不认 filename* 的下载器也能拿到
	// 可用的名字+扩展名，而非无扩展名的 "download"）；filename* 携带 UTF-8 百分号
	// 编码（现代浏览器据此还原中文名）。文件名含引号/控制符时按纯回退处理。
	var b strings.Builder
	for _, r := range filename {
		if r <= 126 && r >= 32 && r != '"' && r != '\\' {
			b.WriteRune(r)
		}
	}
	ascii := strings.TrimLeft(b.String(), "-.")
	if ascii == "" {
		ascii = "download"
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + url.PathEscape(filename)
}

func fmtErr(op string, err error) string {
	return fmt.Sprintf("%s: %v", op, err)
}
