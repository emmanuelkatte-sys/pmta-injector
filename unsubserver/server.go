package unsubserver

// =============================================================================
// 【2026-05-24 批次 2】HTTP 退订服务器
//
// 用途：仅当 ListUnsubMode = "real" 时启动；为邮件 List-Unsubscribe 头里的 URL
// 提供真实可访问的退订页面（Gmail/Yahoo 反垃圾爬虫验证用）。
//
// 架构（C1 决策）：
//   - 独立 systemd service（pmta-injector-unsub.service）长期运行
//   - 监听 0.0.0.0:80（→ 301 → HTTPS）+ 0.0.0.0:443（TLS）
//   - 通配符路由所有路径都返回同一个 2 KB 日文静态退订页
//
// 反指纹（C3 决策）：
//   - HTML 实例签名：启动时一次性随机生成（颜色 + 注释 token + 标点空格）
//   - 同一进程生命周期内稳定（爬虫多次 GET 内容一致，不触发"动态"警报）
//   - 不同服务器之间不同（破坏批量指纹聚类）
//   - X-Robots-Tag: noindex, nofollow（防搜索引擎索引暴露发件指纹）
//
// 证书续期（C2 决策）：
//   - tls.Config.GetCertificate 每次握手回调重读证书文件
//   - acme.sh 续期后自动生效，无需 reload，零运维
//
// 资源占用：
//   - 单 goroutine + net/http
//   - 静态 HTML < 2 KB 内嵌
//   - IDLE 状态约 10 MB RAM
// =============================================================================

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"__MODULE_PLACEHOLDER__/config"
)

// Server HTTP 退订服务器
type Server struct {
	cfg config.UnsubscribeServerConfig

	// HTTP / HTTPS 服务器实例（关闭用）
	httpSrv  *http.Server
	httpsSrv *http.Server

	// 实例签名（启动时一次性生成，进程生命周期内不变）
	instanceSig instanceSignature

	// 缓存生成好的 HTML（避免每次请求重新拼接）
	cachedHTML []byte

	// access log（每天滚动一次，保留 7 天）
	logFile     *os.File
	logFilePath string
	logMu       sync.Mutex
}

// instanceSignature HTML 反指纹随机化的"实例签名"
// 启动时一次随机生成，整个进程生命周期内稳定
type instanceSignature struct {
	HeadingColor string // 标题颜色 6 位 hex（如 0066cc）
	BodyColor    string // 正文颜色 6 位 hex
	HtmlComment  string // HTML 注释里的随机 token
	UseFullStop  bool   // 句末是否带句号（。）
	PaddingLen   int    // 末尾空白 padding 长度（0-32）
	HeadingText  string // 从 3 个备选中选 1 个（避免完全雷同）
	BodyText     string // 从 3 个备选中选 1 个
}

// 头标题候选池（3 个都是真实退订页面常见日语写法）
var headingCandidates = []string{
	"メール配信停止手続き完了",
	"配信停止が完了しました",
	"メール配信停止が完了しました",
}

// 正文候选池
var bodyCandidates = []string{
	"ご登録いただいたメールアドレスへの配信を停止しました。今後、当社からのメールは届きません。",
	"メールマガジンの配信停止を承りました。今後はメールが届きません。",
	"配信停止のお手続きが完了しました。今後このメールアドレスへ配信されることはございません。",
}

// generateInstanceSignature 生成本进程的实例签名（启动时调用一次）
func generateInstanceSignature() instanceSignature {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败的兜底（极罕见）
		copy(buf, []byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}

	// 颜色：从近蓝色调里抽（看起来都像专业风格但每个服务器略不同）
	headingColors := []string{"0055bb", "0066cc", "1d4ed8", "2563eb", "1e40af", "1565c0", "0d47a1"}
	bodyColors := []string{"333333", "444444", "555555", "2f2f2f", "3a3a3a"}

	// 用 buf 的字节决定从池里选哪个（保证启动时一次抽样后稳定）
	hIdx := int(buf[0]) % len(headingColors)
	bIdx := int(buf[1]) % len(bodyColors)
	hCandIdx := int(buf[2]) % len(headingCandidates)
	bCandIdx := int(buf[3]) % len(bodyCandidates)
	useFullStop := buf[4]&1 == 1
	padLen := int(buf[5]) % 33

	return instanceSignature{
		HeadingColor: headingColors[hIdx],
		BodyColor:    bodyColors[bIdx],
		HtmlComment:  hex.EncodeToString(buf[6:14]),
		UseFullStop:  useFullStop,
		PaddingLen:   padLen,
		HeadingText:  headingCandidates[hCandIdx],
		BodyText:     bodyCandidates[bCandIdx],
	}
}

// buildHTML 根据实例签名生成退订页面 HTML（一次性调用，结果缓存）
func buildHTML(sig instanceSignature) []byte {
	bodyText := sig.BodyText
	if !sig.UseFullStop {
		// 去掉文末句号（。）
		bodyText = strings.TrimRight(bodyText, "。")
	}

	padding := strings.Repeat(" ", sig.PaddingLen)

	// HTML 模板（< 2 KB），所有反指纹变量都注入
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>%s</title>
<style>
body { font-family: 'Hiragino Sans', 'Yu Gothic', sans-serif; text-align: center; padding: 60px 20px; color: #%s; max-width: 600px; margin: 0 auto; }
h1 { font-size: 22px; color: #%s; margin-bottom: 16px; }
p { font-size: 14px; line-height: 1.7; margin: 0.8em 0; }
.thanks { margin-top: 24px; color: #888; font-size: 13px; }
</style>
</head>
<body>
<h1>%s</h1>
<p>%s</p>
<p class="thanks">ご利用ありがとうございました</p>
<!-- ref:%s -->%s
</body>
</html>
`, sig.HeadingText,
		sig.BodyColor,
		sig.HeadingColor,
		sig.HeadingText,
		bodyText,
		sig.HtmlComment,
		padding,
	)

	return []byte(html)
}

// NewServer 创建 HTTP 退订服务器
func NewServer(cfg config.UnsubscribeServerConfig) (*Server, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("unsubscribe server is disabled in config")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("cert_file and key_file are required")
	}
	if cfg.ListenHTTPS == "" {
		cfg.ListenHTTPS = ":443"
	}
	if cfg.ListenHTTP == "" {
		cfg.ListenHTTP = ":80"
	}

	sig := generateInstanceSignature()
	html := buildHTML(sig)

	srv := &Server{
		cfg:         cfg,
		instanceSig: sig,
		cachedHTML:  html,
	}

	// 打开 access log（路径：/var/log/pmta-injector-unsub/access.log）
	logDir := "/var/log/pmta-injector-unsub"
	if err := os.MkdirAll(logDir, 0755); err == nil {
		srv.logFilePath = filepath.Join(logDir, "access.log")
		if f, err := os.OpenFile(srv.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			srv.logFile = f
		}
	}

	return srv, nil
}

// Run 启动服务器（阻塞，直到收到关闭信号）
//
// 同时启动 HTTP（80 → 301 → HTTPS）和 HTTPS（443 → 退订页面）两个 server
// 任一 server 启动失败会立即返回错误
//
// ctx 用于优雅关闭：ctx.Done() 触发时两个 server 都被 Shutdown
func (s *Server) Run(ctx context.Context) error {
	// === HTTPS server: 主入口，返回退订页面 ===
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", s.handleUnsubscribe)

	// TLS 配置：GetCertificate 回调每次握手重读证书文件（C2 决策）
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load cert/key failed: %w", err)
			}
			return &cert, nil
		},
	}

	s.httpsSrv = &http.Server{
		Addr:              s.cfg.ListenHTTPS,
		Handler:           httpsMux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// === HTTP server: 80 端口 301 → HTTPS ===
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", s.handleHTTPRedirect)

	s.httpSrv = &http.Server{
		Addr:              s.cfg.ListenHTTP,
		Handler:           httpMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 启动两个 server（各自一个 goroutine）
	errCh := make(chan error, 2)

	go func() {
		log.Printf("[unsubserver] HTTPS listening on %s (cert=%s)", s.cfg.ListenHTTPS, s.cfg.CertFile)
		// ListenAndServeTLS 的参数留空，因为 GetCertificate 回调已配置
		if err := s.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("https server: %w", err)
		}
	}()

	go func() {
		log.Printf("[unsubserver] HTTP listening on %s (301 → HTTPS)", s.cfg.ListenHTTP)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	// 等待 ctx 取消 或 任一 server 出错
	select {
	case err := <-errCh:
		s.shutdown()
		return err
	case <-ctx.Done():
		log.Println("[unsubserver] received shutdown signal, gracefully shutting down...")
		s.shutdown()
		return nil
	}
}

// shutdown 关闭两个 server + access log（5 秒超时）
func (s *Server) shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpsSrv != nil {
		_ = s.httpsSrv.Shutdown(shutdownCtx)
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}
	if s.logFile != nil {
		_ = s.logFile.Close()
	}
}

// hostMatchesConfigured 校验请求的 Host header 是否匹配配置的 Domain
//
// 【2026-05-24 D2 加固】反扫描：拒绝 Host 不匹配的请求（直接 IP 访问 / 错误的 Hostname）。
// 邮件 List-Unsubscribe URL 由 Gmail/Yahoo 解析 → DNS A 查到正确 IP → 请求带 Host: <domain> 头。
// 互联网扫描器扫到本机 IP 后通常用 IP 作为 Host 或留空 → 不匹配 → 404 → 不暴露"这是发件器"。
//
// 容错：
//   - 剥端口号（"smtp.maidong.com:443" → "smtp.maidong.com"）
//   - 支持 IPv6 字面量（"[::1]:80" → "::1"）
//   - 大小写不敏感
//   - cfg.Domain 空时退化为不校验（部署异常兜底，避免误拒所有请求）
//
// 返回 true = 允许处理；false = 拒绝（调用方应返回 404）
func (s *Server) hostMatchesConfigured(r *http.Request) bool {
	configured := strings.TrimSpace(s.cfg.Domain)
	if configured == "" {
		// 配置缺失 → 退化不校验（避免误拒）
		return true
	}

	host := r.Host
	if host == "" {
		// 客户端没发 Host 头（HTTP/1.0 古老客户端可能）→ 拒绝
		return false
	}

	// 剥端口号。处理 3 种格式：
	//   "smtp.maidong.com" → 直接用
	//   "smtp.maidong.com:443" → 取 ":" 前部分
	//   "[::1]:80" → IPv6 字面量，找最后的 "]:" 之后切
	if strings.HasPrefix(host, "[") {
		// IPv6 字面量
		if end := strings.LastIndex(host, "]"); end > 0 {
			host = host[1:end] // 取 [...] 之间内容
		}
	} else if idx := strings.LastIndex(host, ":"); idx >= 0 {
		// IPv4 / 普通主机名带端口
		host = host[:idx]
	}

	return strings.EqualFold(strings.TrimSpace(host), configured)
}

// handleUnsubscribe 退订页面处理器（所有路径 + GET / POST / HEAD 都返回同一个页面）
func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	// 【2026-05-24 D2 加固】Host 校验：不匹配返回 404，避免直接 IP 访问暴露身份
	if !s.hostMatchesConfigured(r) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		http.NotFound(w, r)
		s.logAccess(r, http.StatusNotFound, 0)
		return
	}

	// 反指纹响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// 内容长度（同一进程稳定，反指纹角度好）
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(s.cachedHTML)))

	// HEAD 不写 body
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		s.logAccess(r, http.StatusOK, 0)
		return
	}

	// GET / POST / PUT / 其他全部 200 + HTML
	// （Gmail One-Click 用 POST，普通爬虫用 GET）
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write(s.cachedHTML)

	s.logAccess(r, http.StatusOK, n)
}

// handleHTTPRedirect HTTP 80 端口 → 301 → HTTPS
func (s *Server) handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	// 【2026-05-24 D2 加固】80 端口同样做 Host 校验，避免扫描器从 IP 端口直接被重定向到 HTTPS 暴露域名
	if !s.hostMatchesConfigured(r) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		http.NotFound(w, r)
		s.logAccess(r, http.StatusNotFound, 0)
		return
	}

	host := r.Host
	// 去掉端口号（如果有）
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	// 兜底：如果 Host 头缺失或异常，用配置的 Domain
	if host == "" {
		host = s.cfg.Domain
	}
	target := "https://" + host + r.URL.RequestURI()

	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	http.Redirect(w, r, target, http.StatusMovedPermanently)

	s.logAccess(r, http.StatusMovedPermanently, 0)
}

// logAccess 写入 access log（线程安全，日滚动）
//
// 格式：YYYY-MM-DDTHH:MM:SS±HHMM REMOTE_ADDR METHOD HOST PATH STATUS BYTES UA
func (s *Server) logAccess(r *http.Request, status int, bytes int) {
	if s.logFile == nil {
		return
	}

	s.logMu.Lock()
	defer s.logMu.Unlock()

	// 简单日滚动：如果今天的日期 + ".log" 文件不存在，rotate
	s.rotateIfNeeded()

	now := time.Now().Format("2006-01-02T15:04:05-0700")
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "-"
	}
	line := fmt.Sprintf("%s %s %s %s %s %d %d %q\n",
		now, r.RemoteAddr, r.Method, r.Host, r.URL.RequestURI(), status, bytes, ua)
	_, _ = io.WriteString(s.logFile, line)
}

// rotateIfNeeded 简单日滚动：检查 access.log 最后修改日期，与今天不同则 rotate 并清理 > 7 天的归档
func (s *Server) rotateIfNeeded() {
	if s.logFile == nil || s.logFilePath == "" {
		return
	}
	info, err := s.logFile.Stat()
	if err != nil {
		return
	}
	today := time.Now().Format("2006-01-02")
	lastMod := info.ModTime().Format("2006-01-02")
	if today == lastMod {
		return
	}

	// rotate：把 access.log → access.log.YYYY-MM-DD
	_ = s.logFile.Close()
	archived := s.logFilePath + "." + lastMod
	_ = os.Rename(s.logFilePath, archived)

	// 重新打开
	f, err := os.OpenFile(s.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		s.logFile = nil
		return
	}
	s.logFile = f

	// 清理 > 7 天的归档
	go s.cleanOldLogs()
}

// cleanOldLogs 删除 access.log.* 中 mtime > 7 天的
func (s *Server) cleanOldLogs() {
	dir := filepath.Dir(s.logFilePath)
	prefix := filepath.Base(s.logFilePath) + "."
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
