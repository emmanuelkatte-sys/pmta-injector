// Package smtp 提供面向 MTA 的 SMTP 客户端与连接池。
//
// 当配置启用 smtp.enabled 时，injector 通过本包将完整 RFC 822 邮件
// 提交到本地 MTA（如 PowerMTA 127.0.0.1:25 或 Haraka）。
// pool.go 负责连接复用、失败丢弃和按发送次数轮换连接。
package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client SMTP 客户端连接
type Client struct {
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	addr       string
	timeout    time.Duration
	extensions map[string]string
	lastUsed   time.Time
	sendCount  int // 该连接已发送邮件数
}

// AuthConfig SMTP 认证配置
type AuthConfig struct {
	UseAuth  bool
	Username string
	Password string
}

// connect 建立连接并完成 EHLO 握手 + 可选 AUTH
func connect(addr string, timeout time.Duration, useTLS bool, skipVerify bool, auth *AuthConfig) (*Client, error) {
	// 建立 TCP 连接
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}

	// 如果需要 TLS
	if useTLS {
		host, _, _ := net.SplitHostPort(addr)
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
		}
		conn = tls.Client(conn, tlsConfig)
	}

	client := &Client{
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
		addr:       addr,
		timeout:    timeout,
		extensions: make(map[string]string),
		lastUsed:   time.Now(),
		sendCount:  0,
	}

	// 设置初始超时
	conn.SetDeadline(time.Now().Add(timeout))

	// 读取服务器欢迎消息 (220)
	code, greetLines, err := client.readResponse()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取欢迎消息失败: %w", err)
	}
	if code != 220 {
		conn.Close()
		return nil, fmt.Errorf("服务器拒绝连接，响应码: %d", code)
	}

	// 发送 EHLO 命令
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	code, lines, err := client.command("EHLO %s", hostname)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("EHLO 命令失败: %w", err)
	}
	if code != 250 {
		conn.Close()
		return nil, fmt.Errorf("EHLO 被拒绝，响应码: %d", code)
	}

	// 解析服务器支持的扩展
	client.parseExtensions(lines)

	// YAML use_auth、mta_type=haraka，或欢迎语是 Haraka：都做 AUTH
	if shouldSMTPAuth(auth, greetLines) {
		if err := client.authenticate(auth); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}

	return client, nil
}

func shouldSMTPAuth(auth *AuthConfig, greeting []string) bool {
	if auth == nil || strings.TrimSpace(auth.Username) == "" {
		return false
	}
	if auth.UseAuth {
		return true
	}
	return greetingLooksLikeHaraka(greeting)
}

func greetingLooksLikeHaraka(lines []string) bool {
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "haraka") {
			return true
		}
	}
	return false
}

// authenticate 执行 SMTP AUTH PLAIN 认证
func (c *Client) authenticate(auth *AuthConfig) error {
	// 检查服务器是否支持 AUTH
	if !c.HasExtension("AUTH") {
		// 服务器不宣告 AUTH 扩展，尝试直接发送（有些服务器对本地连接默认允许中继）
		return nil
	}

	// AUTH PLAIN: base64("\0username\0password")
	authStr := fmt.Sprintf("\x00%s\x00%s", auth.Username, auth.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(authStr))

	code, lines, err := c.command("AUTH PLAIN %s", encoded)
	if err != nil {
		return fmt.Errorf("AUTH PLAIN 命令失败: %w", err)
	}

	if code == 235 {
		// 认证成功
		return nil
	}

	// 如果 PLAIN 失败，尝试 AUTH LOGIN
	if code == 504 || code == 535 || code == 503 {
		return c.authenticateLogin(auth)
	}

	errMsg := ""
	if len(lines) > 0 {
		errMsg = lines[0]
	}
	return fmt.Errorf("AUTH PLAIN 被拒绝 [%d]: %s", code, errMsg)
}

// authenticateLogin 执行 AUTH LOGIN 认证
func (c *Client) authenticateLogin(auth *AuthConfig) error {
	code, _, err := c.command("AUTH LOGIN")
	if err != nil {
		return fmt.Errorf("AUTH LOGIN 命令失败: %w", err)
	}
	if code != 334 {
		return fmt.Errorf("AUTH LOGIN 被拒绝，响应码: %d", code)
	}

	// 发送用户名（Base64编码）
	code, _, err = c.command(base64.StdEncoding.EncodeToString([]byte(auth.Username)))
	if err != nil {
		return fmt.Errorf("发送用户名失败: %w", err)
	}
	if code != 334 {
		return fmt.Errorf("用户名被拒绝，响应码: %d", code)
	}

	// 发送密码（Base64编码）
	code, lines, err := c.command(base64.StdEncoding.EncodeToString([]byte(auth.Password)))
	if err != nil {
		return fmt.Errorf("发送密码失败: %w", err)
	}
	if code != 235 {
		errMsg := ""
		if len(lines) > 0 {
			errMsg = lines[0]
		}
		return fmt.Errorf("AUTH LOGIN 认证失败 [%d]: %s", code, errMsg)
	}

	return nil
}

// Send 发送单封邮件
func (c *Client) Send(from, to string, msg []byte) error {
	// 更新超时
	c.conn.SetDeadline(time.Now().Add(c.timeout))
	c.lastUsed = time.Now()

	// 1. MAIL FROM
	code, lines, err := c.command("MAIL FROM:<%s>", from)
	if err != nil {
		return fmt.Errorf("MAIL FROM 失败: %w", err)
	}
	if code != 250 {
		errMsg := ""
		if len(lines) > 0 {
			errMsg = lines[0]
		}
		return fmt.Errorf("MAIL FROM 被拒绝 [%d]: %s", code, errMsg)
	}

	// 2. RCPT TO
	code, lines, err = c.command("RCPT TO:<%s>", to)
	if err != nil {
		return fmt.Errorf("RCPT TO 失败: %w", err)
	}
	if code != 250 && code != 251 {
		errMsg := ""
		if len(lines) > 0 {
			errMsg = lines[0]
		}
		return fmt.Errorf("RCPT TO 被拒绝 [%d]: %s", code, errMsg)
	}

	// 3. DATA
	code, lines, err = c.command("DATA")
	if err != nil {
		return fmt.Errorf("DATA 命令失败: %w", err)
	}
	if code != 354 {
		errMsg := ""
		if len(lines) > 0 {
			errMsg = lines[0]
		}
		return fmt.Errorf("DATA 被拒绝 [%d]: %s", code, errMsg)
	}

	// 4. 发送邮件内容
	escapedMsg := c.escapeDotsInMessage(msg)

	if _, err := c.writer.Write(escapedMsg); err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}

	// 确保以 CRLF.CRLF 结束
	if !bytes.HasSuffix(escapedMsg, []byte("\r\n")) {
		c.writer.WriteString("\r\n")
	}
	c.writer.WriteString(".\r\n")

	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("发送邮件内容失败: %w", err)
	}

	// 5. 等待服务器确认
	code, lines, err = c.readResponse()
	if err != nil {
		return fmt.Errorf("等待邮件确认失败: %w", err)
	}
	if code != 250 {
		errMsg := ""
		if len(lines) > 0 {
			errMsg = lines[0]
		}
		return fmt.Errorf("邮件被拒绝 [%d]: %s", code, errMsg)
	}

	c.sendCount++
	return nil
}

// Reset 重置连接状态
func (c *Client) Reset() error {
	c.conn.SetDeadline(time.Now().Add(c.timeout))
	code, _, err := c.command("RSET")
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("RSET 失败，响应码: %d", code)
	}
	return nil
}

// Noop 发送 NOOP 命令检查连接是否存活
func (c *Client) Noop() error {
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	code, _, err := c.command("NOOP")
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("NOOP 失败，响应码: %d", code)
	}
	return nil
}

// IsHealthy 检查连接是否健康
func (c *Client) IsHealthy() bool {
	if time.Since(c.lastUsed) > 30*time.Second {
		return c.Noop() == nil
	}
	return true
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	c.command("QUIT")
	return c.conn.Close()
}

// SendCount 获取已发送邮件数
func (c *Client) SendCount() int {
	return c.sendCount
}

// LastUsed 获取最后使用时间
func (c *Client) LastUsed() time.Time {
	return c.lastUsed
}

// command 发送命令并读取响应
func (c *Client) command(format string, args ...interface{}) (int, []string, error) {
	cmd := fmt.Sprintf(format, args...)

	if _, err := c.writer.WriteString(cmd + "\r\n"); err != nil {
		return 0, nil, fmt.Errorf("发送命令失败: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		return 0, nil, fmt.Errorf("刷新缓冲区失败: %w", err)
	}

	return c.readResponse()
}

// readResponse 读取 SMTP 响应（支持多行）
func (c *Client) readResponse() (int, []string, error) {
	var lines []string

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return 0, nil, fmt.Errorf("读取响应失败: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)

		if len(line) < 3 {
			return 0, lines, fmt.Errorf("响应格式错误: %s", line)
		}

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, lines, fmt.Errorf("无法解析响应码: %s", line)
		}

		if len(line) == 3 || line[3] != '-' {
			return code, lines, nil
		}
	}
}

// parseExtensions 解析 EHLO 响应中的扩展
func (c *Client) parseExtensions(lines []string) {
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		ext := line[4:]
		parts := strings.SplitN(ext, " ", 2)
		name := strings.ToUpper(parts[0])
		value := ""
		if len(parts) > 1 {
			value = parts[1]
		}
		c.extensions[name] = value
	}
}

// HasExtension 检查服务器是否支持某个扩展
func (c *Client) HasExtension(name string) bool {
	_, ok := c.extensions[strings.ToUpper(name)]
	return ok
}

// escapeDotsInMessage 处理邮件内容中行首的点（透明传输）
func (c *Client) escapeDotsInMessage(msg []byte) []byte {
	var result bytes.Buffer
	result.Grow(len(msg) + 100)

	if len(msg) > 0 && msg[0] == '.' {
		result.WriteByte('.')
	}

	for i := 0; i < len(msg); i++ {
		result.WriteByte(msg[i])
		if msg[i] == '\n' && i+1 < len(msg) && msg[i+1] == '.' {
			result.WriteByte('.')
		}
	}

	return result.Bytes()
}
