package smtp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig 连接池配置
type PoolConfig struct {
	Addr           string        // SMTP 服务器地址 (host:port)
	Size           int           // 连接池大小
	Timeout        time.Duration // 连接超时
	UseTLS         bool          // 是否使用 TLS
	SkipVerify     bool          // 是否跳过证书验证
	MaxSendPerConn int           // 每个连接最大发送数（0 表示不限制）
	Auth           *AuthConfig    // SMTP 认证配置（可选）
}

// Pool SMTP 连接池
type Pool struct {
	config PoolConfig

	clients   chan *Client
	mu        sync.Mutex
	closed    int32 // 原子操作
	active    int32 // 当前活跃连接数
	created   int64 // 累计创建连接数
	failed    int64 // 累计创建失败数
	reused    int64 // 累计复用次数
	totalSent int64 // 累计发送邮件数
}

// NewPool 创建 SMTP 连接池
func NewPool(config PoolConfig) (*Pool, error) {
	// 设置默认值
	if config.Size <= 0 {
		config.Size = 10
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxSendPerConn <= 0 {
		config.MaxSendPerConn = 100 // 默认每个连接发送100封后重建
	}

	pool := &Pool{
		config:  config,
		clients: make(chan *Client, config.Size),
	}

	// 预创建一个连接以验证配置是否正确
	client, err := pool.createNew()
	if err != nil {
		return nil, fmt.Errorf("无法连接到 SMTP 服务器 %s: %w", config.Addr, err)
	}
	pool.clients <- client

	return pool, nil
}

// Send 发送邮件（自动管理连接）
func (p *Pool) Send(from, to string, msg []byte) error {
	// 获取连接
	client, err := p.get()
	if err != nil {
		return fmt.Errorf("获取连接失败: %w", err)
	}

	// 发送邮件
	err = client.Send(from, to, msg)

	if err != nil {
		// 发送失败，丢弃连接
		p.discard(client)
		return err
	}

	// 发送成功，归还连接
	p.put(client)
	atomic.AddInt64(&p.totalSent, 1)
	return nil
}

// SendWithRetry 发送邮件（带重试）
func (p *Pool) SendWithRetry(from, to string, msg []byte, maxRetries int) error {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		err := p.Send(from, to, msg)
		if err == nil {
			return nil
		}

		lastErr = err

		// 最后一次尝试失败，不再重试
		if i == maxRetries {
			break
		}

		// 等待一小段时间再重试
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}

	return fmt.Errorf("发送失败（重试%d次）: %w", maxRetries, lastErr)
}

// get 从连接池获取一个连接
// 【修复问题9】添加nil检查，防止连接池关闭时空指针崩溃
func (p *Pool) get() (*Client, error) {
	// 检查是否已关闭
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, fmt.Errorf("连接池已关闭")
	}

	// 尝试从池中获取连接
	select {
	case client := <-p.clients:
		// 通道关闭后会返回nil
		if client == nil {
			return nil, fmt.Errorf("连接池已关闭")
		}
		// 检查连接健康状态和发送次数限制
		if p.shouldReplaceClient(client) {
			client.Close()
			atomic.AddInt32(&p.active, -1)
			return p.createNew()
		}
		atomic.AddInt64(&p.reused, 1)
		return client, nil

	default:
		// 池中没有可用连接
		// 如果活跃连接数小于池大小，创建新连接
		if atomic.LoadInt32(&p.active) < int32(p.config.Size) {
			return p.createNew()
		}

		// 等待池中连接可用
		select {
		case client := <-p.clients:
			// 通道关闭后会返回nil
			if client == nil {
				return nil, fmt.Errorf("连接池已关闭")
			}
			if p.shouldReplaceClient(client) {
				client.Close()
				atomic.AddInt32(&p.active, -1)
				return p.createNew()
			}
			atomic.AddInt64(&p.reused, 1)
			return client, nil

		case <-time.After(p.config.Timeout):
			return nil, fmt.Errorf("获取连接超时")
		}
	}
}

// put 将连接归还到连接池
func (p *Pool) put(client *Client) {
	if client == nil {
		return
	}

	// 检查是否已关闭
	if atomic.LoadInt32(&p.closed) == 1 {
		client.Close()
		atomic.AddInt32(&p.active, -1)
		return
	}

	// 检查是否需要替换
	if p.shouldReplaceClient(client) {
		client.Close()
		atomic.AddInt32(&p.active, -1)
		return
	}

	// 重置连接状态
	if err := client.Reset(); err != nil {
		// 重置失败，关闭连接
		client.Close()
		atomic.AddInt32(&p.active, -1)
		return
	}

	// 尝试放回池中
	select {
	case p.clients <- client:
		// 成功放回
	default:
		// 池已满，关闭连接
		client.Close()
		atomic.AddInt32(&p.active, -1)
	}
}

// discard 丢弃一个连接（发生错误时调用）
func (p *Pool) discard(client *Client) {
	if client == nil {
		return
	}
	client.Close()
	atomic.AddInt32(&p.active, -1)
}

// shouldReplaceClient 判断是否需要替换连接
func (p *Pool) shouldReplaceClient(client *Client) bool {
	// 检查连接是否健康
	if !client.IsHealthy() {
		return true
	}

	// 检查发送次数是否超过限制
	if p.config.MaxSendPerConn > 0 && client.SendCount() >= p.config.MaxSendPerConn {
		return true
	}

	return false
}

// createNew 创建新连接
func (p *Pool) createNew() (*Client, error) {
	client, err := connect(p.config.Addr, p.config.Timeout, p.config.UseTLS, p.config.SkipVerify, p.config.Auth)
	if err != nil {
		atomic.AddInt64(&p.failed, 1)
		return nil, err
	}
	atomic.AddInt32(&p.active, 1)
	atomic.AddInt64(&p.created, 1)
	return client, nil
}

// Close 关闭连接池及所有连接
func (p *Pool) Close() {
	// 标记为已关闭
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return // 已经关闭
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 关闭通道
	close(p.clients)

	// 关闭所有连接
	for client := range p.clients {
		client.Close()
	}

	atomic.StoreInt32(&p.active, 0)
}

// Stats 获取连接池统计信息
func (p *Pool) Stats() PoolStats {
	return PoolStats{
		Active:    int(atomic.LoadInt32(&p.active)),
		Available: len(p.clients),
		Size:      p.config.Size,
		Created:   atomic.LoadInt64(&p.created),
		Failed:    atomic.LoadInt64(&p.failed),
		Reused:    atomic.LoadInt64(&p.reused),
		TotalSent: atomic.LoadInt64(&p.totalSent),
		Closed:    atomic.LoadInt32(&p.closed) == 1,
	}
}

// PoolStats 连接池统计信息
type PoolStats struct {
	Active    int   // 当前活跃连接数
	Available int   // 池中可用连接数
	Size      int   // 池大小
	Created   int64 // 累计创建连接数
	Failed    int64 // 累计创建失败数
	Reused    int64 // 累计复用次数
	TotalSent int64 // 累计发送邮件数
	Closed    bool  // 是否已关闭
}

// IsClosed 检查连接池是否已关闭
func (p *Pool) IsClosed() bool {
	return atomic.LoadInt32(&p.closed) == 1
}

// Size 获取连接池大小
func (p *Pool) Size() int {
	return p.config.Size
}

// ActiveCount 获取当前活跃连接数
func (p *Pool) ActiveCount() int {
	return int(atomic.LoadInt32(&p.active))
}

// TotalSent 获取累计发送数
func (p *Pool) TotalSent() int64 {
	return atomic.LoadInt64(&p.totalSent)
}
