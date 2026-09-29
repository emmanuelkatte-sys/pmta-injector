package injector

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/email"
	"__MODULE_PLACEHOLDER__/smtp"
)

// 注入模式常量
const (
	modeSMTP   = "smtp"
	modePickup = "pickup"
)

// Injector 邮件注入器（支持 SMTP 模式和 Pickup 文件注入模式）
//
// SMTP 模式：通过 SMTP 协议连接本地 MTA（如 127.0.0.1:25），逐封邮件提交。
//   优点：进度反映真实 MTA 接收量；缺点：受 MTA 内部队列压力影响会降速。
//
// Pickup 模式：将邮件作为 .eml 文件写入 PowerMTA 的 pickup 目录，由 PMTA 异步扫描取走。
//   优点：写文件速度极快，不受 MTA 队列压力影响；缺点：进度只反映文件写入数，不代表真实投递。
//
// 模式选择逻辑（在 New 函数中）：
//   - smtp.enabled = true  → SMTP 模式
//   - smtp.enabled = false 且 pmta.pickup_dir 非空 → Pickup 模式
type Injector struct {
	cfg     *config.Config
	mode    string // "smtp" 或 "pickup"
	enabled bool

	// SMTP 模式字段
	pool *smtp.Pool
	addr string

	// Pickup 模式字段
	pickupDir string
	tempDir   string
	fileMode  os.FileMode
	fileSeq   uint64 // 文件序号计数器（原子递增，用于生成唯一文件名）

	// 公共字段
	counter uint64 // 成功注入计数（供外部通过 GetCounter 查询）
}

// New 创建注入器（根据配置自动选择 SMTP 或 Pickup 模式）
func New(cfg *config.Config) (*Injector, error) {
	// 优先判断 SMTP 模式
	if cfg.SMTP.Enabled {
		return newSMTP(cfg)
	}

	// SMTP 未启用时，如果配置了 pickup_dir，使用 Pickup 模式
	if cfg.PMTA.PickupDir != "" {
		return newPickup(cfg)
	}

	// 两种模式都不满足，返回 disabled 的注入器
	return &Injector{cfg: cfg, enabled: false}, nil
}

// newSMTP 创建 SMTP 模式注入器（原有逻辑，完全不变）
func newSMTP(cfg *config.Config) (*Injector, error) {
	addr := fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port)

	poolSize := cfg.SMTP.MaxConn
	if poolSize <= 0 {
		poolSize = cfg.Performance.Workers
		if poolSize > 100 {
			poolSize = 100
		}
		if poolSize < 10 {
			poolSize = 10
		}
	}

	authCfg := smtpAuthConfig(cfg)

	poolConfig := smtp.PoolConfig{
		Addr:           addr,
		Size:           poolSize,
		Timeout:        time.Duration(cfg.SMTP.Timeout) * time.Second,
		UseTLS:         cfg.SMTP.UseTLS,
		SkipVerify:     cfg.SMTP.SkipVerify,
		MaxSendPerConn: 100,
		Auth:           authCfg,
	}

	pool, err := smtp.NewPool(poolConfig)
	if err != nil {
		return nil, fmt.Errorf("创建 SMTP 连接池失败: %w", err)
	}

	return &Injector{
		cfg:     cfg,
		mode:    modeSMTP,
		enabled: true,
		pool:    pool,
		addr:    addr,
	}, nil
}

// smtpAuthConfig：Haraka 强制 AUTH；帐号密码始终带上，握手若认出 Haraka 也会 AUTH。
func smtpAuthConfig(cfg *config.Config) *smtp.AuthConfig {
	user := cfg.SMTPAuthUser()
	if user == "" {
		return nil
	}
	return &smtp.AuthConfig{
		UseAuth:  cfg.SMTPNeedAuth(),
		Username: user,
		Password: cfg.SMTP.Password,
	}
}

// newPickup 创建 Pickup 模式注入器
func newPickup(cfg *config.Config) (*Injector, error) {
	pickupDir := cfg.PMTA.PickupDir
	tempDir := cfg.PMTA.TempDir
	if tempDir == "" {
		tempDir = pickupDir // 如果没配 temp_dir，回退到 pickup_dir
	}

	fileMode := os.FileMode(cfg.PMTA.FileMode)
	if fileMode == 0 {
		fileMode = 0644 // 默认权限
	}

	// 验证目录存在且可写
	if err := ensureDirWritable(pickupDir); err != nil {
		return nil, fmt.Errorf("Pickup 目录不可用 [%s]: %w", pickupDir, err)
	}
	if tempDir != pickupDir {
		if err := ensureDirWritable(tempDir); err != nil {
			return nil, fmt.Errorf("Temp 目录不可用 [%s]: %w", tempDir, err)
		}
	}

	return &Injector{
		cfg:       cfg,
		mode:      modePickup,
		enabled:   true,
		pickupDir: pickupDir,
		tempDir:   tempDir,
		fileMode:  fileMode,
	}, nil
}

// ensureDirWritable 检查目录存在且可写
func ensureDirWritable(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("目录不存在: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是目录")
	}
	// 尝试创建临时文件来验证可写性
	testFile := filepath.Join(dir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("目录不可写: %w", err)
	}
	f.Close()
	os.Remove(testFile)
	return nil
}

// Inject 注入单封邮件（根据模式自动选择 SMTP 或 Pickup）
func (i *Injector) Inject(eml *email.Email) error {
	if !i.enabled {
		return fmt.Errorf("注入器未启用（smtp.enabled=false 且 pmta.pickup_dir 未配置）")
	}

	var err error
	switch i.mode {
	case modePickup:
		err = i.injectPickup(eml)
	case modeSMTP:
		err = i.injectSMTP(eml)
	default:
		err = fmt.Errorf("未知的注入模式: %s", i.mode)
	}

	if err != nil {
		return err
	}

	atomic.AddUint64(&i.counter, 1)
	return nil
}

// injectSMTP 通过 SMTP 注入（原有逻辑，完全不变）
func (i *Injector) injectSMTP(eml *email.Email) error {
	if i.pool == nil {
		return fmt.Errorf("SMTP 连接池未初始化")
	}
	err := i.pool.SendWithRetry(eml.EnvelopeFrom, eml.EnvelopeTo, []byte(eml.Raw), 2)
	if err != nil {
		return fmt.Errorf("SMTP 发送失败 [%s]: %w", eml.EnvelopeTo, err)
	}
	return nil
}

// injectPickup 通过 Pickup 文件注入
//
// 流程：
//  1. 生成唯一文件名（纳秒时间戳 + 原子递增序号，确保跨 worker 绝不重复）
//  2. 先写入 temp 目录（防止 PowerMTA 读到写了一半的文件）
//  3. 原子 rename 到 pickup 目录（同一文件系统上 rename 是原子操作）
//  4. PowerMTA 的 pickup scanner 检测到新文件后自动取走处理
func (i *Injector) injectPickup(eml *email.Email) error {
	// 生成唯一文件名：纳秒时间戳 + 原子递增序号
	seq := atomic.AddUint64(&i.fileSeq, 1)
	filename := fmt.Sprintf("msg_%d_%08d.eml", time.Now().UnixNano(), seq)

	tempPath := filepath.Join(i.tempDir, filename)
	finalPath := filepath.Join(i.pickupDir, filename)

	// 写入 temp 目录
	if err := os.WriteFile(tempPath, []byte(eml.Raw), i.fileMode); err != nil {
		return fmt.Errorf("写入 temp 文件失败 [%s]: %w", tempPath, err)
	}

	// 原子移动到 pickup 目录（同一文件系统上 os.Rename 是原子操作）
	if err := os.Rename(tempPath, finalPath); err != nil {
		// rename 失败时清理 temp 文件，避免残留
		os.Remove(tempPath)
		return fmt.Errorf("移动到 pickup 目录失败 [%s → %s]: %w", tempPath, finalPath, err)
	}

	return nil
}

// InjectBatch 批量注入
func (i *Injector) InjectBatch(emails []*email.Email) (int, error) {
	success := 0
	var lastErr error
	for _, eml := range emails {
		if err := i.Inject(eml); err != nil {
			lastErr = err
			continue
		}
		success++
	}
	if lastErr != nil && success < len(emails) {
		return success, fmt.Errorf("部分邮件发送失败 (%d/%d): %w", success, len(emails), lastErr)
	}
	return success, nil
}

func (i *Injector) GetCounter() uint64  { return atomic.LoadUint64(&i.counter) }
func (i *Injector) GetSMTPAddr() string { return i.addr }
func (i *Injector) IsEnabled() bool     { return i.enabled }
func (i *Injector) GetMode() string     { return i.mode }

func (i *Injector) GetStats() *smtp.PoolStats {
	if i.pool == nil {
		return nil
	}
	stats := i.pool.Stats()
	return &stats
}

func (i *Injector) Close() {
	if i.pool != nil {
		i.pool.Close()
	}
}
