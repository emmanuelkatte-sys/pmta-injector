// Package core 实现高并发邮件发送的任务调度核心。
//
// Dispatcher 从 reader 读取收件人，按 worker 池并行调用 email.Builder 构建邮件，
// 再通过 injector 注入到 SMTP 或 PowerMTA Pickup 目录。支持速率限制、
// CC/BCC 独立邮件、进度上报和优雅停止（信号 / STOP 文件）。
package core

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/email"
	"__MODULE_PLACEHOLDER__/injector"
	"__MODULE_PLACEHOLDER__/reader"
	"__MODULE_PLACEHOLDER__/reporter"
	"__MODULE_PLACEHOLDER__/types"
)

// ProgressReporter 进度报告接口
type ProgressReporter interface {
	UpdateProgress(progress *types.Progress) error
}

// Dispatcher 任务调度器
type Dispatcher struct {
	cfg      *config.Config
	reporter ProgressReporter

	// 统计计数
	total      int64
	processed  int64
	success    int64
	failed     int64
	startTime  time.Time
	lastReport time.Time

	// 错误收集
	errors     []types.ErrorInfo
	errorsLock sync.Mutex

	// 速率限制
	rateLimiter *RateLimiter

	// 【2026-05-26 CC/BCC】抄送/密送独立邮件配置
	// 池在 Run 启动时一次性加载,worker 通过原子索引 ccIdx/bccIdx 消费,消费完即停
	ccEnabled    bool
	ccPool       []string
	ccIdx        int64 // atomic 索引(下次该取的起始下标)
	ccPerEmail   int
	bccEnabled   bool
	bccPool      []string
	bccIdx       int64
	bccPerEmail  int
	fileLogger   *reporter.FileLogger
}

// NewDispatcher 创建调度器
func NewDispatcher(cfg *config.Config, rep ProgressReporter) *Dispatcher {
	d := &Dispatcher{
		cfg:      cfg,
		reporter: rep,
		errors:   make([]types.ErrorInfo, 0),
	}

	if cfg.Performance.RateLimit > 0 {
		d.rateLimiter = NewRateLimiter(cfg.Performance.RateLimit)
	}

	return d
}

// Run 运行调度器
func (d *Dispatcher) Run(ctx context.Context) (*types.Result, error) {
	d.startTime = time.Now()
	d.lastReport = d.startTime

	fileLog, err := reporter.NewFileLogger(d.cfg)
	if err != nil {
		return nil, err
	}
	d.fileLogger = fileLog
	if d.fileLogger != nil {
		defer d.fileLogger.Close()
	}

	// 创建注入器
	inj, err := injector.New(d.cfg)
	if err != nil {
		return nil, fmt.Errorf("创建注入器失败: %w", err)
	}
	defer inj.Close()

	// 创建收件人读取器
	rdr, err := reader.New(d.cfg.Recipients.FilePath, d.cfg)
	if err != nil {
		return nil, fmt.Errorf("创建收件人读取器失败: %w", err)
	}
	defer rdr.Close()

	// 获取总数
	d.total, _ = rdr.Count()

	// 【2026-05-26 CC/BCC】加载抄送/密送池(若启用)
	// 池一次性全量加载到内存(各服务器子池已由 C# 切好,通常 ≤ 100 万条 = ~150MB)
	// worker 通过 atomic.AddInt64 原子分配索引,消费完即停
	d.ccEnabled = d.cfg.CC.Enabled && d.cfg.CC.FilePath != ""
	if d.ccEnabled {
		ccPool, ccErr := reader.ReadEmailList(d.cfg.CC.FilePath)
		if ccErr != nil {
			return nil, fmt.Errorf("加载抄送列表失败: %w", ccErr)
		}
		d.ccPool = ccPool
		d.ccPerEmail = d.cfg.CC.PerEmail
		// 【v8.1.4 #26 防御】clamp 到 [1, 100],跟 C# UI NumericUpDown 上限一致
		// 防止用户手改 config.yaml 设巨大值导致单 Cc 头超 RFC 998 硬上限
		if d.ccPerEmail < 1 {
			d.ccPerEmail = 1
		}
		if d.ccPerEmail > 100 {
			d.ccPerEmail = 100
		}
		fmt.Printf("[CC] 已加载抄送池: %d 条,每封 %d 个,消费完即停\n", len(d.ccPool), d.ccPerEmail)
	}
	d.bccEnabled = d.cfg.BCC.Enabled && d.cfg.BCC.FilePath != ""
	if d.bccEnabled {
		bccPool, bccErr := reader.ReadEmailList(d.cfg.BCC.FilePath)
		if bccErr != nil {
			return nil, fmt.Errorf("加载密送列表失败: %w", bccErr)
		}
		d.bccPool = bccPool
		d.bccPerEmail = d.cfg.BCC.PerEmail
		// 【v8.1.4 #26 防御】clamp 到 [1, 100]
		if d.bccPerEmail < 1 {
			d.bccPerEmail = 1
		}
		if d.bccPerEmail > 100 {
			d.bccPerEmail = 100
		}
		fmt.Printf("[BCC] 已加载密送池: %d 条,每封 %d 个,独立邮件\n", len(d.bccPool), d.bccPerEmail)
	}

	// 【CC/BCC v8.1 简化】修正 total: 主邮件数 + 实际会触发的 CC 独立邮件数 + BCC 独立邮件数
	//
	// 实际触发数(消费完即停语义):
	//   maxSecondary = min(池大小, 主邮件数 * perEmail)
	//
	// 注: 收件人禁用 + 只发 CC/BCC 场景由 C# 端在 ExecuteServerSideSendingAsync 阶段把 CC/BCC 池
	//   合并为 recipients,且 cc/bcc.enabled 都置 false。所以 Go 端不再需要"收件人禁用特殊处理"。
	//   此时 d.ccEnabled 和 d.bccEnabled 都是 false,本函数不会执行 maxCC/maxBCC 计算。
	//
	// total 仅用于 UI 进度百分比显示,真实统计走 d.processed/success/failed atomic 计数器
	mainTriggerCount := d.total
	if d.ccEnabled {
		maxCC := mainTriggerCount * int64(d.ccPerEmail)
		if maxCC > int64(len(d.ccPool)) {
			maxCC = int64(len(d.ccPool))
		}
		d.total += maxCC
	}
	if d.bccEnabled {
		maxBCC := mainTriggerCount * int64(d.bccPerEmail)
		if maxBCC > int64(len(d.bccPool)) {
			maxBCC = int64(len(d.bccPool))
		}
		d.total += maxBCC
	}
	d.total += d.cfg.ExpectedBacktestCount(mainTriggerCount)

	// 创建工作通道
	recipientCh := make(chan *reader.Recipient, d.cfg.Performance.ChannelBuffer)
	resultCh := make(chan *WorkResult, d.cfg.Performance.ChannelBuffer)
	doneCh := make(chan struct{})

	// 启动结果收集器
	go d.collectResults(ctx, resultCh, doneCh)

	// 启动进度报告器
	go d.reportProgress(ctx)

	// 【修复问题1】每个 worker 创建独立的 Builder（包含独立的 VariableProcessor 和 HeaderGenerator）
	// 这样每个 worker 拥有自己的随机数生成器、计数器等，完全避免并发竞争
	var wg sync.WaitGroup
	for i := 0; i < d.cfg.Performance.Workers; i++ {
		wg.Add(1)

		// 每个 worker 独立创建模板引擎和构建器
		tmplEngine, tmplErr := email.NewTemplateEngine(d.cfg.Email.TemplatePath)
		if tmplErr != nil {
			// 如果模板加载失败，减少 WaitGroup 并跳过此 worker
			wg.Done()
			return nil, fmt.Errorf("加载模板失败(worker %d): %w", i, tmplErr)
		}
		tmplEngine.SetGlobalVariables(d.cfg.Template.GlobalVariables)

		// 【v62修复】传入 workerID，确保每个 worker 的随机数种子唯一
		builder := email.NewBuilder(d.cfg, tmplEngine, i)

		go d.worker(ctx, i, recipientCh, resultCh, builder, inj, &wg)
	}

	// 【v63修复】worker 存活监控：当所有 worker 退出后（正常完成或全部崩溃），及时通知主线程
	// 防止所有 worker 崩溃后，主线程因往已满的 recipientCh 写入而永久阻塞（死锁）
	// Go 允许多个 goroutine 同时调用 wg.Wait()，所以这里和下方 line 160 的 wg.Wait() 不冲突
	workersDoneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDoneCh)
	}()

	// 【修复问题10】读取收件人并分发：出错时记录日志并跳过，而非静默中断
	lineNum := 0
	skipLines := d.cfg.Recipients.SkipLines
	mainQueued := int64(0)

readLoop:
	for {
		select {
		case <-ctx.Done():
			break readLoop
		default:
			recipient, err := rdr.Read()
			if err != nil {
				// 记录读取错误，但继续读取下一行
				d.errorsLock.Lock()
				if len(d.errors) < 1000 {
					d.errors = append(d.errors, types.ErrorInfo{
						Email: "",
						Error: fmt.Sprintf("读取收件人失败(行 %d): %v", lineNum+1, err),
						Line:  lineNum + 1,
					})
				}
				d.errorsLock.Unlock()
				atomic.AddInt64(&d.failed, 1)
				atomic.AddInt64(&d.processed, 1)
				continue // 跳过这一行，继续读取下一行
			}
			if recipient == nil {
				// 文件读取完毕
				break readLoop
			}

			lineNum++
			if lineNum <= skipLines {
				continue
			}

			recipient.LineNumber = lineNum

			select {
			case recipientCh <- recipient:
				mainQueued++
				if !d.enqueueBacktest(ctx, recipientCh, workersDoneCh, mainQueued) {
					break readLoop
				}
			case <-ctx.Done():
				break readLoop
			case <-workersDoneCh:
				// 【v63修复】所有 worker 已退出（可能全部崩溃），立即停止分发，避免死锁
				break readLoop
			}
		}
	}

	// 关闭收件人通道，等待工作完成
	close(recipientCh)
	wg.Wait()

	// 关闭结果通道，等待收集完成
	close(resultCh)
	<-doneCh

	// 构建结果
	result := d.buildResult(ctx)
	return result, nil
}

func (d *Dispatcher) enqueueBacktest(ctx context.Context, recipientCh chan<- *reader.Recipient, workersDoneCh <-chan struct{}, mainQueued int64) bool {
	if !d.cfg.BacktestActive() || mainQueued%int64(d.cfg.Backtest.Frequency) != 0 {
		return true
	}
	probe := &reader.Recipient{
		Email:      strings.TrimSpace(d.cfg.Backtest.Email),
		IsBacktest: true,
	}
	select {
	case recipientCh <- probe:
		return true
	case <-ctx.Done():
		return false
	case <-workersDoneCh:
		return false
	}
}

// WorkResult 工作结果
type WorkResult struct {
	Email   string
	Success bool
	Error   error
	Line    int
}

// worker 工作协程
// 【v64修复】recover 从 worker 级别改为 per-recipient 级别
// 之前：worker 遇到一次 panic 就整个退出，100个worker全死 → 只处理~1000封
// 现在：每封邮件单独 recover，即使 panic 也只跳过该封，worker 继续处理下一封
func (d *Dispatcher) worker(ctx context.Context, id int, recipientCh <-chan *reader.Recipient,
	resultCh chan<- *WorkResult, builder *email.Builder, inj *injector.Injector, wg *sync.WaitGroup) {
	defer wg.Done()
	intervalRNG := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)*9973))
	// 保留 worker 级别 recover 作为最后防线（理论上不应再触发）
	defer func() {
		if r := recover(); r != nil {
			d.errorsLock.Lock()
			if len(d.errors) < 1000 {
				d.errors = append(d.errors, types.ErrorInfo{
					Email: "",
					Error: fmt.Sprintf("worker %d 发生意外崩溃(外层): %v", id, r),
					Line:  0,
				})
			}
			d.errorsLock.Unlock()
			atomic.AddInt64(&d.failed, 1)
			atomic.AddInt64(&d.processed, 1)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case recipient, ok := <-recipientCh:
			if !ok {
				return
			}

			// 速率限制
			if d.rateLimiter != nil {
				d.rateLimiter.Wait(ctx)
			}

			// 【v64修复】每封邮件单独 recover，panic 不会杀死 worker
			result := d.safeProcessRecipient(ctx, id, recipient, builder, inj)

			select {
			case resultCh <- result:
			case <-ctx.Done():
				return
			}

			if delay := performanceSendDelay(d.cfg, intervalRNG); delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}
	}
}

// safeProcessRecipient 安全地处理单个收件人（per-recipient recover）
// 【v64修复】如果 processRecipient 内部发生 panic（如数组越界、nil指针等），
// 本方法会捕获 panic 并返回错误结果，worker 不受影响继续处理下一封
func (d *Dispatcher) safeProcessRecipient(ctx context.Context, workerID int,
	recipient *reader.Recipient, builder *email.Builder, inj *injector.Injector) (result *WorkResult) {

	defer func() {
		if r := recover(); r != nil {
			// 捕获 processRecipient 内部的 panic，返回错误结果
			result = &WorkResult{
				Email:   recipient.Email,
				Success: false,
				Error:   fmt.Errorf("worker %d 处理邮件时崩溃: %v", workerID, r),
				Line:    recipient.LineNumber,
			}
		}
	}()

	return d.processRecipient(ctx, recipient, builder, inj)
}

// processRecipient 处理单个收件人(主邮件 + 触发 CC/BCC 独立邮件循环)
//
// 【2026-05-26 CC/BCC】完整流程:
//  1. 原子分配 CC 子批次(从全局 ccPool 取 ccPerEmail 个,池消费完则空切片)
//  2. 同上 BCC 子批次
//  3. 主邮件: Build 时把 CC 子批次塞进 Cc 头(BCC 不进 raw),然后 inj.Inject
//     - 收件人禁用且 Email 为空 → 跳过主邮件投递(防御性兜底,C# 端 v8.1 后正常不会传空 Email)
//     - 主邮件失败不再跳过 CC/BCC 独立邮件(每封独立 Build,失败原因可能与独立邮件无关)
//  4. CC 独立邮件循环: 每个 CC 地址单独 Build(data.Email = cc) + Inject,独立 Message-ID
//  5. BCC 独立邮件循环: 同上
//  6. 每封独立邮件独立 wait 速率限制 token,独立计 success/fail/processed
//
// 设计关键点:
//   - CC 子批次同时用于"主邮件 Cc 头" 和 "CC 独立邮件循环",保证语义一致
//   - 主邮件和独立邮件共享同一个 Builder,但每次 Build 都生成全新 Message-ID/boundary/时间戳
//     → 同一发件 worker 看到主邮件和独立邮件像"同一发件人发出去的多封不同邮件"(反指纹安全)
//   - 速率限制按邮件粒度,1 + N + M 封各自单独 wait
//   - 【v8.1 修复】主邮件失败不再跳过 CC/BCC: ccBatch/bccBatch 已经被 atomic 原子分配走,
//     无法归还。若跳过 CC/BCC,这批配额就被白白浪费(消费完即停语义下永远发不出去)。
//     每封 Build 是独立的,失败原因(临时 SMTP/网络)未必影响其他邮件,各自尝试更稳健。
func (d *Dispatcher) processRecipient(ctx context.Context, recipient *reader.Recipient,
	builder *email.Builder, inj *injector.Injector) *WorkResult {

	result := &WorkResult{
		Email: recipient.Email,
		Line:  recipient.LineNumber,
	}

	// 【CC/BCC】Step 1+2: 原子分配本封的 CC 和 BCC 子批次
	// atomic.AddInt64 是无锁原子操作,即使 100 worker 同时分配也不会重复
	var ccBatch []string
	var bccBatch []string
	if !recipient.IsBacktest {
		ccBatch = d.takeCCBatch()
		bccBatch = d.takeBCCBatch()
	}

	// 【CC/BCC】Step 3: 主邮件
	// 防御性兜底: 收件人禁用 + Email 为空 → 跳过主邮件
	// (v8.1 起 C# 端不再合成空 Email,但保留此分支防御未来回归 Bug)
	skipMain := !d.cfg.Recipient.Enabled || recipient.Email == ""
	if !skipMain {
		mainResult := d.buildAndInjectOne(ctx, recipient, recipient.Email, builder, inj, ccBatch, false)
		if mainResult != nil {
			result.Success = mainResult.Success
			result.Error = mainResult.Error
			// 【v8.1 关键修复】不再因主邮件失败而 return,继续执行 CC/BCC 独立邮件循环
			// 原因: ccBatch/bccBatch 已被 atomic 分配走,跳过会让配额永久丢失
		}
	} else {
		// 主邮件跳过场景: 也要更新 result 状态(避免外层把空 Email 当失败)
		result.Success = true
	}

	// 【CC/BCC】Step 4: CC 独立邮件循环
	// 每个 CC 地址都单独生成一封独立 raw 邮件(独立 Message-ID/boundary/零宽位置/时间戳)
	// 这封独立邮件的 To 头是 CC 地址本身(不含 Cc 头,反指纹安全:收件方看不到主收件人)
	//
	// 取消语义说明: ctx 取消后,正在 inject 的那一封会照常完成(SMTP 单封 timeout 上限 30s,
	// 由 smtp.Pool 内部 net.Dialer 超时控制,无法中途打断),下一次迭代会被 select 拦下立即返回。
	// 即"取消后最多等一次单封 SMTP 超时",不存在"PerEmail × 30s"叠加。
	for _, ccAddr := range ccBatch {
		// 速率限制按邮件粒度,每封独立邮件单独 wait(Wait 无返回值,内部处理 ctx 取消)
		if d.rateLimiter != nil {
			d.rateLimiter.Wait(ctx)
		}
		// ctx 取消检查: 提前退出循环
		select {
		case <-ctx.Done():
			return result
		default:
		}
		secResult := d.buildAndInjectOne(ctx, recipient, ccAddr, builder, inj, nil, true)
		// 每封独立邮件单独计入 processed/success/failed
		atomic.AddInt64(&d.processed, 1)
		if secResult.Success {
			atomic.AddInt64(&d.success, 1)
		} else {
			atomic.AddInt64(&d.failed, 1)
			d.errorsLock.Lock()
			if len(d.errors) < 1000 && secResult.Error != nil {
				// 【v8.1 P1】错误信息含主收件人上下文,便于追溯"这封 CC 是哪封主邮件触发的"
				d.errors = append(d.errors, types.ErrorInfo{
					Email: ccAddr,
					Error: fmt.Sprintf("[CC独立邮件 主收件人=%s] %v", recipient.Email, secResult.Error),
					Line:  recipient.LineNumber,
				})
			}
			d.errorsLock.Unlock()
		}
	}

	// 【CC/BCC】Step 5: BCC 独立邮件循环
	// 与 CC 独立邮件路径一致,区别仅在: 不带 Cc 头(BCC 永远不出现在 raw),收件人完全独立
	for _, bccAddr := range bccBatch {
		if d.rateLimiter != nil {
			d.rateLimiter.Wait(ctx)
		}
		select {
		case <-ctx.Done():
			return result
		default:
		}
		secResult := d.buildAndInjectOne(ctx, recipient, bccAddr, builder, inj, nil, true)
		atomic.AddInt64(&d.processed, 1)
		if secResult.Success {
			atomic.AddInt64(&d.success, 1)
		} else {
			atomic.AddInt64(&d.failed, 1)
			d.errorsLock.Lock()
			if len(d.errors) < 1000 && secResult.Error != nil {
				// 【v8.1 P1】错误信息含主收件人上下文
				d.errors = append(d.errors, types.ErrorInfo{
					Email: bccAddr,
					Error: fmt.Sprintf("[BCC独立邮件 主收件人=%s] %v", recipient.Email, secResult.Error),
					Line:  recipient.LineNumber,
				})
			}
			d.errorsLock.Unlock()
		}
	}

	// 注: result 反映"主邮件"或"占位"的状态,通过 resultCh 发给 collectResults
	//   - skipMain=true: result.Success=true(占位标记,外层 collectResults 加 1 success/processed
	//     代表这条 CSV 行已扫过,实际上没投递主邮件;d.total 已包含该 1)
	//   - skipMain=false: result.Success 反映真实主邮件投递状态(成功/失败/重试结果)
	//   - CC/BCC 独立邮件的统计已在循环内 atomic 加好,不通过 result 传出
	return result
}

// buildAndInjectOne 构建单封邮件并注入(主邮件 或 CC/BCC 独立邮件)
//
// 入参:
//   - recipient: 原始收件人(用于变量上下文,如 {firstname}/{lastname}/自定义字段)
//   - targetEmail: 这封邮件的实际收件人(主邮件=recipient.Email; CC/BCC 独立邮件=cc/bcc 地址)
//   - ccHeaderList: 主邮件传 CC 列表(用于 Cc 头);CC/BCC 独立邮件传 nil
//
// 返回: WorkResult(Success/Error/Email/Line)
// 【2026-05-27 β 决策 - Haraka 独有】isSecondary 参数明确区分主邮件 vs CC/BCC 独立邮件:
//   - 主邮件: isSecondary=false; ccHeaderList 可为 nil(CC 禁用)或非空(CC 启用)
//   - CC/BCC 独立邮件: isSecondary=true; ccHeaderList=nil
// 区分目的: SkipTelegram 头只加到独立邮件,主邮件即使 CC 禁用也不能跳过 Telegram 推送
func (d *Dispatcher) buildAndInjectOne(ctx context.Context, recipient *reader.Recipient,
	targetEmail string, builder *email.Builder, inj *injector.Injector,
	ccHeaderList []string, isSecondary bool) *WorkResult {

	result := &WorkResult{
		Email: targetEmail,
		Line:  recipient.LineNumber,
	}

	// 构建模板数据
	// 关键: targetEmail 不一定等于 recipient.Email
	//   - 主邮件: targetEmail == recipient.Email,变量上下文用收件人原始字段
	//   - CC/BCC 独立邮件: targetEmail == cc/bcc 地址,但变量上下文仍用主收件人字段(避免破坏 CSV 自定义变量语义)
	// 但 tmplData.Email 必须是 targetEmail(让 builder 用它生成 EnvelopeTo / To 头 / Message-ID 域名等)
	tmplData := email.NewTemplateData()
	tmplData.Email = targetEmail
	tmplData.Name = recipient.Name
	tmplData.FirstName = recipient.FirstName
	tmplData.LastName = recipient.LastName
	tmplData.Data = recipient.CustomFields
	tmplData.System.Index = recipient.LineNumber
	tmplData.System.JobID = d.cfg.Job.ID

	// 生成邮件(主邮件传 ccHeaderList,独立邮件传 nil 触发零值 BuildOptions{})
	// 【2026-05-27 β 决策 - Haraka 独有】明确按 isSecondary 区分:
	//   - 主邮件 (isSecondary=false): 不加 SkipTelegram 头,正常进 Telegram 推送
	//   - CC/BCC 独立邮件 (isSecondary=true): 加 SkipTelegram 头,log_delivered.js 跳过 Telegram
	// 即使主邮件 CC 禁用 (ccHeaderList=nil) 也不能跳过 Telegram
	opts := email.BuildOptions{
		SkipTelegram: isSecondary,
		IsBacktest:   recipient.IsBacktest,
	}
	if !isSecondary && len(ccHeaderList) > 0 {
		opts.CcHeaderList = ccHeaderList
	}
	eml, err := builder.Build(tmplData, opts)
	if err != nil {
		result.Error = fmt.Errorf("生成邮件失败: %w", err)
		return result
	}

	// 注入
	if !d.cfg.DryRun {
		if err := inj.Inject(eml); err != nil {
			result.Error = fmt.Errorf("注入失败: %w", err)
			return result
		}
	}

	result.Success = true
	return result
}

// takeCCBatch 原子分配本封邮件的 CC 子批次
// 返回从全局 ccPool 中取的 PerEmail 个地址(池消费完返回 nil/空切片)
func (d *Dispatcher) takeCCBatch() []string {
	if !d.ccEnabled || len(d.ccPool) == 0 || d.ccPerEmail == 0 {
		return nil
	}
	// 原子分配 [start, start+PerEmail) 的索引区间
	// 即使 100 worker 同时调用也不会重复(atomic 保证)
	end := atomic.AddInt64(&d.ccIdx, int64(d.ccPerEmail))
	start := end - int64(d.ccPerEmail)
	poolLen := int64(len(d.ccPool))
	if start >= poolLen {
		return nil // 池已消费完
	}
	if end > poolLen {
		end = poolLen
	}
	return d.ccPool[start:end]
}

// takeBCCBatch 同 takeCCBatch
func (d *Dispatcher) takeBCCBatch() []string {
	if !d.bccEnabled || len(d.bccPool) == 0 || d.bccPerEmail == 0 {
		return nil
	}
	end := atomic.AddInt64(&d.bccIdx, int64(d.bccPerEmail))
	start := end - int64(d.bccPerEmail)
	poolLen := int64(len(d.bccPool))
	if start >= poolLen {
		return nil
	}
	if end > poolLen {
		end = poolLen
	}
	return d.bccPool[start:end]
}

// collectResults 收集结果
func (d *Dispatcher) collectResults(ctx context.Context, resultCh <-chan *WorkResult, doneCh chan<- struct{}) {
	defer close(doneCh)

	for {
		select {
		case result, ok := <-resultCh:
			if !ok {
				return
			}

			atomic.AddInt64(&d.processed, 1)

			if result.Success {
				atomic.AddInt64(&d.success, 1)
			} else {
				atomic.AddInt64(&d.failed, 1)

				// 记录错误
				// 【最终自检 D3.14 防御】result.Error 可能为 nil(理论上当前所有失败路径都设了 Error,
				//   但未来若有人加新分支提前 return 但忘了设 Error, .Error() 会 nil panic 杀掉整个 collectResults goroutine)
				errStr := "未知错误(result.Error 为 nil)"
				if result.Error != nil {
					errStr = result.Error.Error()
				}
				d.errorsLock.Lock()
				if len(d.errors) < 1000 { // 最多记录1000个错误
					d.errors = append(d.errors, types.ErrorInfo{
						Email: result.Email,
						Error: errStr,
						Line:  result.Line,
					})
				}
				d.errorsLock.Unlock()
			}
			if d.fileLogger != nil {
				d.fileLogger.Record(result.Email, result.Line, result.Success, result.Error)
			}

		case <-ctx.Done():
			// 继续处理完剩余的结果
			for result := range resultCh {
				atomic.AddInt64(&d.processed, 1)
				if result.Success {
					atomic.AddInt64(&d.success, 1)
				} else {
					atomic.AddInt64(&d.failed, 1)
				}
				if d.fileLogger != nil {
					d.fileLogger.Record(result.Email, result.Line, result.Success, result.Error)
				}
			}
			return
		}
	}
}

// reportProgress 进度报告
func (d *Dispatcher) reportProgress(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(d.cfg.Performance.ProgressInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.updateProgress()
		}
	}
}

// updateProgress 更新进度
func (d *Dispatcher) updateProgress() {
	processed := atomic.LoadInt64(&d.processed)
	success := atomic.LoadInt64(&d.success)
	failed := atomic.LoadInt64(&d.failed)
	elapsed := time.Since(d.startTime).Seconds()

	var rate float64
	if elapsed > 0 {
		rate = float64(processed) / elapsed
	}

	var eta int64
	if rate > 0 && d.total > processed {
		eta = int64(float64(d.total-processed) / rate)
	}

	progress := &types.Progress{
		JobID:      d.cfg.Job.ID,
		Status:     "running",
		Total:      d.total,
		Processed:  processed,
		Success:    success,
		Failed:     failed,
		Rate:       rate,
		ETASeconds: eta,
		StartTime:  d.startTime,
		UpdateTime: time.Now(),
	}

	if d.reporter != nil {
		d.reporter.UpdateProgress(progress)
	}

	// 打印进度（防止除零）
	var percentage float64
	if d.total > 0 {
		percentage = float64(processed) / float64(d.total) * 100
	}
	fmt.Printf("\r[进度] %d/%d (%.1f%%) | 成功: %d | 失败: %d | 速率: %.0f/秒 | 剩余: %ds",
		processed, d.total, percentage,
		success, failed, rate, eta)
}

// buildResult 构建结果
func (d *Dispatcher) buildResult(ctx context.Context) *types.Result {
	endTime := time.Now()
	duration := endTime.Sub(d.startTime)

	processed := atomic.LoadInt64(&d.processed)
	success := atomic.LoadInt64(&d.success)
	failed := atomic.LoadInt64(&d.failed)

	var avgRate float64
	if duration.Seconds() > 0 {
		avgRate = float64(processed) / duration.Seconds()
	}

	status := "completed"
	if ctx.Err() != nil {
		status = "cancelled"
	}

	return &types.Result{
		JobID:       d.cfg.Job.ID,
		Status:      status,
		Total:       processed,
		Success:     success,
		Failed:      failed,
		StartTime:   d.startTime,
		EndTime:     endTime,
		Duration:    duration,
		AverageRate: avgRate,
		Errors:      d.errors,
	}
}
