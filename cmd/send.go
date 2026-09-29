package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/core"
	"__MODULE_PLACEHOLDER__/reporter"
	"__MODULE_PLACEHOLDER__/types"

	"github.com/spf13/cobra"
)

var (
	// 发送命令参数
	recipientsFile string
	templateFile   string
	subject        string
	fromAddress    string
	fromName       string
	envelopeFrom   string
	vmta           string
	jobID          string
	workers        int
	rateLimit      int
	pickupDir      string
	tempDir        string
	progressFile   string
	resultFile     string
	dryRun         bool
	resume         bool
	skipLines      int
)

// sendCmd 发送命令
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "发送邮件",
	Long: `发送邮件到 PowerMTA Pickup 目录。

示例：
  # 使用配置文件
  pmta-injector send --config /etc/pmta-injector/config.yaml

  # 命令行指定参数
  pmta-injector send \
    --recipients /data/list.csv \
    --template /data/template.html \
    --subject "Welcome" \
    --from "noreply@example.com" \
    --from-name "Example Company"

  # 高性能模式
  pmta-injector send --config config.yaml --workers 200 --rate-limit 50000

  # 测试模式（不实际写入）
  pmta-injector send --config config.yaml --dry-run`,
	RunE: runSend,
}

func init() {
	// 发送命令参数
	sendCmd.Flags().StringVarP(&recipientsFile, "recipients", "r", "", "收件人文件路径 (CSV/JSON)")
	sendCmd.Flags().StringVarP(&templateFile, "template", "t", "", "邮件模板文件路径")
	sendCmd.Flags().StringVarP(&subject, "subject", "s", "", "邮件主题")
	sendCmd.Flags().StringVarP(&fromAddress, "from", "f", "", "发件人地址")
	sendCmd.Flags().StringVar(&fromName, "from-name", "", "发件人显示名")
	sendCmd.Flags().StringVar(&envelopeFrom, "envelope-from", "", "信封发件人（用于退信）")
	sendCmd.Flags().StringVar(&vmta, "vmta", "", "虚拟MTA名称")
	sendCmd.Flags().StringVar(&jobID, "job-id", "", "任务ID（留空自动生成）")
	sendCmd.Flags().IntVarP(&workers, "workers", "w", 0, "并发工作协程数")
	sendCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "每秒最大发送数（0=不限制）")
	sendCmd.Flags().StringVar(&pickupDir, "pickup-dir", "", "Pickup目录路径")
	sendCmd.Flags().StringVar(&tempDir, "temp-dir", "", "临时目录路径")
	sendCmd.Flags().StringVar(&progressFile, "progress-file", "", "进度文件路径")
	sendCmd.Flags().StringVar(&resultFile, "result-file", "", "结果文件路径")
	sendCmd.Flags().BoolVar(&dryRun, "dry-run", false, "模拟运行（不实际写入）")
	sendCmd.Flags().BoolVar(&resume, "resume", false, "断点续发模式")
	sendCmd.Flags().IntVar(&skipLines, "skip-lines", 0, "跳过前N行（用于断点续发）")
}

func runSend(cmd *cobra.Command, args []string) error {
	// 加载配置
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	// 命令行参数覆盖配置文件
	applyCommandLineOverrides(cfg)

	// 验证配置
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	// 生成任务ID
	if cfg.Job.ID == "" {
		cfg.Job.ID = fmt.Sprintf("%s-%s", cfg.Job.IDPrefix, time.Now().Format("20060102-150405"))
	}

	// 创建进度报告器
	rep := reporter.New(cfg)

	// 打印启动信息
	if !quiet {
		printStartInfo(cfg)
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			fmt.Printf("\n收到信号 %v，正在优雅停止...\n", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	// 检查停止文件
	go func() {
		stopFile := filepath.Join(filepath.Dir(cfg.Output.ProgressFile), "STOP")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := os.Stat(stopFile); err == nil {
					fmt.Println("\n检测到停止文件，正在优雅停止...")
					cancel()
					os.Remove(stopFile)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// 创建并运行调度器
	dispatcher := core.NewDispatcher(cfg, rep)

	// 开始发送
	result, err := dispatcher.Run(ctx)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("发送失败: %w", err)
	}

	// 保存最终结果
	if err := rep.SaveResult(result); err != nil {
		fmt.Fprintf(os.Stderr, "保存结果失败: %v\n", err)
	}

	// 打印结果
	if !quiet {
		printResult(result)
	}

	return nil
}

func loadConfig() (*config.Config, error) {
	if cfgFile != "" {
		return config.LoadFromFile(cfgFile)
	}
	// 使用默认配置
	return config.Default(), nil
}

func applyCommandLineOverrides(cfg *config.Config) {
	if recipientsFile != "" {
		cfg.Recipients.FilePath = recipientsFile
	}
	if templateFile != "" {
		cfg.Email.TemplatePath = templateFile
	}
	if subject != "" {
		cfg.Email.Subject = subject
	}
	if fromAddress != "" {
		cfg.Sender.FromAddress = fromAddress
	}
	if fromName != "" {
		cfg.Sender.FromName = fromName
	}
	if envelopeFrom != "" {
		cfg.Sender.EnvelopeFrom = envelopeFrom
	}
	if vmta != "" {
		cfg.PMTA.VirtualMTA = vmta
	}
	if jobID != "" {
		cfg.Job.ID = jobID
	}
	if workers > 0 {
		cfg.Performance.Workers = workers
	}
	if rateLimit > 0 {
		cfg.Performance.RateLimit = rateLimit
	}
	if pickupDir != "" {
		cfg.PMTA.PickupDir = pickupDir
	}
	if tempDir != "" {
		cfg.PMTA.TempDir = tempDir
	}
	if progressFile != "" {
		cfg.Output.ProgressFile = progressFile
	}
	if resultFile != "" {
		cfg.Output.ResultFile = resultFile
	}
	if dryRun {
		cfg.DryRun = true
	}
	if skipLines > 0 {
		cfg.Recipients.SkipLines = skipLines
	}
}

func validateConfig(cfg *config.Config) error {
	if cfg.Recipients.FilePath == "" {
		return fmt.Errorf("未指定收件人文件")
	}
	if _, err := os.Stat(cfg.Recipients.FilePath); os.IsNotExist(err) {
		return fmt.Errorf("收件人文件不存在: %s", cfg.Recipients.FilePath)
	}
	if cfg.Email.TemplatePath == "" {
		return fmt.Errorf("未指定模板文件")
	}
	if _, err := os.Stat(cfg.Email.TemplatePath); os.IsNotExist(err) {
		return fmt.Errorf("模板文件不存在: %s", cfg.Email.TemplatePath)
	}
	if cfg.Sender.FromAddress == "" {
		return fmt.Errorf("未指定发件人地址")
	}
	// 主题允许为空，不再验证
	// SMTP 配置验证
	if !cfg.DryRun && cfg.SMTP.Enabled {
		if cfg.SMTP.Host == "" {
			return fmt.Errorf("未指定 SMTP 服务器地址")
		}
		if cfg.SMTP.Port <= 0 {
			return fmt.Errorf("无效的 SMTP 端口: %d", cfg.SMTP.Port)
		}
	}
	return nil
}

func printStartInfo(cfg *config.Config) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    PMTA Injector 启动")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  任务ID:       %s\n", cfg.Job.ID)
	fmt.Printf("  收件人文件:   %s\n", cfg.Recipients.FilePath)
	fmt.Printf("  模板文件:     %s\n", cfg.Email.TemplatePath)
	fmt.Printf("  发件人:       %s <%s>\n", cfg.Sender.FromName, cfg.Sender.FromAddress)
	fmt.Printf("  主题:         %s\n", cfg.Email.Subject)
	fmt.Printf("  虚拟MTA:      %s\n", cfg.PMTA.VirtualMTA)
	fmt.Printf("  并发数:       %d\n", cfg.Performance.Workers)
	if cfg.Performance.RateLimit > 0 {
		fmt.Printf("  速率限制:     %d/秒\n", cfg.Performance.RateLimit)
	} else {
		fmt.Printf("  速率限制:     无限制\n")
	}
	fmt.Printf("  Pickup目录:   %s\n", cfg.PMTA.PickupDir)
	if cfg.DryRun {
		fmt.Printf("  模式:         [模拟运行]\n")
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
}

func printResult(result *types.Result) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                      发送完成")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  总数:         %d\n", result.Total)
	fmt.Printf("  成功:         %d\n", result.Success)
	fmt.Printf("  失败:         %d\n", result.Failed)
	fmt.Printf("  耗时:         %.2f 秒\n", result.Duration.Seconds())
	fmt.Printf("  平均速率:     %.2f 封/秒\n", result.AverageRate)
	fmt.Printf("  开始时间:     %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  结束时间:     %s\n", result.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Println("═══════════════════════════════════════════════════════════════")
}
