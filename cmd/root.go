// Package cmd 提供 pmta-injector 的 CLI 入口（基于 Cobra）。
//
// 子命令：
//   - send     批量生成并注入邮件
//   - validate 验证配置与模板
//   - serve    启动 List-Unsubscribe 真实退订 HTTP 服务
//   - version  显示版本信息
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// 版本信息
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"

	// 全局标志
	cfgFile string
	verbose bool
	quiet   bool
)

// rootCmd 根命令
var rootCmd = &cobra.Command{
	Use:   "pmta-injector",
	Short: "PowerMTA Pickup 模式高性能邮件注入程序",
	Long: `pmta-injector 是一个高性能的邮件注入工具，
通过直接写入 PowerMTA 的 Pickup 目录实现极高吞吐量的邮件发送。

支持功能：
  - 高并发邮件生成（50,000+ 封/秒）
  - 模板变量替换
  - CSV/JSON 收件人数据
  - 实时进度追踪
  - 断点续发

使用示例：
  pmta-injector send --config config.yaml
  pmta-injector send -r recipients.csv -t template.html -s "Welcome"
  pmta-injector validate --template template.html`,
}

// Execute 执行根命令
func Execute() error {
	return rootCmd.Execute()
}

// SetVersionInfo 设置版本信息
func SetVersionInfo(v, bt, gc string) {
	version = v
	buildTime = bt
	gitCommit = gc
}

func init() {
	// 全局标志
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "配置文件路径")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "详细输出模式")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "静默模式")

	// 添加子命令
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)
}

// versionCmd 版本命令
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "显示版本信息",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("pmta-injector version %s\n", version)
		fmt.Printf("Build time: %s\n", buildTime)
		fmt.Printf("Git commit: %s\n", gitCommit)
		fmt.Printf("Go version: %s\n", "go1.21+")
		fmt.Printf("OS/Arch: %s/%s\n", os.Getenv("GOOS"), os.Getenv("GOARCH"))
	},
}
