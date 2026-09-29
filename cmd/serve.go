package cmd

// =============================================================================
// 【2026-05-24 批次 2】serve 子命令 —— 启动 HTTP 退订服务器
//
// 用法：
//   pmta-injector serve --config /etc/haraka-injector/unsub.yaml
//
// 仅当配置文件里 unsubscribe_server.enabled = true 时才真正启动；否则立刻退出。
// 由 systemd 单元 pmta-injector-unsub.service 管理：
//   - User=root（绑 80/443 需要 root，或用 setcap 给二进制 CAP_NET_BIND_SERVICE）
//   - Restart=on-failure
//   - 由 deploy-injector.sh 在选了"使用真实退订风格"时安装、enable、start
//
// 退出信号：
//   - SIGINT / SIGTERM 触发优雅关闭（context.Cancel → server.Shutdown 5s timeout）
// =============================================================================

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/unsubserver"

	"github.com/spf13/cobra"
)

// serveCmd serve 子命令
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "启动 HTTP 退订服务器（List-Unsubscribe 真实模式）",
	Long: `serve 子命令仅在 ListUnsubMode = "real" 部署模式下使用。

该命令启动一个长期运行的 HTTP 服务：
  - 0.0.0.0:80  → 301 → HTTPS
  - 0.0.0.0:443 → 返回退订成功页面（日文静态 HTML，< 2 KB）
  - 所有请求路径都返回同一个页面（通配符路由）
  - X-Robots-Tag: noindex 防搜索引擎索引
  - 实例签名反指纹（启动一次随机，进程生命周期稳定）

由 systemd 单元 pmta-injector-unsub.service 管理。

示例：
  pmta-injector serve --config /etc/haraka-injector/unsub.yaml`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		return fmt.Errorf("--config 参数必填")
	}

	cfg, err := config.LoadFromFile(cfgFile)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	if !cfg.UnsubscribeServer.Enabled {
		log.Println("[serve] unsubscribe_server.enabled = false in config, exiting cleanly.")
		return nil
	}

	srv, err := unsubserver.NewServer(cfg.UnsubscribeServer)
	if err != nil {
		return fmt.Errorf("初始化退订服务器失败: %w", err)
	}

	// 监听 SIGINT/SIGTERM 优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("[serve] received signal %v, shutting down...", sig)
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("退订服务器运行出错: %w", err)
	}

	log.Println("[serve] shutdown complete.")
	return nil
}
