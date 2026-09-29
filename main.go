// pmta-injector - PowerMTA Pickup 模式高性能邮件注入程序
// 通过直接写入 Pickup 目录实现极高吞吐量的邮件发送
package main

import (
	"fmt"
	"os"

	"__MODULE_PLACEHOLDER__/cmd"
)

// 版本信息（编译时注入）
var (
	Version   = "__VERSION_PLACEHOLDER__"
	BuildTime = "__BUILDTIME_PLACEHOLDER__"
	GitCommit = "__GITCOMMIT_PLACEHOLDER__"
)

func main() {
	// 设置版本信息
	cmd.SetVersionInfo(Version, BuildTime, GitCommit)

	// 执行根命令
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
