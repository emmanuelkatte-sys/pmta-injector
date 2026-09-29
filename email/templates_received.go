package email

// =============================================================================
// 【2026-05-31】Received 模板池 — 从嵌入文件加载(替代原 50 条字面量)
//
// 演化历史:
//   - 2026-05-24 批次 2:50 条字面量(idx 0-49,Yahoo/Gmail/Docomo/Postfix/Mitsui/...)
//   - 2026-05-31:同步 C# 端 19987 条池,改为 //go:embed templates_received_pool.txt
//
// 数据源:templates_received_pool.txt(与 C# Resources/builtin-received-templates.txt 字面一致)
//   一行一个模板,纯模板格式,UTF-8 LF,空行 + "//" 注释行被忽略
//
// 约定:
//   - 每个模板都是单行(不含 \r\n),渲染后由 foldHeaderValue 折叠
//   - 不含 "Received: " 前缀(由调用方拼接)
//   - 所有变量占位符必须能被 variables_ext.go 的 53 个变量解析(已离线校验过 46 种)
//   - 模板内部不嵌套变量(如 `{ID_HEX:{TIMESTAMP}}`),避免循环替换
//
// 与上游 C# 端一致性保证:
//   两端嵌入同一份去重产物(20167 行源文件 → 13 条内部重复去除 → 19987 条净集)
//   离线 generate_pool.py 同时输出两份文件,内容字节级一致
// =============================================================================

import (
	_ "embed"
	"strings"
)

//go:embed templates_received_pool.txt
var receivedTemplatePoolRaw string

// receivedTemplatePool 19987 个 Received 模板(从嵌入资源解析)
// package init 时一次性 split + 过滤,运行期不再变化
//
// 实际运行时:generateReceivedRandom 从 hg.cfg.ReceivedRandomTemplates(用户在 C# UI 编辑后
// 写入 config.yaml 的列表)读取模板,不直接读 receivedTemplatePool。
//
// 该变量保留的两个作用:
//  1. 反指纹"二进制变体差异"(D4 决策)— 嵌入的 3.5MB 数据让每台服务器 Go 二进制内容不同
//  2. 未来扩展 API 备份池 — 万一未来想让 Go 端在 config 空池时回落到内置池,直接读这里
var receivedTemplatePool = loadReceivedTemplatePool()

// receivedTemplatePoolSize 池大小(启动时一次性计算,避免运行时反复求 len)
var receivedTemplatePoolSize = len(receivedTemplatePool)

// loadReceivedTemplatePool 解析嵌入的 .txt 文件,过滤空行/注释行
// 容错:同时处理 \r\n 和 \n;过滤每行前后空白
// 防御:嵌入失败(空字符串)时返回 []string{} 而非 nil,避免 receivedTemplatePool[i] 越界 panic
//
//	(实际不会发生 — go:embed 失败会在编译期报错)
func loadReceivedTemplatePool() []string {
	if receivedTemplatePoolRaw == "" {
		return []string{}
	}
	// 按 \n split,然后逐行 trim \r 和空白
	rawLines := strings.Split(receivedTemplatePoolRaw, "\n")
	result := make([]string, 0, len(rawLines))
	for _, raw := range rawLines {
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "//") {
			continue
		}
		result = append(result, line)
	}
	return result
}
