package email

// =============================================================================
// 【2026-05-27 从 PowerMTA 移植】RFC 5322 §2.2.3 智能邮件头折叠器
//
// 用途：
//   Received（随机）模板和 List-Unsubscribe 真实/自定义/随机模板中的长头部值
//   需要折叠成多行，符合 RFC 5322 §2.2.3 folding 规则，否则：
//     - 单行 > 78 字符（RFC 推荐上限）：邮件客户端显示不友好
//     - 单行 > 998 字符（RFC 硬上限）：违反协议，部分 MTA 拒收
//
// 规则（RFC 5322）：
//   - "long line" 在 White Space (WSP = SP/TAB) 处可换行
//   - 续行前缀必须是 CRLF + 1 个 WSP（"\r\n\t" 或 "\r\n "）
//   - "header-name:" 不能被折叠，必须保留在首行
//   - 续行允许任意层级，每行 ≤ 78（软）/ 998（硬）
//
// 实施策略：
//   - 优先在"语义边界"处断行：' for ' / ' by ' / '; ' / ' with ' / ' (EHLO ' / ') '
//   - 找不到优先边界时，退化到任意空格
//   - 续行用 "\r\n\t"（1 个 tab，标准做法，渲染更紧凑）
//   - 每行尝试 ≤ targetLen（默认 78）；超过 hardLimit（默认 998）强制断
// =============================================================================

import "strings"

// foldHeaderValue 把单行头部值折叠成符合 RFC 5322 §2.2.3 的多行形式
//
// 输入约定：
//   - value 是 "Header-Name: " 后面的纯值部分（不含 Name 和冒号）
//   - 不含 CRLF（如果含，先 NormalizeLineEndings 清理）
//   - prefixLen 是 "Header-Name: " 的字符数（首行预留宽度）
//
// 返回：
//   - 不含 "Header-Name:" 前缀，但含必要的 CRLF + tab 续行
//   - 末尾不含 CRLF（调用方按需追加 "\r\n"）
//
// 边界优先级（高到低）：
//   1. "; "
//   2. " for "
//   3. " by "
//   4. " with "
//   5. " (EHLO "  / ") "
//   6. 任意 ASCII 空格
//
// 性能：单次扫描 O(n)，无回溯
func foldHeaderValue(value string, prefixLen int) string {
	const targetLen = 78
	const hardLimit = 998

	// 清理可能的 \r \n（防御性，调用方应该已经清理过）
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")

	// 如果总长度（含前缀）≤ targetLen，无需折叠
	if prefixLen+len(value) <= targetLen {
		return value
	}

	var b strings.Builder
	b.Grow(len(value) + len(value)/40) // 预估 +2.5% 增量（续行符开销）

	currentLineLen := prefixLen // 首行起始：含 "Header-Name: " 的占位
	remaining := value
	firstChunk := true

	for len(remaining) > 0 {
		// 计算这一行还能容纳的剩余字符数（用 target 而不是 hard，留余量）
		budget := targetLen - currentLineLen
		if budget < 20 {
			// 余量太小（< 20 字符），直接换行从头开始算
			b.WriteString("\r\n\t")
			currentLineLen = 1 // tab 算 1 字符
			budget = targetLen - 1
			firstChunk = false
		}

		// 如果剩余内容能全部塞进 budget，直接输出收尾
		if len(remaining) <= budget {
			if !firstChunk {
				// 续行前缀已写过；剩余内容直接追加
			}
			b.WriteString(remaining)
			return b.String()
		}

		// 剩余太长——需要找一个语义边界断行
		// 在 [1, budget] 之间找最右侧的优先边界
		breakAt := findBestBreak(remaining, budget, hardLimit-currentLineLen)
		if breakAt < 0 {
			// 实在找不到边界（极端情况，比如一长串没空格的 base64），硬切
			breakAt = budget
			if breakAt > len(remaining) {
				breakAt = len(remaining)
			}
		}

		chunk := remaining[:breakAt]
		b.WriteString(chunk)

		// 续行：CRLF + TAB
		b.WriteString("\r\n\t")
		currentLineLen = 1

		// 跳过断点处的前导空格（避免续行第一个字符是空格）
		remaining = strings.TrimLeft(remaining[breakAt:], " \t")
		firstChunk = false
	}

	return b.String()
}

// findBestBreak 在 value 的 [1, maxBudget] 范围内寻找最佳断行位置
// 返回断点索引（断点字符不包含在前段中）；找不到返回 -1
//
// 优先级（从高到低）：
//   1. "; "       → 在 ;= 后断
//   2. " for "    → 在 for 前断
//   3. " by "     → 在 by 前断
//   4. " with "   → 在 with 前断
//   5. " (EHLO "  → 在 ( 前断
//   6. ") "       → 在 ) 后断
//   7. " "        → 任意空格（最后兜底）
//
// hardBudget: 超过此长度算违反 RFC 硬上限（998），需在此之内必须找到断点
func findBestBreak(value string, softBudget, hardBudget int) int {
	if hardBudget < softBudget {
		softBudget = hardBudget
	}
	if softBudget <= 1 {
		return -1
	}
	if softBudget > len(value) {
		softBudget = len(value)
	}

	// 搜索区域（首字符不能切，会产生空续行）
	search := value[:softBudget]

	// 优先级 1: "; "（在 ; 后切，含 ; 在前段）
	if idx := strings.LastIndex(search, "; "); idx > 0 {
		return idx + 2 // 包含 "; " 在前段
	}

	// 优先级 2: " for "
	if idx := strings.LastIndex(search, " for "); idx > 0 {
		return idx + 1 // 切在 for 前的空格之后
	}

	// 优先级 3: " by "
	if idx := strings.LastIndex(search, " by "); idx > 0 {
		return idx + 1
	}

	// 优先级 4: " with "
	if idx := strings.LastIndex(search, " with "); idx > 0 {
		return idx + 1
	}

	// 优先级 5: " (EHLO "
	if idx := strings.LastIndex(search, " (EHLO "); idx > 0 {
		return idx + 1
	}

	// 优先级 6: ") "
	if idx := strings.LastIndex(search, ") "); idx > 0 {
		return idx + 2 // 含 ") " 在前段
	}

	// 优先级 7: 任意 ASCII 空格（最后兜底）
	if idx := strings.LastIndex(search, " "); idx > 0 {
		return idx + 1
	}

	// 在 soft budget 内没找到 → 尝试 hard budget 范围
	if hardBudget > softBudget && hardBudget <= len(value) {
		extSearch := value[:hardBudget]
		if idx := strings.LastIndex(extSearch, " "); idx > softBudget {
			return idx + 1
		}
	}

	// 完全找不到
	return -1
}

// foldFullHeader 完整折叠一个 "Name: value\r\n" 形式的邮件头
// 输入：name = "Received"，value = 头部值（不含 Name 和冒号，不含末尾 CRLF）
// 输出：完整 "Name: folded-value\r\n"
//
// 用于 Received（随机）模板渲染后整体折叠
func foldFullHeader(name, value string) string {
	prefixLen := len(name) + 2 // "Name: " 占用字符数
	folded := foldHeaderValue(value, prefixLen)
	return name + ": " + folded + "\r\n"
}
