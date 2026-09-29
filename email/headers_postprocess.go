package email

// =============================================================================
// 【2026-05-31】邮件头后处理:字段名随机大小写 + 锚定式乱序
//
// 入口:在 builder.go::buildRawEmail 主头组装完成后,对累积的 []string mainHeaders 做后处理
//
// 配置:
//   - cfg.Headers.RandomCase    true → 应用 randomizeFieldNames
//   - cfg.Headers.ShuffleOrder  true → 应用 shuffleHeadersWithAnchors
//   - cfg.Headers.CaseMode      预留(D2 决策切换点):空="random"=全随机式;"stylepool" 留作未来扩展
//
// 锚定规则(温和模式):
//   priority 0  : x-virtual-mta / x-job        (PMTA 控制头,在最顶)
//   priority 1  : 所有 Received-*              (RFC 5321 时序要求)
//   priority 2  : DKIM-Signature               (紧随 Received 之后)
//   priority 3  : MIME-Version                 (在 body 前的 MIME 基础头)
//   priority 4  : From
//   priority 5  : To
//   priority 6  : Cc
//   priority 7  : Subject
//   priority 8  : Date
//   priority 9  : Message-ID
//   其它头     : 可乱序池(Fisher-Yates 洗牌)
//   特殊配对 : List-Unsubscribe + List-Unsubscribe-Post 配对锚定,Post 紧跟 Unsubscribe
//
// 大小写跳过名单(case-insensitive 比对):
//   DKIM-Signature  — simple canonicalization 字节比较,且伪签名失败原因要保持"链路损坏"语义
//   x-virtual-mta   — PMTA 控制头,字段名小写是 PMTA 配置约定
//   x-job           — 同上
//
// 设计原则:
//   - 不丢任何头(len(output) == len(input))
//   - 不重复任何头(每个输入头精确出现一次)
//   - Received-* 系列保持生成顺序(时序敏感)
//   - 大小写随机化后,锚定/配对识别用 strings.EqualFold(大小写不敏感)
//   - 所有随机源用传入的 *rand.Rand(worker 独立,避免共享种子污染)
// =============================================================================

import (
	"math/rand"
	"strings"
)

// caseSkipNames 字段名大小写随机化的跳过集合(全小写比对)
// 命中即保持原大小写,不参与随机化
//
// 设计:两个工程(PowerMTA / Haraka)共用同一份名单(联合集),保字节级一致
//   - dkim-signature   : DKIM simple canonicalization 字节比较兼容
//   - x-virtual-mta    : PowerMTA 控制头(Haraka 路径下永远不会出现 — 由 IsPMTA() 跳过)
//   - x-job            : 同上
//   - x-internal-ccbcc-skip-tg : Haraka log_delivered.js 插件依赖精确字段名扫描
//     (PowerMTA 路径下永远不会出现 — 由 SkipTelegram 字段控制)
var caseSkipNames = map[string]struct{}{
	"dkim-signature":                {},
	"arc-seal":                      {},
	"arc-message-signature":         {},
	"arc-authentication-results":    {},
	"x-virtual-mta":                 {},
	"x-job":                         {},
	"x-internal-ccbcc-skip-tg":      {},
}

// anchorPriority 温和锚定模式下,定位每类头到固定 priority(越小越靠前)
// 不在表里的头进入可乱序池
//
// 注意:"received" 是前缀匹配("Received:" 包括所有 ESP Received / Random Received / 原始 Received)
// 其它头是精确匹配
//
// 【2026-06-01 第三轮自检修复】mime-version 从 prio 3 改为 prio 10:
//
//	原因:builder.go::buildRawEmail 中 MIME-Version 是在 Message-ID 之后 append 的(L491 vs L486),
//	      如果 anchorPriority["mime-version"]=3,启用 ShuffleOrder 时 MIME-Version 会跑到 From 之前 —
//	      与"全关(ShuffleOrder=false)时按 append 顺序输出"的行为不一致,**同一发件方启用/关闭乱序
//	      会产生两类邮件特征**,反垃圾聚类时可能识别。
//	修复:prio 10 让 MIME-Version 锚定在 Message-ID(prio 9)之后,两种模式输出位置一致。
var anchorPriority = map[string]int{
	"x-virtual-mta":  0,
	"x-job":          0,
	"received":       1, // 前缀
	"dkim-signature": 2,
	"from":           4,
	"sender":         4,
	"to":             5,
	"cc":             6,
	"subject":        7,
	"date":           8,
	"message-id":     9,
	"mime-version":   10, // 改:从 3 → 10,锚定在 Message-ID 之后
}

// splitHeaderBlock 把多个连续的邮件头(字符串块)按 RFC 5322 §2.2.3 折叠规则切成单条
// 续行(以 SP / TAB 开头的行)归属上一个头
//
// 输入示例(block):
//
//	"Received: from xxx\r\n (Authenticated...)\r\n by yyy\r\nFrom: a@b\r\n"
//
// 输出:
//
//	["Received: from xxx\r\n (Authenticated...)\r\n by yyy\r\n", "From: a@b\r\n"]
//
// 边界处理:
//   - 空字符串 → nil
//   - 末尾没有 \r\n 也能正确切分(SplitAfter 保留分隔符,无分隔符行原样保留)
//   - 多个连续空行不会合并(空行不归属任何头,直接丢弃)
func splitHeaderBlock(block string) []string {
	if block == "" {
		return nil
	}
	// 用 SplitAfter("\n") 保留 \n;\r\n 切分后每行末尾 = "\r\n";单 \n 行末尾 = "\n"
	lines := strings.SplitAfter(block, "\n")
	result := make([]string, 0, 16)
	var current strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		// 空白行不参与累积也不分隔(罕见,但要兼容)
		// 注意:strings.TrimRight 后看是否空,但 "\r\n" trim 后为空也算空行
		if strings.TrimRight(line, "\r\n") == "" {
			continue
		}
		if current.Len() == 0 {
			current.WriteString(line)
			continue
		}
		// 折叠续行:首字符是 SP / TAB
		first := line[0]
		if first == ' ' || first == '\t' {
			current.WriteString(line)
		} else {
			result = append(result, current.String())
			current.Reset()
			current.WriteString(line)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

// extractFieldName 从一个完整 header 条目("Name: value\r\n..." 含可能的折叠续行)提取字段名(小写)
// 续行(SP/TAB 开头)返回空字符串(理论上不会传入,但防御性处理)
// 无冒号返回空字符串
func extractFieldName(line string) string {
	if line == "" {
		return ""
	}
	if line[0] == ' ' || line[0] == '\t' {
		return ""
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(line[:colon]))
}

// randomizeFieldName 把一个 header 条目的字段名("Name" 在 ":" 之前)逐字符随机大小写
// 跳过 caseSkipNames 中的字段(DKIM-Signature / x-virtual-mta / x-job)
// 值部分(冒号之后,包括折叠续行)完全不动
// 续行(SP/TAB 开头)原样返回
func randomizeFieldName(line string, r *rand.Rand) string {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return line
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return line
	}
	name := line[:colon]
	if _, skip := caseSkipNames[strings.ToLower(strings.TrimSpace(name))]; skip {
		return line
	}
	var sb strings.Builder
	sb.Grow(len(line))
	for i := 0; i < len(name); i++ {
		ch := name[i]
		isLower := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		if !isLower && !isUpper {
			// 数字、连字符 -、点 . 等保持原样
			sb.WriteByte(ch)
			continue
		}
		// 50/50 翻转
		if safeIntn(r, 2) == 0 {
			// 取大写
			if isLower {
				sb.WriteByte(ch - 32)
			} else {
				sb.WriteByte(ch)
			}
		} else {
			// 取小写
			if isUpper {
				sb.WriteByte(ch + 32)
			} else {
				sb.WriteByte(ch)
			}
		}
	}
	// 拼上 ":" 及后续(包括所有折叠续行)
	sb.WriteString(line[colon:])
	return sb.String()
}

// applyCaseRandomization 对整个 mainHeaders 切片做字段名大小写随机化
// 输入切片就地修改(返回同一切片,方便链式)
// 预留 caseMode 切换点:目前只走 "random" 路径
func applyCaseRandomization(headers []string, r *rand.Rand, caseMode string) []string {
	_ = caseMode // 预留:未来可扩展 "stylepool"(真实风格池)等
	if len(headers) == 0 {
		return headers
	}
	for i, h := range headers {
		headers[i] = randomizeFieldName(h, r)
	}
	return headers
}

// PostprocessMainHeaders 总入口,builder.go 调用
// 顺序:先乱序,后随机大小写
//
// dkimSignHeaders: Haraka DKIM 预设签名字段（小写）；乱序时保持其相对顺序以保障 DKIM 对齐。
func PostprocessMainHeaders(headers []string, r *rand.Rand, shuffleOrder, randomCase bool, caseMode string, dkimSignHeaders []string) []string {
	if len(headers) == 0 {
		return headers
	}
	if shuffleOrder {
		if len(dkimSignHeaders) > 0 {
			headers = shuffleHeadersWithAnchors(headers, r, dkimSignHeaders)
		} else {
			headers = shuffleHeadersLegacy(headers, r)
		}
	}
	if randomCase {
		headers = applyCaseRandomization(headers, r, caseMode)
	}
	return headers
}
