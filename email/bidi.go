package email

import (
	"math/rand"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// 【2026-09-04】关键字每 2 字一组 RLO 倒序（主题 / 显示名 / 正文，对齐 PHPMailer-injector）
// 【2026-07-09 升级】改用 LRI/PDI 隔离段包裹（对齐朋友字节格式 + Unicode 6.3+ 官方推荐做法）
//
// 输出格式：[LRI(U+2066)][RLO(U+202E)][rune 反序内容][PDF(U+202C)][PDI(U+2069)]
//   - LRI/PDI：Unicode 6.3+ 引入的"隔离"控制符，把整段视为独立方向段，外围文本（如后续 <邮箱@域>、
//     Subject 后续内容）完全不受内部 RLO 影响 —— 这是解决 v1 RLO/PDF 段落被邮箱地址"漏出去反转"的关键。
//   - RLO/PDF：在隔离段内部把 rune 反序内容视觉再反一次 → 字母/数字/CJK 等"非镜像"字符显示正常。
//   - 扫描器端：读到的原始字节是反序的 → 朴素子串关键词匹配失效。
//
// ⚠ 显示局限（RLO 固有，非 bug）：
//   ① 成对镜像字符（() [] <> {} 等 Bidi_Mirrored 字符）在 RTL 覆盖下会被镜像翻转：
//      原文 "A(B)C" 经反转 + RLO 显示后会变成 "A)B(C"（括号方向反了）。含括号/书名号的文本会错乱。
//   ② 按 rune 反转会拆散 emoji 的 ZWJ 组合序列（如家庭 emoji）/ 肤色修饰 / 变音符 → 这类字符显示可能错乱。
//      纯文字（CJK/拉丁/数字/常见标点）无影响。
//   故本功能仅建议用于"纯文字"的主题/显示名，含括号或 emoji 组合时慎用。
//
// 应用时机（见 builder.go）：文本 → 变量/模板替换 → 零宽字符插入（如启用）→ 本函数（最后一道）。
//   顺序含义：零宽字符跟原文一起被反转，视觉上零宽字符仍落在"字母之间"的合理位置；且 RLO 段落内
//   不会因零宽字符（BN 类 Boundary Neutral）打断 bidi 计算 → 视觉正确 + 反指纹叠加。
//
// 限制：LRI/RLO/PDF/PDI 是 Unicode 双向控制符，属 UTF-8 专属，Shift_JIS / ISO-2022-JP / EUC-JP / GBK 无法表示 →
//   调用方必须先用 bidiCharsetSupported 判定 charset，非 UTF-8 时跳过（否则转码会丢字符/变 ?）。
//
// 反指纹局限（已知）：成熟的 bidi-aware 扫描器会按显示顺序重建文本再扫描 → 可能仍命中关键词，且 RLO
//   本身是反垃圾高危特征，可能拉低送达率。本功能默认关闭，建议慎用/小批量实测。
//
// 注意：这里用 \u 转义而非字面控制符，避免真实 RLO/PDF 出现在源码里造成显示错乱。
const (
	bidiLRI rune = 0x2066 // Left-to-Right Isolate
	bidiRLI rune = 0x2067 // Right-to-Left Isolate
	bidiFSI rune = 0x2068 // First Strong Isolate
	bidiRLO rune = 0x202E // Right-to-Left Override（强制反转显示）
	bidiRLE rune = 0x202B // Right-to-Left Embedding
	bidiPDF rune = 0x202C // Pop Directional Formatting（关闭 RLO 覆盖）
	bidiPDI rune = 0x2069 // Pop Directional Isolate（关闭 LRI 隔离段）
)

var bidiIsolateOpeners = []rune{bidiLRI, bidiRLI, bidiFSI}

// bidiReverseHide 对 text 做"rune 反序 + LRI/PDI 隔离包裹"。空串原样返回。
// 输出格式：[LRI][RLO][rune 反序内容][PDF][PDI]（4 个 rune 控制符各 3 字节 UTF-8，共 12 字节额外开销）
func bidiReverseHide(text string) string {
	if text == "" {
		return text
	}
	runes := []rune(text)
	var sb strings.Builder
	sb.Grow(len(text) + 16) // 4 控制符 × 3 字节 = 12，留 4 字节余量
	sb.WriteRune(bidiLRI)
	sb.WriteRune(bidiRLO)
	for i := len(runes) - 1; i >= 0; i-- {
		sb.WriteRune(runes[i])
	}
	sb.WriteRune(bidiPDF)
	sb.WriteRune(bidiPDI)
	return sb.String()
}

// bidiCharsetSupported 仅 UTF-8（含空串默认）支持 bidi 控制符；其它字符集无法编码这些字符。
func bidiCharsetSupported(charset string) bool {
	c := strings.ToUpper(strings.TrimSpace(charset))
	return c == "" || c == "UTF-8" || c == "UTF8"
}

func hasRtlOverride(s string) bool {
	return strings.ContainsRune(s, bidiRLO) || strings.ContainsRune(s, bidiRLE)
}

func isBidiIsolateOpener(r rune) bool {
	return r == bidiLRI || r == bidiRLI || r == bidiFSI
}

func isBidiRtlOpener(r rune) bool {
	return r == bidiRLO || r == bidiRLE
}

// EnsureBidiIsolatedFormat 为未包裹隔离符的裸 RLO/RLE…PDF 段补上 [LRI|RLI|FSI]…[PDI]。
// 主题/发件人经 RFC2047 传输后，邮件客户端 DOM 中常只显示 RLO/PDF；补齐隔离符与模板 HTML 一致。
func EnsureBidiIsolatedFormat(s string, rng *rand.Rand) string {
	s = NormalizeBidiControlsRawUnicode(s)
	if !hasRtlOverride(s) {
		return s
	}
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	rs := []rune(s)
	var out strings.Builder
	out.Grow(len(s) + 32)
	for i := 0; i < len(rs); i++ {
		if !isBidiRtlOpener(rs[i]) {
			out.WriteRune(rs[i])
			continue
		}
		if i > 0 && isBidiIsolateOpener(rs[i-1]) {
			out.WriteRune(rs[i])
			continue
		}
		j := i + 1
		for j < len(rs) && rs[j] != bidiPDF {
			j++
		}
		if j >= len(rs) {
			out.WriteRune(rs[i])
			continue
		}
		out.WriteRune(bidiIsolateOpeners[rng.Intn(len(bidiIsolateOpeners))])
		for k := i; k <= j; k++ {
			out.WriteRune(rs[k])
		}
		out.WriteRune(bidiPDI)
		i = j
	}
	return out.String()
}

// FinalizeBidiHeaderField 主题/发件人专用：实体→raw、补齐块级隔离、外层 LRI/PDI。
func FinalizeBidiHeaderField(s string, rng *rand.Rand) string {
	s = NormalizeBidiControlsRawUnicode(s)
	s = EnsureBidiIsolatedFormat(s, rng)
	return IsolateBidi(s)
}

// IsolateBidi wraps leftover RLO input in LRI/PDI so a trailing '+' is not
// pulled into the RTL run (visual iC+duol vs iCloud+).
func IsolateBidi(s string) string {
	s = RemoveZeroWidthRunes(s)
	if s == "" || !hasRtlOverride(s) {
		return s
	}
	rs := []rune(s)
	if len(rs) >= 2 && rs[0] == bidiLRI && rs[len(rs)-1] == bidiPDI {
		return s
	}
	return string(bidiLRI) + s + string(bidiPDI)
}

// isolateKeepZW 对齐 PHP ReverseBidi::isolate：有 RLO 时最外层 LRI…PDI，不剥零宽。
func isolateKeepZW(s string) string {
	if s == "" || !hasRtlOverride(s) {
		return s
	}
	rs := []rune(s)
	if len(rs) >= 2 && rs[0] == bidiLRI && rs[len(rs)-1] == bidiPDI {
		return s
	}
	return string(bidiLRI) + s + string(bidiPDI)
}

// RestoreBidiPlaintext undoes leftover RLO/RLE hide (and isolate wrappers) so
// subject/display name stored from a previous obfuscation pass become plaintext.
func RestoreBidiPlaintext(s string) string {
	if s == "" {
		return s
	}
	s = unwindRTLOverrides(s)
	s = unwrapIsolates(s)
	return stripBidiControls(s)
}

func unwindRTLOverrides(s string) string {
	for {
		rs := []rune(s)
		start := -1
		for i := len(rs) - 1; i >= 0; i-- {
			if rs[i] == bidiRLO || rs[i] == bidiRLE {
				start = i
				break
			}
		}
		if start < 0 {
			return s
		}
		end := -1
		for i := start + 1; i < len(rs); i++ {
			if rs[i] == bidiPDF {
				end = i
				break
			}
		}
		if end < 0 {
			s = string(append(append([]rune{}, rs[:start]...), rs[start+1:]...))
			continue
		}
		inner := reverseRunes(rs[start+1 : end])
		out := append(append([]rune{}, rs[:start]...), inner...)
		out = append(out, rs[end+1:]...)
		s = string(out)
	}
}

func unwrapIsolates(s string) string {
	for {
		rs := []rune(s)
		start := -1
		for i := len(rs) - 1; i >= 0; i-- {
			if rs[i] == bidiLRI || rs[i] == 0x2067 || rs[i] == 0x2068 {
				start = i
				break
			}
		}
		if start < 0 {
			return s
		}
		end := -1
		for i := start + 1; i < len(rs); i++ {
			if rs[i] == bidiPDI {
				end = i
				break
			}
		}
		if end < 0 {
			s = string(append(append([]rune{}, rs[:start]...), rs[start+1:]...))
			continue
		}
		out := append(append([]rune{}, rs[:start]...), rs[start+1:end]...)
		out = append(out, rs[end+1:]...)
		s = string(out)
	}
}

func reverseRunes(rs []rune) []rune {
	out := make([]rune, len(rs))
	for i, r := range rs {
		out[len(rs)-1-i] = r
	}
	return out
}

// applyBidiAtKeywordsEveryTwoChars 仅对关键字做随机 1～2 字分组 RLO 倒序（主题/发件人/正文）。
// rng 为 nil 时退回全局 rand（测试用）；正常发信应传入每封邮件独立的 RNG。
func applyBidiAtKeywordsEveryTwoChars(text string, keywords []string, isHTML bool, rng *rand.Rand) string {
	if text == "" || len(keywords) == 0 {
		return text
	}
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	text = NormalizeBidiControlsRawUnicode(text)
	keywords = sortKeywordsByLength(keywords)
	for _, kw := range keywords {
		if utf8.RuneCountInString(kw) < 2 {
			continue
		}
		text = applyBidiInMatches(text, kw, isHTML, rng)
	}
	return NormalizeBidiControlsRawUnicode(text)
}

func sortKeywordsByLength(keywords []string) []string {
	out := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		if strings.TrimSpace(kw) != "" {
			out = append(out, kw)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return utf8.RuneCountInString(out[i]) > utf8.RuneCountInString(out[j])
	})
	return out
}

func applyBidiInMatches(text, keyword string, isHTML bool, rng *rand.Rand) string {
	if keyword == "" || utf8.RuneCountInString(keyword) < 2 {
		return text
	}
	var starts []int
	searchFrom := 0
	for {
		idx := strings.Index(text[searchFrom:], keyword)
		if idx < 0 {
			break
		}
		abs := searchFrom + idx
		end := abs + len(keyword)
		if isHTML && (isInsideHTMLTag(text, abs, end) || isInsideHTMLAttribute(text, abs)) {
			searchFrom = abs + 1
			continue
		}
		starts = append(starts, abs)
		searchFrom = end
	}
	for i := len(starts) - 1; i >= 0; i-- {
		start := starts[i]
		end := start + len(keyword)
		replaced := obfuscateWordRandomChunks(text[start:end], rng)
		text = text[:start] + replaced + text[end:]
	}
	return text
}

func obfuscateWordRandomChunks(word string, rng *rand.Rand) string {
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	runes := []rune(word)
	n := len(runes)
	if n < 2 {
		return word
	}
	var out strings.Builder
	out.Grow(len(word) + n*16)
	for i := 0; i < n; {
		remaining := n - i
		if remaining < 2 {
			out.WriteRune(runes[i])
			break
		}
		size := randomObfuscateChunkSize(remaining, 2, rng)
		chunk := string(runes[i : i+size])
		out.WriteString(bidiReverseHide(chunk))
		i += size
	}
	s := out.String()
	if hasRtlOverride(s) {
		return IsolateBidi(s)
	}
	return s
}

func randomObfuscateChunkSize(remaining, minLen int, rng *rand.Rand) int {
	if remaining <= minLen {
		return remaining
	}
	var choices []int
	for size := minLen; size <= remaining; size++ {
		left := remaining - size
		if left == 0 || left >= minLen || left == 1 {
			choices = append(choices, size)
		}
	}
	if len(choices) == 0 {
		return remaining
	}
	return choices[rng.Intn(len(choices))]
}

// obfuscateWordRandomGroups 保留名：随机分段 bidiReverseHide。
func obfuscateWordRandomGroups(word string, rng *rand.Rand) string {
	return obfuscateWordRandomChunks(word, rng)
}

func stripBidiControls(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF || r == 0x2060 ||
			(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
