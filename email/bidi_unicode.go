package email

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// bidiControlCodepoints HTML 实体可能被错误写入模板；统一解码为 UTF-8 原字符。
var bidiControlCodepoints = map[rune]struct{}{
	0x200B: {}, 0x200C: {}, 0x200D: {}, 0xFEFF: {}, 0x2060: {},
	0x202A: {}, 0x202B: {}, 0x202C: {}, 0x202D: {}, 0x202E: {},
	0x2066: {}, 0x2067: {}, 0x2068: {}, 0x2069: {},
}

func isBidiControlCodepoint(cp int) bool {
	if cp < 0 || cp > utf8.MaxRune {
		return false
	}
	_, ok := bidiControlCodepoints[rune(cp)]
	return ok
}

// NormalizeBidiControlsRawUnicode 将 HTML 数字实体形式的 bidi/零宽控制符还原为 UTF-8 原字符。
// 注入器只输出 raw Unicode，绝不写 &#x202E; 这类实体。
func NormalizeBidiControlsRawUnicode(s string) string {
	if s == "" || !strings.Contains(s, "&#") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '&' || i+3 >= len(s) {
			out.WriteByte(s[i])
			i++
			continue
		}
		if decoded, n, ok := decodeHTMLNumericEntityAt(s, i); ok && isBidiControlCodepoint(decoded) {
			out.WriteRune(rune(decoded))
			i += n
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func decodeHTMLNumericEntityAt(s string, i int) (cp int, n int, ok bool) {
	if i >= len(s) || s[i] != '&' {
		return 0, 0, false
	}
	if i+4 < len(s) && (s[i+1] == '#' && (s[i+2] == 'x' || s[i+2] == 'X')) {
		j := i + 3
		start := j
		for j < len(s) && ((s[j] >= '0' && s[j] <= '9') ||
			(s[j] >= 'a' && s[j] <= 'f') ||
			(s[j] >= 'A' && s[j] <= 'F')) {
			j++
		}
		if j > start && j < len(s) && s[j] == ';' {
			v, err := strconv.ParseInt(s[start:j], 16, 32)
			if err == nil {
				return int(v), j - i + 1, true
			}
		}
	}
	if i+3 < len(s) && s[i+1] == '#' {
		j := i + 2
		start := j
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > start && j < len(s) && s[j] == ';' {
			v, err := strconv.ParseInt(s[start:j], 10, 32)
			if err == nil {
				return int(v), j - i + 1, true
			}
		}
	}
	return 0, 0, false
}
