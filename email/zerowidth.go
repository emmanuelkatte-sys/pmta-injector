package email

import (
	"math/rand"
	"sort"
	"strings"
	"unicode/utf8"
)

// 零宽字符集（4 种混用，增加指纹多样性）
var zeroWidthChars = []rune{
	'\u200B', // 零宽空格
	'\u200C', // 零宽非连接符
	'\u200D', // 零宽连接符
	'\uFEFF', // 零宽不换行空格
	'\u2060', // 单词连接符
}

// ParseKeywords 解析逗号分隔的关键字列表（去空白、去重、长关键字优先）
func ParseKeywords(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, part := range strings.Split(raw, ",") {
		kw := strings.TrimSpace(part)
		if kw == "" || seen[kw] {
			continue
		}
		seen[kw] = true
		out = append(out, kw)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// InsertZeroWidthAtKeywords 在文本中与关键字匹配的位置插入零宽字符（关键字内部随机插入）
func InsertZeroWidthAtKeywords(text string, keywords []string, isHTML bool) string {
	if text == "" || len(keywords) == 0 {
		return text
	}
	result := text
	for _, kw := range keywords {
		result = insertZeroWidthInKeywordMatches(result, kw, isHTML)
	}
	return result
}

func insertZeroWidthInKeywordMatches(text, keyword string, isHTML bool) string {
	if keyword == "" {
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
		replaced := insertZeroWidthIntoWord(text[start:end])
		text = text[:start] + replaced + text[end:]
	}
	return text
}

func isInsideHTMLTag(text string, start, end int) bool {
	if start < 0 || end > len(text) {
		return false
	}
	before := text[:start]
	lastOpen := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")
	return lastOpen > lastClose
}

// isInsideHTMLAttribute 判断 pos 是否位于 HTML 属性值（如 src="cid:xxx"）内部。
func isInsideHTMLAttribute(text string, pos int) bool {
	if pos <= 0 || pos > len(text) {
		return false
	}
	for i := pos - 1; i >= 0; i-- {
		switch text[i] {
		case '"', '\'':
			j := i - 1
			for j >= 0 && (text[j] == ' ' || text[j] == '\t') {
				j--
			}
			if j >= 0 && text[j] == '=' {
				return true
			}
			return false
		case '<', '>':
			return false
		}
	}
	return false
}

// RemoveZeroWidthRunes 移除字符串中的零宽字符。
func RemoveZeroWidthRunes(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isZeroWidthRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isZeroWidthRune(r rune) bool {
	for _, zw := range zeroWidthChars {
		if r == zw {
			return true
		}
	}
	return false
}

// SanitizeCIDReferences 清除 cid: 引用中的零宽字符，避免 Content-ID 匹配失败。
func SanitizeCIDReferences(html string) string {
	const prefix = "cid:"
	var out strings.Builder
	out.Grow(len(html))
	i := 0
	lower := strings.ToLower
	for i < len(html) {
		idx := lower(html[i:])
		rel := strings.Index(idx, prefix)
		if rel < 0 {
			out.WriteString(html[i:])
			break
		}
		abs := i + rel
		out.WriteString(html[i:abs])
		out.WriteString(prefix)
		j := abs + len(prefix)
		for j < len(html) {
			r, size := utf8.DecodeRuneInString(html[j:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			if r == '"' || r == '\'' || r == '>' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				break
			}
			if !isZeroWidthRune(r) {
				out.WriteString(html[j : j+size])
			}
			j += size
		}
		i = j
	}
	return out.String()
}

func insertZeroWidthIntoWord(word string) string {
	runes := []rune(word)
	n := len(runes)
	if n < 2 {
		return word
	}
	maxIns := n - 1
	count := 1 + rand.Intn(minInt(3, maxIns))
	positions := make(map[int]bool, count)
	for len(positions) < count {
		pos := rand.Intn(maxIns) + 1
		positions[pos] = true
	}
	var b strings.Builder
	b.Grow(len(word) + count*4)
	for i, r := range runes {
		b.WriteRune(r)
		if positions[i+1] {
			b.WriteRune(zeroWidthChars[rand.Intn(len(zeroWidthChars))])
		}
	}
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
