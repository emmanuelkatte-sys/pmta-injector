package email

// 【v66新增】字符编码转换模块
// 支持将 Go 内部的 UTF-8 字符串/字节转换为目标编码（Shift_JIS、ISO-2022-JP、EUC-JP、GB2312、GBK）
// 用于邮件 Subject、正文、显示名的编码，确保 Content-Type charset 标签和实际内容一致

import (
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// getEncoder 根据 charset 名称获取对应的编码器
// 返回 nil 表示 UTF-8 或不支持的编码（不做转换）
func getEncoder(charset string) *encoding.Encoder {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "shift_jis", "shift-jis", "sjis", "windows-31j", "cp932":
		return japanese.ShiftJIS.NewEncoder()
	case "iso-2022-jp", "iso2022jp":
		return japanese.ISO2022JP.NewEncoder()
	case "euc-jp", "eucjp":
		return japanese.EUCJP.NewEncoder()
	case "gb2312", "gbk", "gb18030", "cp936", "windows-936":
		return simplifiedchinese.GBK.NewEncoder()
	case "hz-gb-2312", "hz-gb2312":
		return simplifiedchinese.HZGB2312.NewEncoder()
	default:
		// UTF-8、US-ASCII 或未知编码 → 不做转换
		return nil
	}
}

// isUTF8Charset 判断 charset 是否为 UTF-8（不需要转换）
func isUTF8Charset(charset string) bool {
	lower := strings.ToLower(strings.TrimSpace(charset))
	return lower == "" || lower == "utf-8" || lower == "utf8" || lower == "us-ascii" || lower == "ascii"
}

// ConvertFromUTF8 将 UTF-8 字节转换为目标编码的字节
// 如果 charset 是 UTF-8 或不支持的编码，直接返回原始字节（不做转换）
// 【Haraka25 修复】转换失败时不再整段回退 UTF-8，而是将不支持的字符替换为 '?'，
// 避免因 ━▶♪ 等特殊字符导致全文乱码。
// 对于 ISO-2022-JP 等有状态编码，先构建安全字符串再整段转换，
// 保证转义序列的连续性和正确性。
func ConvertFromUTF8(utf8Bytes []byte, charset string) []byte {
	if isUTF8Charset(charset) {
		return utf8Bytes
	}

	encoder := getEncoder(charset)
	if encoder == nil {
		return utf8Bytes
	}

	// 先尝试整段转换（大部分情况下会成功，性能最优）
	result, _, err := transform.Bytes(encoder, utf8Bytes)
	if err == nil {
		return result
	}

	// 整段转换失败 → 逐字符检测，将不支持的字符替换为 '?'，
	// 然后用替换后的安全字符串做一次完整转换。
	// 这样对 ISO-2022-JP 等有状态编码，转义序列仍然是连续正确的。
	s := string(utf8Bytes)
	var safeBuilder strings.Builder
	for _, r := range s {
		testEncoder := getEncoder(charset)
		_, _, testErr := transform.Bytes(testEncoder, []byte(string(r)))
		if testErr != nil {
			safeBuilder.WriteByte('?')
		} else {
			safeBuilder.WriteRune(r)
		}
	}

	// 用安全字符串重新做一次完整转换
	safeEncoder := getEncoder(charset)
	safeResult, _, safeErr := transform.Bytes(safeEncoder, []byte(safeBuilder.String()))
	if safeErr != nil {
		// 极端情况：替换后仍失败，返回 ASCII 化的内容
		return []byte(safeBuilder.String())
	}
	return safeResult
}

// ConvertStringFromUTF8 将 UTF-8 字符串转换为目标编码的字节
func ConvertStringFromUTF8(s string, charset string) []byte {
	return ConvertFromUTF8([]byte(s), charset)
}
