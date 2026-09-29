package email

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const phpmailerMaxLineLength = 998
const phpmailerEncodedWordMax = 75

// encodeFromAddressPHPMailer 对齐 PHPMailer addrFormat + encodeHeader('phrase')：
// 自动选 B/Q、encoded-word 按 75 字节折行；不使用 YAML header_encoding。
func encodeFromAddressPHPMailer(displayName, email, charset string) string {
	email = phpmailerSecureHeader(email)
	displayName = phpmailerSecureHeader(displayName)
	if displayName == "" {
		return email
	}
	if charset == "" {
		charset = "UTF-8"
	}
	return encodeHeaderPhrase(displayName, charset) + " <" + email + ">"
}

func phpmailerSecureHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "")
}

func encodeHeaderPhrase(str, charset string) string {
	if str == "" {
		return str
	}
	if !phpmailerHas8bit(str) {
		escaped := phpmailerAddCSlashes(str)
		if str == escaped && phpmailerIsAtomPhrase(str) {
			return str
		}
		return `"` + escaped + `"`
	}

	matchcount := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c != 0x20 && c != 0x21 && !(c >= 0x23 && c <= 0x5B) && !(c >= 0x5D && c <= 0x7E) {
			matchcount++
		}
	}

	cs := charset
	if !phpmailerHas8bit(str) {
		cs = "us-ascii"
	}
	overhead := 8 + len(cs)
	maxlen := phpmailerMaxLineLength - overhead

	var encoding string
	switch {
	case matchcount > len(str)/3:
		encoding = "B"
	case matchcount > 0:
		encoding = "Q"
	case len(str) > maxlen:
		encoding = "Q"
	default:
		return str
	}

	var encoded string
	if encoding == "B" {
		if phpmailerHasMultiBytes(str) {
			encoded = phpmailerBase64EncodeWrapMB(str, cs)
		} else {
			b64 := base64.StdEncoding.EncodeToString([]byte(str))
			chunk := phpmailerEncodedWordMax - 8 - len(cs)
			chunk -= chunk % 4
			if chunk < 4 {
				chunk = 4
			}
			encoded = phpmailerWrapRawB64(b64, chunk, cs)
		}
	} else {
		q := phpmailerEncodeQPhrase(str)
		encoded = phpmailerWrapQWords(q, cs)
	}
	return strings.TrimSpace(encoded)
}

func phpmailerHas8bit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

func phpmailerHasMultiBytes(s string) bool {
	return utf8.RuneCountInString(s) < len(s)
}

func phpmailerIsAtomPhrase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~', ' ':
			continue
		default:
			return false
		}
	}
	return true
}

func phpmailerAddCSlashes(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 32 || c == 127 || c == '\\' || c == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func phpmailerEncodeQPhrase(str string) string {
	encoded := strings.ReplaceAll(strings.ReplaceAll(str, "\r", ""), "\n", "")
	var b strings.Builder
	b.Grow(len(encoded) * 3)
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '!' || c == '*' || c == '+' || c == '/' || c == ' ' || c == '-'
		if ok {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "=%02X", c)
		}
	}
	return strings.ReplaceAll(b.String(), " ", "_")
}

func phpmailerBase64EncodeWrapMB(str, charset string) string {
	start := "=?" + charset + "?B?"
	end := "?="
	length := phpmailerEncodedWordMax - len(start) - len(end)
	if length < 4 {
		length = 4
	}
	runes := []rune(str)
	mbLen := len(runes)
	byteLen := len(str)
	if byteLen < 1 {
		return ""
	}
	ratio := float64(mbLen) / float64(byteLen)
	avgLength := int(math.Floor(float64(length) * ratio * 0.75))
	if avgLength < 1 {
		avgLength = 1
	}

	var parts []string
	for i := 0; i < mbLen; {
		lookBack := 0
		var chunkEnc string
		offset := 0
		for {
			offset = avgLength - lookBack
			if offset < 1 {
				offset = 1
			}
			if i+offset > mbLen {
				offset = mbLen - i
			}
			chunk := string(runes[i : i+offset])
			chunkEnc = base64.StdEncoding.EncodeToString([]byte(chunk))
			lookBack++
			if len(chunkEnc) <= length || offset <= 1 {
				break
			}
		}
		parts = append(parts, start+chunkEnc+end)
		i += offset
	}
	return strings.Join(parts, "\r\n ")
}

func phpmailerWrapRawB64(b64 string, chunk int, charset string) string {
	start := "=?" + charset + "?B?"
	end := "?="
	var parts []string
	for i := 0; i < len(b64); i += chunk {
		j := i + chunk
		if j > len(b64) {
			j = len(b64)
		}
		parts = append(parts, start+b64[i:j]+end)
	}
	return strings.Join(parts, "\r\n ")
}

func phpmailerWrapQWords(q, charset string) string {
	start := "=?" + charset + "?Q?"
	end := "?="
	max := phpmailerEncodedWordMax - len(start) - len(end)
	if max < 3 {
		max = 3
	}
	var parts []string
	for len(q) > 0 {
		n := max
		if n > len(q) {
			n = len(q)
		}
		n = phpmailerQChunk(q, n)
		if n < 1 {
			n = 1
		}
		parts = append(parts, start+q[:n]+end)
		q = q[n:]
	}
	return strings.Join(parts, "\r\n ")
}

func phpmailerQChunk(q string, n int) int {
	if n >= len(q) {
		return len(q)
	}
	if n >= 1 && q[n-1] == '=' {
		n--
	}
	if n >= 2 && q[n-2] == '=' {
		n -= 2
	}
	if n < 1 {
		return 1
	}
	return n
}
