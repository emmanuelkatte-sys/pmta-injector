package email

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	arc "github.com/rest-mail/go-arc"
	"github.com/rest-mail/go-dkim"

	"__MODULE_PLACEHOLDER__/config"
)

type arcSealer struct {
	domain   string
	selector string
	key      *rsa.PrivateKey
	headers  []string
}

func newArcSealer(cfg *config.Config) *arcSealer {
	if cfg == nil || !cfg.Arc.Enabled {
		return nil
	}
	domain := strings.TrimPrefix(strings.TrimSpace(cfg.Arc.Domain), "@")
	if domain == "" {
		if i := strings.LastIndex(cfg.Sender.FromAddress, "@"); i >= 0 {
			domain = strings.TrimSpace(cfg.Sender.FromAddress[i+1:])
		}
	}
	selector := strings.TrimSpace(cfg.Arc.Selector)
	if selector == "" {
		selector = "dkim"
	}
	if domain == "" || selector == "" {
		return nil
	}
	pem := strings.TrimSpace(cfg.Arc.PrivateKeyPEM)
	if pem == "" {
		path := strings.TrimSpace(cfg.Arc.PrivateKeyPath)
		if path == "" {
			path = defaultArcKeyPath(cfg.MtaType, selector, domain)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		pem = string(raw)
	}
	key, err := dkim.ParsePrivateKey(pem)
	if err != nil {
		return nil
	}
	headers := append([]string(nil), cfg.Headers.DkimSignHeaders...)
	hasFrom := false
	for _, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h), "from") {
			hasFrom = true
			break
		}
	}
	if len(headers) > 0 && !hasFrom {
		headers = append([]string{"from"}, headers...)
	}
	return &arcSealer{domain: domain, selector: selector, key: key, headers: headers}
}

func defaultArcKeyPath(mtaType, selector, domain string) string {
	switch strings.ToLower(strings.TrimSpace(mtaType)) {
	case "zonemta", "zonepmta", "zone-mta":
		return "/opt/zone-mta/keys/dkim-private.pem"
	case "haraka":
		return "/root/haraka/config/dkim/dkim-private-" + domain + ".pem"
	default:
		return "/etc/pmta/private/" + selector + "." + domain + ".private.pem"
	}
}

func (s *arcSealer) seal(raw, envelopeFrom string) string {
	if s == nil || raw == "" {
		return raw
	}
	prefix, rest := peelLeadingControlHeaders(raw)
	mailfrom := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, strings.TrimSpace(envelopeFrom))
	auth := fmt.Sprintf("%s; dkim=pass header.d=%s; spf=pass smtp.mailfrom=%s", s.domain, s.domain, mailfrom)
	res, err := arc.Seal(context.Background(), []byte(rest), arc.SealOptions{
		Domain:      s.domain,
		Selector:    s.selector,
		PrivateKey:  s.key,
		AuthResults: auth,
		Headers:     s.headers,
	})
	if err != nil || res == nil || res.AS == "" || res.AMS == "" || res.AAR == "" {
		return raw
	}
	// Seal 输出单行头；按 RFC 5322 §2.1.1 / §2.2.3 折叠后再拼回原信。
	return prefix + foldArcFieldRFC5322(res.AS) + foldArcFieldRFC5322(res.AMS) + foldArcFieldRFC5322(res.AAR) + rest
}

const (
	rfc5322SoftLine = 78
	rfc5322HardLine = 998
)

// foldArcFieldRFC5322 把 go-arc 的 "Name: value"（无末尾 CRLF）折成 RFC 5322 头。
// 只在已有 WSP（通常是 "; "）处断行，避免 relaxed 规范化改哈希；b= 的 base64 可在
// 签名后插入 FWS（校验时 StripWSP / RemoveBValue）。
func foldArcFieldRFC5322(field string) string {
	field = strings.TrimRight(field, "\r\n")
	if field == "" {
		return ""
	}
	colon := strings.IndexByte(field, ':')
	if colon <= 0 {
		return field + "\r\n"
	}
	name := field[:colon]
	value := strings.TrimLeft(field[colon+1:], " \t")
	return name + ": " + foldArcHeaderValue(value, len(name)+2) + "\r\n"
}

func foldArcHeaderValue(value string, prefixLen int) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if prefixLen+len(value) <= rfc5322SoftLine {
		return value
	}
	var b strings.Builder
	b.Grow(len(value) + 32)
	lineLen := prefixLen
	i := 0
	for i < len(value) {
		remain := value[i:]
		budget := rfc5322SoftLine - lineLen
		if budget < 8 {
			b.WriteString("\r\n ")
			lineLen = 1
			budget = rfc5322SoftLine - 1
			continue
		}
		if len(remain) <= budget {
			b.WriteString(remain)
			break
		}
		if br := rfc5322ArcBreak(remain, budget); br > 0 {
			b.WriteString(remain[:br])
			b.WriteString("\r\n ")
			lineLen = 1
			i += br
			for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
				i++
			}
			continue
		}
		if arcInBValue(value, i) {
			n := budget
			if n > len(remain) {
				n = len(remain)
			}
			if n < 1 {
				n = 1
			}
			b.WriteString(remain[:n])
			i += n
			if i < len(value) {
				b.WriteString("\r\n ")
				lineLen = 1
			}
			continue
		}
		n := strings.IndexAny(remain, " \t")
		if n < 0 {
			n = len(remain)
		}
		if lineLen+n > rfc5322HardLine {
			n = rfc5322HardLine - lineLen
			if n < 1 {
				n = 1
			}
		}
		b.WriteString(remain[:n])
		lineLen += n
		i += n
	}
	return b.String()
}

func rfc5322ArcBreak(s string, budget int) int {
	if budget > len(s) {
		budget = len(s)
	}
	if budget < 2 {
		return -1
	}
	search := s[:budget]
	if idx := strings.LastIndex(search, "; "); idx > 0 {
		return idx + 2
	}
	if idx := strings.LastIndexAny(search, " \t"); idx > 0 {
		return idx + 1
	}
	return -1
}

func arcInBValue(value string, pos int) bool {
	if pos < 0 {
		pos = 0
	}
	if pos > len(value) {
		pos = len(value)
	}
	if strings.HasPrefix(strings.ToLower(value[pos:]), "b=") {
		return true
	}
	tag := value[:pos]
	if i := strings.LastIndex(tag, ";"); i >= 0 {
		tag = tag[i+1:]
	}
	tag = strings.TrimLeft(tag, " \t")
	return len(tag) >= 2 && (tag[0] == 'b' || tag[0] == 'B') && tag[1] == '='
}

// peelLeadingControlHeaders 抽出最前的 PowerMTA 控制头，ARC 密封后仍放回顶部。
func peelLeadingControlHeaders(raw string) (prefix, rest string) {
	rest = raw
	var b strings.Builder
	for {
		name, hdr, next, ok := nextRFC5322Header(rest)
		if !ok {
			break
		}
		switch strings.ToLower(name) {
		case "x-virtual-mta", "x-job":
			b.WriteString(hdr)
			rest = next
		default:
			return b.String(), rest
		}
	}
	return b.String(), rest
}

func nextRFC5322Header(raw string) (name, hdr, rest string, ok bool) {
	if raw == "" {
		return "", "", raw, false
	}
	nl := strings.IndexByte(raw, '\n')
	if nl < 0 {
		return "", "", raw, false
	}
	line := raw[:nl+1]
	if strings.TrimRight(line, "\r\n") == "" {
		return "", "", raw, false
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 || line[0] == ' ' || line[0] == '\t' {
		return "", "", raw, false
	}
	name = strings.TrimSpace(line[:colon])
	end := nl + 1
	for end < len(raw) && (raw[end] == ' ' || raw[end] == '\t') {
		n2 := strings.IndexByte(raw[end:], '\n')
		if n2 < 0 {
			end = len(raw)
			break
		}
		end += n2 + 1
	}
	return name, raw[:end], raw[end:], true
}
