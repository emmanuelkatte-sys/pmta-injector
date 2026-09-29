package email

import (
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"strings"

	"__MODULE_PLACEHOLDER__/config"
)

func apexFromBoundDomain(domain string) string {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return ""
	}
	re := regexp.MustCompile(`(?i)^(mail\d*|email)\.`)
	apex := re.ReplaceAllString(d, "")
	apex = strings.Trim(apex, ".")
	if apex == "" {
		return d
	}
	return apex
}

func unsubHostFromBound(domain string) string {
	apex := apexFromBoundDomain(domain)
	if apex == "" {
		return ""
	}
	return "unsub." + apex
}

func resolveUnsubscribeHost(cfg *config.HeadersConfig, boundDomain, senderEmail string) string {
	if cfg == nil {
		return "unsub.localhost"
	}
	host := strings.TrimSpace(cfg.UnsubscribeHost)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	if host != "" {
		return strings.ToLower(host)
	}
	if boundDomain != "" {
		if h := unsubHostFromBound(boundDomain); h != "" {
			return h
		}
	}
	if i := strings.LastIndex(senderEmail, "@"); i >= 0 {
		if h := unsubHostFromBound(senderEmail[i+1:]); h != "" {
			return h
		}
	}
	return "unsub.localhost"
}

func buildUnsubscribeURL(to, from string, cfg *config.HeadersConfig, boundDomain string) string {
	if cfg == nil || !cfg.ListUnsubscribe {
		return ""
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return ""
	}
	if seed := unsubscribeSeedFromConfig(cfg); seed != "" {
		base := resolveUnsubscribeBaseURL(cfg, boundDomain, from)
		if base != "" {
			link, err := generateCleanLink(to, seed, base)
			if err == nil && link != "" {
				return link
			}
		}
	}
	host := resolveUnsubscribeHost(cfg, boundDomain, from)
	path := strings.TrimSpace(cfg.UnsubscribePath)
	if path == "" {
		path = "/unsubscribe"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	param := strings.TrimSpace(cfg.UnsubscribeQueryParam)
	if param == "" {
		param = "email"
	}
	return fmt.Sprintf("https://%s%s?%s=%s", host, path, param, url.QueryEscape(to))
}

func buildListUnsubscribeHeaderValue(to, from string, cfg *config.HeadersConfig, boundDomain string) string {
	httpsURL := buildUnsubscribeURL(to, from, cfg, boundDomain)
	if httpsURL == "" {
		return ""
	}
	parts := []string{"<" + httpsURL + ">"}
	if unsubIncludeMailto(cfg) {
		mailto := buildUnsubscribeMailto(httpsURL, from, cfg, boundDomain)
		if mailto != "" {
			parts = append(parts, "<"+mailto+">")
		}
	}
	return strings.Join(parts, ", ")
}

func unsubIncludeMailto(_ *config.HeadersConfig) bool {
	return true
}

func buildUnsubscribeMailto(httpsURL, senderEmail string, cfg *config.HeadersConfig, boundDomain string) string {
	if cfg == nil {
		return ""
	}
	addr := resolveUnsubscribeMailAccount(cfg, senderEmail, boundDomain, httpsURL)
	if addr == "" {
		return ""
	}
	return "mailto:" + addr + "?subject=" + url.QueryEscape("unsubscribe")
}

func resolveUnsubscribeMailAccount(cfg *config.HeadersConfig, senderEmail, boundDomain, httpsURL string) string {
	domain := strings.TrimSpace(strings.ToLower(boundDomain))
	if domain == "" && strings.Contains(senderEmail, "@") {
		domain = strings.ToLower(strings.TrimSpace(senderEmail[strings.LastIndex(senderEmail, "@")+1:]))
	}
	if domain == "" {
		domain = mailtoDomainFromConfig(cfg, senderEmail, httpsURL, boundDomain)
	}
	if strings.Contains(senderEmail, "@") {
		return strings.ToLower(strings.TrimSpace(senderEmail))
	}
	user := "umei"
	if domain != "" {
		return strings.ToLower(user + "@" + domain)
	}
	return strings.ToLower(user + "@localhost")
}

func normalizeMailApex(dom string) string {
	dom = strings.TrimSpace(strings.ToLower(dom))
	dom = strings.TrimPrefix(dom, "mailto:")
	if i := strings.Index(dom, "@"); i >= 0 {
		dom = dom[i+1:]
	}
	dom = strings.Split(dom, "?")[0]
	dom = strings.Trim(dom, ".")
	if dom == "" || !strings.Contains(dom, ".") {
		return ""
	}
	return dom
}

func mailtoDomainFromConfig(cfg *config.HeadersConfig, senderEmail, httpsURL, boundDomain string) string {
	if cfg != nil {
		if d := normalizeMailApex(cfg.UnsubscribeMailtoDomain); d != "" {
			return d
		}
	}
	if u, err := url.Parse(httpsURL); err == nil && u.Hostname() != "" {
		if d := normalizeMailApex(apexFromUnsubHost(u.Hostname())); d != "" {
			return d
		}
	}
	return normalizeMailApex(apexFromBoundDomain(boundDomain))
}

func apexFromUnsubHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(strings.Split(host, "/")[0]))
	if strings.HasPrefix(h, "unsub.") {
		return h[5:]
	}
	return apexFromBoundDomain(h)
}

func encodeListUnsubscribeHeader(raw string, cfg *config.HeadersConfig) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if cfg != nil && !cfg.UnsubscribeUseDecimal {
		return foldListUnsubscribePlain(raw, unsubHeaderFoldWidth(cfg))
	}
	return encodeListUnsubscribeQP(raw, unsubHeaderFoldWidth(cfg))
}

func unsubHeaderFoldWidth(cfg *config.HeadersConfig) int {
	w := 76
	if cfg != nil && cfg.UnsubscribeHeaderFoldWidth > 0 {
		w = cfg.UnsubscribeHeaderFoldWidth
	}
	if w < 40 {
		w = 40
	}
	if w > 998 {
		w = 998
	}
	return w
}

func foldListUnsubscribePlain(raw string, foldW int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) <= foldW {
		return raw
	}
	sep := ">, <"
	if i := strings.Index(raw, sep); i >= 0 {
		first := strings.TrimSpace(raw[:i+1])
		second := strings.TrimSpace(raw[i+3:])
		if len(first)+2 <= foldW {
			return first + ",\r\n " + second
		}
	}
	return raw
}

func splitListUnsubSegments(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func encodeMIMEQPWord(raw string) string {
	var b strings.Builder
	b.WriteString("=?us-ascii?Q?")
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == ' ':
			b.WriteByte('_')
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			b.WriteString(fmt.Sprintf("=%02X", c))
		}
	}
	b.WriteString("?=")
	return b.String()
}

func encodeSegmentAsQPWords(seg string, maxLine int) []string {
	if maxLine < 24 {
		maxLine = 24
	}
	enc := encodeMIMEQPWord(seg)
	if len(enc) <= maxLine {
		return []string{enc}
	}
	var words []string
	remaining := seg
	for len(remaining) > 0 {
		lo, hi := 1, len(remaining)
		best := 1
		for lo <= hi {
			mid := (lo + hi) / 2
			trial := encodeMIMEQPWord(remaining[:mid])
			if len(trial) <= maxLine {
				best = mid
				lo = mid + 1
			} else {
				hi = mid - 1
			}
		}
		words = append(words, encodeMIMEQPWord(remaining[:best]))
		remaining = remaining[best:]
	}
	return words
}

func encodeListUnsubscribeQP(raw string, foldW int) string {
	segments := splitListUnsubSegments(raw)
	if len(segments) == 0 {
		return ""
	}
	firstMax := foldW - len("List-Unsubscribe: ") - 2
	if firstMax < 30 {
		firstMax = 30
	}
	contMax := foldW - 1
	limit := firstMax

	var lines []string
	var cur string
	for si, seg := range segments {
		piece := seg
		if si > 0 {
			piece = ", " + seg
		}
		for _, w := range encodeSegmentAsQPWords(piece, limit) {
			if cur == "" {
				if len(w) <= limit {
					cur = w
				} else {
					lines = append(lines, w)
				}
				continue
			}
			combined := cur + " " + w
			if len(combined) <= limit {
				cur = combined
				continue
			}
			lines = append(lines, cur)
			cur = w
			limit = contMax
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\r\n ")
}

// decodeListUnsubscribePlain 将已 QP 编码或明文的 List-Unsubscribe 还原为明文（供后处理兜底）。
func decodeListUnsubscribePlain(folded string) string {
	folded = strings.TrimSpace(folded)
	if folded == "" {
		return ""
	}
	unfolded := strings.Join(strings.FieldsFunc(folded, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), " ")
	if !strings.Contains(strings.ToLower(unfolded), "=?") {
		return unfolded
	}
	dec := &mime.WordDecoder{}
	plain, err := dec.DecodeHeader(unfolded)
	if err != nil || strings.TrimSpace(plain) == "" {
		return unfolded
	}
	return plain
}
