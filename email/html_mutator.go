package email

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"__MODULE_PLACEHOLDER__/config"
)

var (
	// 仅微扰不影响背景色与布局对齐的属性
	cssJitterPropRe = regexp.MustCompile(`(?i)\b(font-size|line-height|letter-spacing|margin-top|margin-bottom)\s*:\s*([#]?[\d.a-fA-F]+%?)(px|em|rem|%)?`)
	openTagRe       = regexp.MustCompile(`(?i)^<\s*([a-zA-Z][a-zA-Z0-9:-]*)\s*([^>/]*?)\s*/?\s*>$`)
)

var voidTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

var skipInjectTags = map[string]bool{
	"a": true, "img": true, "script": true, "style": true, "link": true, "meta": true,
}

var tableTags = map[string]bool{
	"table": true, "thead": true, "tbody": true, "tfoot": true,
	"tr": true, "td": true, "th": true, "col": true, "colgroup": true, "caption": true,
}

// MutateHTML applies per-recipient HTML fingerprint breaking on rendered template HTML.
func MutateHTML(input string, cfg config.HtmlMutatorConfig, seed string) string {
	if !cfg.Enabled || strings.TrimSpace(input) == "" || !isHTMLContent(input) {
		return input
	}
	rng := rand.New(rand.NewSource(hashSeed(seed)))
	out := input
	if cfg.CssJitter {
		out = jitterInlineCSS(out, rng)
	}
	if cfg.InjectAttrs || cfg.TagSwap {
		out = mutateTags(out, cfg, rng)
	}
	return out
}

func hashSeed(seed string) int64 {
	sum := sha256.Sum256([]byte(seed))
	return int64(binary.LittleEndian.Uint64(sum[:8]))
}

func jitterInlineCSS(html string, rng *rand.Rand) string {
	return cssJitterPropRe.ReplaceAllStringFunc(html, func(match string) string {
		parts := cssJitterPropRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		prop, value, unit := parts[1], parts[2], parts[3]
		propLower := strings.ToLower(prop)
		num, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return match
		}
		jittered := jitterNumber(propLower, num, unit, rng)
		if unit == "%" {
			return fmt.Sprintf("%s:%s%s", prop, formatFloat(jittered), unit)
		}
		if unit != "" {
			return fmt.Sprintf("%s:%s%s", prop, formatFloat(jittered), unit)
		}
		return fmt.Sprintf("%s:%s", prop, formatFloat(jittered))
	})
}

func jitterNumber(prop string, num float64, unit string, rng *rand.Rand) float64 {
	delta := 0.0
	switch {
	case prop == "line-height" && unit == "":
		delta = (rng.Float64()*0.04 - 0.02)
	case prop == "font-size":
		delta = rng.Float64()*0.4 - 0.2
	case prop == "letter-spacing":
		delta = rng.Float64()*0.2 - 0.1
	case prop == "margin-top" || prop == "margin-bottom":
		delta = rng.Float64()*0.8 - 0.4
	default:
		return num
	}
	out := num + delta
	if out < 0 {
		out = 0
	}
	if unit == "" && prop == "line-height" {
		return math.Round(out*1000) / 1000
	}
	return math.Round(out*10) / 10
}

func formatFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

func mutateTags(html string, cfg config.HtmlMutatorConfig, rng *rand.Rand) string {
	var out strings.Builder
	tableDepth := 0
	var pSwapStack []bool
	i := 0
	for i < len(html) {
		if html[i] != '<' {
			j := strings.IndexByte(html[i:], '<')
			if j < 0 {
				out.WriteString(html[i:])
				break
			}
			out.WriteString(html[i : i+j])
			i += j
			continue
		}
		j := strings.IndexByte(html[i:], '>')
		if j < 0 {
			out.WriteString(html[i:])
			break
		}
		tagToken := html[i : i+j+1]
		i += j + 1

		if strings.HasPrefix(tagToken, "<!--") {
			out.WriteString(tagToken)
			continue
		}
		if strings.HasPrefix(tagToken, "<!") || strings.HasPrefix(tagToken, "<?") {
			out.WriteString(tagToken)
			continue
		}

		closing := strings.HasPrefix(tagToken, "</")
		selfClosing := strings.HasSuffix(strings.TrimSpace(tagToken), "/>") || isVoidOpenTag(tagToken)
		tagName := parseTagName(tagToken)
		tagLower := strings.ToLower(tagName)

		if closing {
			if cfg.PreserveTables && tableTags[tagLower] {
				tableDepth--
				if tableDepth < 0 {
					tableDepth = 0
				}
			}
			if cfg.TagSwap && tagLower == "p" && len(pSwapStack) > 0 {
				swapped := pSwapStack[len(pSwapStack)-1]
				pSwapStack = pSwapStack[:len(pSwapStack)-1]
				if swapped {
					out.WriteString("</div>")
					continue
				}
			}
			out.WriteString(tagToken)
			continue
		}

		if cfg.PreserveTables && tagLower == "table" {
			tableDepth++
		}

		mutated := tagToken
		swappedP := false
		// p→div 在表格单元格内同样生效；不把 table/tr/td 改成 div
		if cfg.TagSwap && tagLower == "p" {
			swappedP = rng.Intn(2) == 0
			if swappedP {
				mutated = replaceTagName(mutated, "p", "div")
			}
			pSwapStack = append(pSwapStack, swappedP)
		}
		if cfg.InjectAttrs && !skipInjectTags[tagLower] && !selfClosing {
			mutated = injectAttrs(mutated, rng)
		}
		if (cfg.InjectAttrs || cfg.TagSwap) && tableTags[tagLower] && !selfClosing {
			mutated = injectTableLayoutAttrs(mutated, tagLower, rng)
		}
		out.WriteString(mutated)
	}
	return out.String()
}

func parseTagName(tagToken string) string {
	token := strings.TrimSpace(tagToken)
	token = strings.TrimPrefix(token, "<")
	token = strings.TrimPrefix(token, "/")
	if idx := strings.IndexAny(token, " \t\r\n>/"); idx >= 0 {
		token = token[:idx]
	}
	return strings.TrimSuffix(token, "/")
}

func isVoidOpenTag(tagToken string) bool {
	name := strings.ToLower(parseTagName(tagToken))
	return voidTags[name]
}

func replaceTagName(tagToken, from, to string) string {
	fromLower := strings.ToLower(from)
	token := tagToken
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(token)), "<"+fromLower) {
		idx := strings.Index(token, from)
		if idx >= 0 {
			return token[:idx] + to + token[idx+len(from):]
		}
	}
	return token
}

func injectAttrs(tagToken string, rng *rand.Rand) string {
	m := openTagRe.FindStringSubmatch(strings.TrimSpace(tagToken))
	if len(m) < 3 {
		return tagToken
	}
	tagName, attrs := m[1], strings.TrimSpace(m[2])
	if attrs == "/" {
		attrs = ""
	}
	selfClose := strings.HasSuffix(tagToken, "/>")
	parts := []string{attrs}
	if rng.Intn(2) == 0 {
		parts = append(parts, fmt.Sprintf(`data-x="%s"`, randomToken(rng, 6)))
	}
	if rng.Intn(2) == 0 {
		parts = append(parts, fmt.Sprintf(`class="c-%s"`, randomToken(rng, 5)))
	}
	if rng.Intn(3) == 0 {
		parts = append(parts, fmt.Sprintf(`id="n-%s"`, randomToken(rng, 5)))
	}
	newAttrs := strings.TrimSpace(strings.Join(parts, " "))
	if selfClose {
		return fmt.Sprintf("<%s %s/>", tagName, newAttrs)
	}
	return fmt.Sprintf("<%s %s>", tagName, newAttrs)
}

func injectTableLayoutAttrs(tagToken, tagLower string, rng *rand.Rand) string {
	lower := strings.ToLower(tagToken)
	var extra []string
	switch tagLower {
	case "table":
		if !strings.Contains(lower, "role=") && rng.Intn(2) == 0 {
			extra = append(extra, `role="presentation"`)
		}
		if !strings.Contains(lower, "cellpadding=") && rng.Intn(2) == 0 {
			extra = append(extra, fmt.Sprintf(`cellpadding="%d"`, rng.Intn(2)))
		}
		if !strings.Contains(lower, "cellspacing=") && rng.Intn(2) == 0 {
			extra = append(extra, fmt.Sprintf(`cellspacing="%d"`, rng.Intn(2)))
		}
		if !strings.Contains(lower, "border=") && rng.Intn(2) == 0 {
			extra = append(extra, `border="0"`)
		}
	case "td", "th":
		if !strings.Contains(lower, "valign=") && rng.Intn(3) == 0 {
			extra = append(extra, `valign="top"`)
		}
	}
	if len(extra) == 0 {
		return tagToken
	}
	selfClose := strings.HasSuffix(strings.TrimSpace(tagToken), "/>")
	core := strings.TrimSuffix(strings.TrimSpace(tagToken), ">")
	core = strings.TrimSuffix(core, "/")
	core = strings.TrimSpace(core)
	joined := strings.Join(extra, " ")
	if selfClose {
		return core + " " + joined + "/>"
	}
	return core + " " + joined + ">"
}

func randomToken(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	if n <= 0 {
		n = 6
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}
