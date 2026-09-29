package email

import (
	"math/rand"
	"sort"
	"strings"
)

// defaultDkimSignHeaders 与 Haraka 默认预设 haraka_rfc6376 对齐（injector 未配置时的兜底）。
var defaultDkimSignHeaders = []string{
	"from", "sender", "to", "cc", "subject", "date", "message-id", "mime-version", "content-type",
}

func normalizeDkimSignHeaders(names []string) []string {
	if len(names) == 0 {
		out := make([]string, len(defaultDkimSignHeaders))
		copy(out, defaultDkimSignHeaders)
		return out
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || name == "received" || name == "dkim-signature" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return normalizeDkimSignHeaders(nil)
	}
	return out
}

func buildDkimSignOrder(names []string) map[string]int {
	order := make(map[string]int, len(names))
	for i, name := range normalizeDkimSignHeaders(names) {
		order[name] = i
	}
	return order
}

func shuffleStringSlice(items []string, r *rand.Rand) {
	for i := len(items) - 1; i > 0; i-- {
		j := safeIntn(r, i+1)
		items[i], items[j] = items[j], items[i]
	}
}

// shuffleHeadersWithAnchors DKIM 对齐的锚定乱序：
//   - Received / 注入器 DKIM-Signature 固定在最前
//   - Haraka 预设签名字段块保持配置顺序（不乱序、不拆分）
//   - 其它头 Fisher-Yates 洗牌后随机分到签名字段块前/后
func shuffleHeadersWithAnchors(headers []string, r *rand.Rand, dkimSignHeaders []string) []string {
	if len(headers) <= 1 {
		return headers
	}

	signOrder := buildDkimSignOrder(dkimSignHeaders)
	maxSignIdx := len(signOrder) - 1

	var received []string
	var dkimSigs []string
	signSlots := make(map[int]string, len(signOrder))
	pool := make([]string, 0, len(headers))
	var listUnsubPost string

	for _, h := range headers {
		name := extractFieldName(h)
		if name == "" {
			pool = append(pool, h)
			continue
		}
		if strings.HasPrefix(name, "received") {
			received = append(received, h)
			continue
		}
		if name == "dkim-signature" {
			dkimSigs = append(dkimSigs, h)
			continue
		}
		if idx, ok := signOrder[name]; ok {
			signSlots[idx] = h
			continue
		}
		if name == "list-unsubscribe-post" {
			listUnsubPost = h
			continue
		}
		pool = append(pool, h)
	}

	signBlock := make([]string, 0, len(signSlots))
	for i := 0; i <= maxSignIdx; i++ {
		if line, ok := signSlots[i]; ok {
			signBlock = append(signBlock, line)
		}
	}

	shuffleStringSlice(pool, r)

	if listUnsubPost != "" {
		insertIdx := -1
		for i, h := range pool {
			if extractFieldName(h) == "list-unsubscribe" {
				insertIdx = i + 1
				break
			}
		}
		if insertIdx >= 0 {
			newPool := make([]string, 0, len(pool)+1)
			newPool = append(newPool, pool[:insertIdx]...)
			newPool = append(newPool, listUnsubPost)
			newPool = append(newPool, pool[insertIdx:]...)
			pool = newPool
		} else {
			pool = append(pool, listUnsubPost)
		}
	}

	prefix := make([]string, 0, len(pool))
	suffix := make([]string, 0, len(pool))
	for _, h := range pool {
		if safeIntn(r, 2) == 0 {
			prefix = append(prefix, h)
		} else {
			suffix = append(suffix, h)
		}
	}

	result := make([]string, 0, len(headers))
	result = append(result, received...)
	result = append(result, dkimSigs...)
	result = append(result, prefix...)
	result = append(result, signBlock...)
	result = append(result, suffix...)
	return result
}

// shuffleHeadersLegacy 旧版锚定乱序（无 DKIM 签名字段表时使用）。
func shuffleHeadersLegacy(headers []string, r *rand.Rand) []string {
	if len(headers) <= 1 {
		return headers
	}

	type anchoredHeader struct {
		line      string
		priority  int
		origIndex int
	}
	anchors := make([]anchoredHeader, 0, len(headers))
	pool := make([]string, 0, len(headers))
	var listUnsubPost string

	for i, h := range headers {
		name := extractFieldName(h)
		if name == "" {
			pool = append(pool, h)
			continue
		}
		if strings.HasPrefix(name, "received") {
			anchors = append(anchors, anchoredHeader{h, anchorPriority["received"], i})
			continue
		}
		if prio, ok := anchorPriority[name]; ok {
			anchors = append(anchors, anchoredHeader{h, prio, i})
			continue
		}
		if name == "list-unsubscribe-post" {
			listUnsubPost = h
			continue
		}
		pool = append(pool, h)
	}

	shuffleStringSlice(pool, r)

	if listUnsubPost != "" {
		insertIdx := -1
		for i, h := range pool {
			if extractFieldName(h) == "list-unsubscribe" {
				insertIdx = i + 1
				break
			}
		}
		if insertIdx >= 0 {
			newPool := make([]string, 0, len(pool)+1)
			newPool = append(newPool, pool[:insertIdx]...)
			newPool = append(newPool, listUnsubPost)
			newPool = append(newPool, pool[insertIdx:]...)
			pool = newPool
		} else {
			pool = append(pool, listUnsubPost)
		}
	}

	sort.SliceStable(anchors, func(i, j int) bool {
		if anchors[i].priority != anchors[j].priority {
			return anchors[i].priority < anchors[j].priority
		}
		return anchors[i].origIndex < anchors[j].origIndex
	})

	result := make([]string, 0, len(headers))
	for _, a := range anchors {
		result = append(result, a.line)
	}
	result = append(result, pool...)
	return result
}
