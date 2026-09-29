package email

// =============================================================================
// 【2026-05-27 从 PowerMTA 移植】53 个扩展变量的实现
//   A. RFC 2822 时间变量（13 个）—— Mon, 22 May 2026 18:23:47 +0900 类
//   B. ID 类变量（8 个）—— queue/postfix/gmail/bounce 等真实 MTA 格式
//   C. IP 池变量（10 个）—— 雅虎/软银/docomo/AWS SES 等专用池
//   D. 域名池变量（15 个）—— 各大邮件商内部域名池
//   E. SMTP/TLS 协议变量（6 个）—— TLS 版本/cipher/MTA banner
//   F. JWT 变量（1 个）—— 完整 3 段 JWT
//
// 设计原则：
//   - 所有随机源走 vp.random（每 worker 独立，与 v62 修复保持一致）
//   - 参数化变量先处理（正则），无参变量后处理（map 字面替换）
//   - 全部支持大小写双形式（大写池 + 小写池一并替换）
//   - LoadLocation 失败 graceful 回退 UTC（不 panic）
//   - 不嵌套其他变量（避免循环替换）
// =============================================================================

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 预编译正则（启动时一次构造，并发安全）
// ============================================================================

var (
	// A 组 参数化时间变量
	reRFC2822TZ       = regexp.MustCompile(`(?i)\{RFC2822_DATE_TZ:([A-Za-z][A-Za-z0-9_/+\-]+)\}`)
	reRFC2822Offset   = regexp.MustCompile(`(?i)\{RFC2822_DATE_OFFSET:([+\-]\d{4})\}`)
	reRFC2822PastSec  = regexp.MustCompile(`(?i)\{RFC2822_DATE_PAST_SEC:(\d+)\}`)
	reRFC2822PastRand = regexp.MustCompile(`(?i)\{RFC2822_DATE_PAST_RAND:(\d+)-(\d+)\}`)

	// B 组 参数化 ID 变量
	reIDQueue = regexp.MustCompile(`(?i)\{ID_QUEUE:(\d+)\}`)
	reIDHex   = regexp.MustCompile(`(?i)\{ID_HEX:(\d+)\}`)
)

// ============================================================================
// 时区常量（FixedZone 不依赖系统 tzdata，线程安全）
// ============================================================================

var (
	extTzJST = time.FixedZone("JST", 9*3600)
	extTzGMT = time.FixedZone("GMT", 0)
	extTzPST = time.FixedZone("PST", -8*3600)
	extTzPDT = time.FixedZone("PDT", -7*3600)
	extTzEST = time.FixedZone("EST", -5*3600)
	extTzCET = time.FixedZone("CET", 1*3600)
)

const rfc2822LayoutBase = "Mon, 02 Jan 2006 15:04:05 -0700"

// tzCache 缓存 LoadLocation 解析结果，避免每封邮件反复解析
// 并发安全（sync.Map 内部读多写少场景已优化）
var tzCache sync.Map // map[string]*time.Location

// loadLocationCached 缓存版 LoadLocation；失败返回 UTC（避免 panic）
func loadLocationCached(name string) *time.Location {
	if v, ok := tzCache.Load(name); ok {
		return v.(*time.Location)
	}
	loc, err := time.LoadLocation(name)
	if err != nil || loc == nil {
		// 失败回退 UTC（不 panic，graceful 降级）
		tzCache.Store(name, time.UTC)
		return time.UTC
	}
	tzCache.Store(name, loc)
	return loc
}

// ============================================================================
// 总入口：processExtendedVariables
// 由 variables.go::Process() 在所有现有步骤之后调用（步骤 10）
// 顺序：A → B → C → D → E → F
// ============================================================================

func (vp *VariableProcessor) processExtendedVariables(content string) string {
	if content == "" {
		return content
	}
	// A 时间（参数化先 → 字面后）
	content = vp.processRFC2822Variables(content)
	// B ID
	content = vp.processIDVariables(content)
	// C IP 池
	content = vp.processExtIPVariables(content)
	// D 域名池
	content = vp.processExtDomainVariables(content)
	// E SMTP/TLS 协议
	content = vp.processProtocolVariables(content)
	// F JWT
	content = vp.processJWTVariables(content)
	return content
}

// ============================================================================
// A. RFC 2822 时间变量（13 个）
// ============================================================================

func (vp *VariableProcessor) processRFC2822Variables(content string) string {
	now := time.Now()

	// === 参数化（必须先处理，避免后续字面替换误伤）===

	// {RFC2822_DATE_TZ:Asia/Tokyo}
	content = reRFC2822TZ.ReplaceAllStringFunc(content, func(match string) string {
		sub := reRFC2822TZ.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		loc := loadLocationCached(sub[1])
		return now.In(loc).Format(rfc2822LayoutBase)
	})

	// {RFC2822_DATE_OFFSET:+0900}
	content = reRFC2822Offset.ReplaceAllStringFunc(content, func(match string) string {
		sub := reRFC2822Offset.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		offsetStr := sub[1] // +0900 / -0700
		sign := 1
		if offsetStr[0] == '-' {
			sign = -1
		}
		hh, _ := strconv.Atoi(offsetStr[1:3])
		mm, _ := strconv.Atoi(offsetStr[3:5])
		secs := sign * (hh*3600 + mm*60)
		loc := time.FixedZone(offsetStr, secs)
		return now.In(loc).Format(rfc2822LayoutBase)
	})

	// {RFC2822_DATE_PAST_SEC:30}
	content = reRFC2822PastSec.ReplaceAllStringFunc(content, func(match string) string {
		sub := reRFC2822PastSec.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		secs, _ := strconv.Atoi(sub[1])
		t := now.Add(-time.Duration(secs) * time.Second).In(extTzJST)
		return t.Format(rfc2822LayoutBase)
	})

	// {RFC2822_DATE_PAST_RAND:1-3600}
	content = reRFC2822PastRand.ReplaceAllStringFunc(content, func(match string) string {
		sub := reRFC2822PastRand.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		minS, _ := strconv.Atoi(sub[1])
		maxS, _ := strconv.Atoi(sub[2])
		if maxS < minS {
			maxS = minS
		}
		gap := maxS - minS + 1
		offset := minS + safeIntn(vp.random, gap)
		t := now.Add(-time.Duration(offset) * time.Second).In(extTzJST)
		return t.Format(rfc2822LayoutBase)
	})

	// === 字面变量（无参，map 替换；大写+小写各替换一遍）===
	replacements := map[string]string{
		"{RFC2822_DATE}":          now.In(extTzJST).Format(rfc2822LayoutBase),
		"{RFC2822_DATE_JST}":      now.In(extTzJST).Format(rfc2822LayoutBase),
		"{RFC2822_DATE_UTC}":      now.UTC().Format(rfc2822LayoutBase),
		"{RFC2822_DATE_GMT}":      now.In(extTzGMT).Format(rfc2822LayoutBase) + " (GMT)",
		"{RFC2822_DATE_PST}":      now.In(extTzPST).Format(rfc2822LayoutBase),
		"{RFC2822_DATE_PDT}":      now.In(extTzPDT).Format(rfc2822LayoutBase) + " (PDT)",
		"{RFC2822_DATE_EST}":      now.In(extTzEST).Format(rfc2822LayoutBase),
		"{RFC2822_DATE_CET}":      now.In(extTzCET).Format(rfc2822LayoutBase),
		"{RFC2822_DATE_WITH_JST}": now.In(extTzJST).Format(rfc2822LayoutBase) + " (JST)",
	}
	for k, v := range replacements {
		content = strings.ReplaceAll(content, k, v)
		content = strings.ReplaceAll(content, strings.ToLower(k), v)
	}
	return content
}

// ============================================================================
// B. ID 变量（8 个）
// ============================================================================

const (
	charsetUpperNum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLowerNum   = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetHex        = "0123456789abcdef"
	charsetBase62     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charsetUpperOnly  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetUpperNum26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" // 26 字母+10 数字
)

func (vp *VariableProcessor) randStringFrom(n int, charset string) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[safeIntn(vp.random, len(charset))]
	}
	return string(b)
}

func (vp *VariableProcessor) processIDVariables(content string) string {
	// 参数化先处理
	// {ID_QUEUE:N} - N 位大写字母+数字（Postfix queue ID 风格）
	content = reIDQueue.ReplaceAllStringFunc(content, func(match string) string {
		sub := reIDQueue.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		n, _ := strconv.Atoi(sub[1])
		if n < 1 {
			n = 11
		}
		if n > 64 {
			n = 64
		}
		return vp.randStringFrom(n, charsetUpperNum)
	})

	// {ID_HEX:N} - N 位 hex
	content = reIDHex.ReplaceAllStringFunc(content, func(match string) string {
		sub := reIDHex.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		n, _ := strconv.Atoi(sub[1])
		if n < 1 {
			n = 16
		}
		if n > 256 {
			n = 256
		}
		return vp.randStringFrom(n, charsetHex)
	})

	// 字面变量（每次生成都不同，map 替换不能用——需逐个 ReplaceAllStringFunc）
	// {ID_POSTFIX_LONG} - 22 字符 base62（4gMhJq3dVszLldv 风）
	content = vp.replaceLiteral(content, "{ID_POSTFIX_LONG}", func() string {
		return vp.randStringFrom(22, charsetBase62)
	})

	// {ID_GMAIL} - Gmail SMTPSA id 风：12 hex `-` 11 hex `sm` 11-13 数字 `.` 1-2 数字
	content = vp.replaceLiteral(content, "{ID_GMAIL}", func() string {
		nDigit := 11 + safeIntn(vp.random, 3) // 11-13
		nTail := 1 + safeIntn(vp.random, 2)   // 1-2
		return fmt.Sprintf("%s-%ssm%s.%s",
			vp.randStringFrom(12, charsetHex),
			vp.randStringFrom(11, charsetHex),
			vp.randStringFrom(nDigit, "0123456789"),
			vp.randStringFrom(nTail, "0123456789"))
	})

	// {ID_BOUNCE_TOKEN} - bounce-{26 大写+数字}.{5 数字} 风
	content = vp.replaceLiteral(content, "{ID_BOUNCE_TOKEN}", func() string {
		return vp.randStringFrom(26, charsetUpperNum26) + "." + vp.randStringFrom(5, "0123456789")
	})

	// {ID_AMAZON_SES} - SES Message-ID 风：{16}-{8}-{4}-{4}-{4}-{12}-{6}
	content = vp.replaceLiteral(content, "{ID_AMAZON_SES}", func() string {
		return fmt.Sprintf("%s-%s-%s-%s-%s-%s-%s",
			vp.randStringFrom(16, charsetHex),
			vp.randStringFrom(8, charsetHex),
			vp.randStringFrom(4, charsetHex),
			vp.randStringFrom(4, charsetHex),
			vp.randStringFrom(4, charsetHex),
			vp.randStringFrom(12, charsetHex),
			vp.randStringFrom(6, "0123456789"))
	})

	// {ID_BICCAMERA} - 12 字符小写字母+数字
	content = vp.replaceLiteral(content, "{ID_BICCAMERA}", func() string {
		return vp.randStringFrom(12, charsetLowerNum)
	})

	// {ID_EXIM_QUEUE} - Exim queue ID 风：1{6-7 base62}-{6 base62}-{2 base62}
	// 例：1mAxYz-0001QX-Bz / 1nQa3B4-Z9X8Cv-Ab
	content = vp.replaceLiteral(content, "{ID_EXIM_QUEUE}", func() string {
		mid := 6 + safeIntn(vp.random, 2) // 6-7 字符
		return fmt.Sprintf("1%s-%s-%s",
			vp.randStringFrom(mid, charsetBase62),
			vp.randStringFrom(6, charsetBase62),
			vp.randStringFrom(2, charsetBase62))
	})

	return content
}

// replaceLiteral 将 content 中所有出现的 token（大写 + 小写双形式）替换为 gen() 的输出
// 每次替换都调用 gen()，使每个实例都不同（不像 strings.ReplaceAll 那样全用同一个值）
func (vp *VariableProcessor) replaceLiteral(content, token string, gen func() string) string {
	for _, t := range []string{token, strings.ToLower(token)} {
		for {
			idx := strings.Index(content, t)
			if idx < 0 {
				break
			}
			content = content[:idx] + gen() + content[idx+len(t):]
		}
	}
	return content
}

// ============================================================================
// C. IP 池变量（10 个）
// ============================================================================

// gmailGwIPRanges Gmail / Google 出口段（部分知名段）
var gmailGwIPRanges = [][2]int{
	{209, 85},  // 209.85.x.x
	{74, 125},  // 74.125.x.x
	{173, 194}, // 173.194.x.x
	{64, 233},  // 64.233.x.x
	{72, 14},   // 72.14.x.x
	{216, 58},  // 216.58.x.x
}

// awsSesIPRanges AWS SES 已知出口段第一/第二段
var awsSesIPRanges = [][2]int{
	{23, 249},  // 23.249.x.x
	{54, 240},  // 54.240.x.x
	{199, 255}, // 199.255.x.x
	{207, 171}, // 207.171.x.x
	{52, 95},   // 52.95.x.x
	{76, 223},  // 76.223.x.x
}

func (vp *VariableProcessor) processExtIPVariables(content string) string {
	// {IP_YAHOO_JP} - 复用 headers.go 的 randomYahooIP（已 init() 校验过 CIDR 池）
	content = vp.replaceLiteral(content, "{IP_YAHOO_JP}", func() string {
		return randomYahooIP(vp.random)
	})

	// {IP_SOFTBANK_172} - 复用 randomSoftbank172IP
	content = vp.replaceLiteral(content, "{IP_SOFTBANK_172}", func() string {
		return randomSoftbank172IP(vp.random)
	})

	// {IP_DOCOMO_INTERNAL} - 10.200.x.x 内部段
	content = vp.replaceLiteral(content, "{IP_DOCOMO_INTERNAL}", func() string {
		return fmt.Sprintf("10.200.%d.%d", safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	// {IP_GMAIL_GW} - Google 出口段
	content = vp.replaceLiteral(content, "{IP_GMAIL_GW}", func() string {
		r := gmailGwIPRanges[safeIntn(vp.random, len(gmailGwIPRanges))]
		return fmt.Sprintf("%d.%d.%d.%d", r[0], r[1], safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	// {IP_PRIVATE_10} - 10.x.x.x
	content = vp.replaceLiteral(content, "{IP_PRIVATE_10}", func() string {
		return fmt.Sprintf("10.%d.%d.%d", safeIntn(vp.random, 256), safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	// {IP_PRIVATE_172} - 172.16-31.x.x
	content = vp.replaceLiteral(content, "{IP_PRIVATE_172}", func() string {
		return fmt.Sprintf("172.%d.%d.%d", 16+safeIntn(vp.random, 16), safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	// {IP_PRIVATE_192} - 192.168.x.x
	content = vp.replaceLiteral(content, "{IP_PRIVATE_192}", func() string {
		return fmt.Sprintf("192.168.%d.%d", safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	// {IP_LOOPBACK} - 127.0.0.1
	content = vp.replaceLiteral(content, "{IP_LOOPBACK}", func() string {
		return "127.0.0.1"
	})

	// {IP_PUBLIC_GLOBAL} - 全球公网随机（复用 headers.go::randomPublicIP）
	content = vp.replaceLiteral(content, "{IP_PUBLIC_GLOBAL}", func() string {
		return randomPublicIP(vp.random)
	})

	// {IP_AWS_SES} - AWS SES 已知出口段
	content = vp.replaceLiteral(content, "{IP_AWS_SES}", func() string {
		r := awsSesIPRanges[safeIntn(vp.random, len(awsSesIPRanges))]
		return fmt.Sprintf("%d.%d.%d.%d", r[0], r[1], safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
	})

	return content
}

// ============================================================================
// D. 域名池变量（15 个）
// ============================================================================

// yahooMxByPatterns 雅虎 MX 域名风格池（覆盖 mta/mtaat + otm/snz + ynwp/gm）
type yahooMxPattern struct {
	tpl      string
	numFmt   string
	startNum int
	endNum   int
}

var yahooMxPatterns = []yahooMxPattern{
	{"mta%04d.mail.otm.ynwp.yahoo.co.jp", "%04d", 1, 9999},
	{"mta%04d.mail.snz.ynwp.yahoo.co.jp", "%04d", 1, 9999},
	{"mtaat%04d.mail.otm.ynwp.yahoo.co.jp", "%04d", 1, 9999},
	{"mtaat%04d.mail.snz.ynwp.yahoo.co.jp", "%04d", 1, 9999},
	{"mta%03d.kks.gm.yahoo.co.jp", "%03d", 1, 600},
	{"mta%03d.ssk.gm.yahoo.co.jp", "%03d", 1, 600},
	{"mta%03d.kth.gm.yahoo.co.jp", "%03d", 1, 600},
}

var yahooEhloSubsExt = []string{"kks", "kth", "ssk"}

// gmailOutDomainPool Gmail 出站域名池
var gmailOutDomainPool = []string{
	"smtp.gmail.com",
	"mail-yw1-f%d.google.com",
	"mail-ed1-f%d.google.com",
	"mail-pl1-f%d.google.com",
	"mail-lf1-f%d.google.com",
	"mail-pf1-f%d.google.com",
	"mail-pj1-f%d.google.com",
	"mail-ot1-f%d.google.com",
	"mail-qk1-f%d.google.com",
	"mail-vk1-f%d.google.com",
}

// mitsuiDomainPool 三井相关域名池
var mitsuiDomainPool = []string{
	"mail.vpass.ne.jp",
	"mail.smbc.co.jp",
	"mta.contact.vpass.ne.jp",
	"smtp.smbc.co.jp",
	"mta1.contact.vpass.ne.jp",
	"mta2.contact.vpass.ne.jp",
}

// amazonSesOutDomainSuffixPool SES 出口主机前缀字符集
var amazonSesPrefixPool = []string{
	"a8-", "a10-", "a12-", "a15-", "a23-", "a28-", "a30-", "a45-", "a48-", "a52-",
	"e23-", "e45-",
}

func (vp *VariableProcessor) processExtDomainVariables(content string) string {
	// {DOMAIN_YAHOO_MX} - 7 种范式随机抽
	content = vp.replaceLiteral(content, "{DOMAIN_YAHOO_MX}", func() string {
		p := yahooMxPatterns[safeIntn(vp.random, len(yahooMxPatterns))]
		num := p.startNum + safeIntn(vp.random, p.endNum-p.startNum+1)
		return fmt.Sprintf(p.tpl, num)
	})

	// {DOMAIN_YAHOO_EHLO} - mta{001-600}.{kks|kth|ssk}.gm.yahoo.co.jp
	content = vp.replaceLiteral(content, "{DOMAIN_YAHOO_EHLO}", func() string {
		sub := yahooEhloSubsExt[safeIntn(vp.random, len(yahooEhloSubsExt))]
		num := 1 + safeIntn(vp.random, 600)
		return fmt.Sprintf("mta%03d.%s.gm.yahoo.co.jp", num, sub)
	})

	// {DOMAIN_YAHOO_GW} - smtp-gw-f{XX}h{XX}c{XX}.prod.goats.kks.ynwl.yahoo.co.jp
	content = vp.replaceLiteral(content, "{DOMAIN_YAHOO_GW}", func() string {
		f := safeIntn(vp.random, 100)  // 0-99
		h := safeIntn(vp.random, 1000) // 0-999
		c := safeIntn(vp.random, 100)  // 0-99
		return fmt.Sprintf("smtp-gw-f%02dh%03dc%02d.prod.goats.kks.ynwl.yahoo.co.jp", f, h, c)
	})

	// {DOMAIN_GMAIL_OUT} - Gmail 出站域池
	content = vp.replaceLiteral(content, "{DOMAIN_GMAIL_OUT}", func() string {
		tpl := gmailOutDomainPool[safeIntn(vp.random, len(gmailOutDomainPool))]
		if strings.Contains(tpl, "%d") {
			return fmt.Sprintf(tpl, 1+safeIntn(vp.random, 200))
		}
		return tpl
	})

	// {DOMAIN_GMAIL_HOST} - server-{ip-dashed}.da.direct（IP 内部生成，dash 格式）
	content = vp.replaceLiteral(content, "{DOMAIN_GMAIL_HOST}", func() string {
		return fmt.Sprintf("server-%d-%d-%d-%d.da.direct",
			1+safeIntn(vp.random, 222),
			safeIntn(vp.random, 256),
			safeIntn(vp.random, 256),
			1+safeIntn(vp.random, 254))
	})

	// {DOMAIN_DOCOMO_BILL} - mail{1-10}.docomo-bill.ne.jp
	content = vp.replaceLiteral(content, "{DOMAIN_DOCOMO_BILL}", func() string {
		return fmt.Sprintf("mail%d.docomo-bill.ne.jp", 1+safeIntn(vp.random, 10))
	})

	// {DOMAIN_DOCOMO_LOCAL} - localhost.docomo.ne.jp（固定）
	content = vp.replaceLiteral(content, "{DOMAIN_DOCOMO_LOCAL}", func() string {
		return "localhost.docomo.ne.jp"
	})

	// {DOMAIN_DOCOMO_MFSMAX} - mfsmax.docomo.ne.jp（固定）
	content = vp.replaceLiteral(content, "{DOMAIN_DOCOMO_MFSMAX}", func() string {
		return "mfsmax.docomo.ne.jp"
	})

	// {DOMAIN_SOFTBANK_EBMKY} - ebmky{101-150}sc.softbank.ad.jp（与 ESP Received softbank 一致）
	content = vp.replaceLiteral(content, "{DOMAIN_SOFTBANK_EBMKY}", func() string {
		return fmt.Sprintf("ebmky%dsc.softbank.ad.jp", 101+safeIntn(vp.random, 50))
	})

	// {DOMAIN_AU} - mta-snd-e{01-99}.au.com（与 ESP Received au 一致）
	content = vp.replaceLiteral(content, "{DOMAIN_AU}", func() string {
		return fmt.Sprintf("mta-snd-e%02d.au.com", 1+safeIntn(vp.random, 99))
	})

	// {DOMAIN_MITSUI} - 三井相关域名池随机
	content = vp.replaceLiteral(content, "{DOMAIN_MITSUI}", func() string {
		return mitsuiDomainPool[safeIntn(vp.random, len(mitsuiDomainPool))]
	})

	// {DOMAIN_BICCAMERA} - mta{1-15}.ml.biccamera.com
	content = vp.replaceLiteral(content, "{DOMAIN_BICCAMERA}", func() string {
		return fmt.Sprintf("mta%d.ml.biccamera.com", 1+safeIntn(vp.random, 15))
	})

	// {DOMAIN_YODOBASHI} - yctcue{01-99}.yodobashi.co.jp
	content = vp.replaceLiteral(content, "{DOMAIN_YODOBASHI}", func() string {
		return fmt.Sprintf("yctcue%02d.yodobashi.co.jp", 1+safeIntn(vp.random, 99))
	})

	// {DOMAIN_LTIKE} - md{1-10}.l-tike.com
	content = vp.replaceLiteral(content, "{DOMAIN_LTIKE}", func() string {
		return fmt.Sprintf("md%d.l-tike.com", 1+safeIntn(vp.random, 10))
	})

	// {DOMAIN_AMAZONSES_OUT} - {a/e prefix}-{4-8 字符}.smtp-out.amazonses.com
	content = vp.replaceLiteral(content, "{DOMAIN_AMAZONSES_OUT}", func() string {
		pref := amazonSesPrefixPool[safeIntn(vp.random, len(amazonSesPrefixPool))]
		tail := vp.randStringFrom(4+safeIntn(vp.random, 5), charsetLowerNum)
		return fmt.Sprintf("%s%s.smtp-out.amazonses.com", pref, tail)
	})

	return content
}

// ============================================================================
// E. SMTP/TLS 协议变量（6 个）
// ============================================================================

var (
	tlsVersionPool = []string{"TLS1_3", "TLS1_2"}
	tlsCipherPool  = []string{
		// TLS 1.3 ciphers（短名）
		"TLS_AES_256_GCM_SHA384",
		"TLS_AES_128_GCM_SHA256",
		"TLS_CHACHA20_POLY1305_SHA256",
		// TLS 1.2 ciphers
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305",
	}
	tlsBitsPool       = []string{"256/256", "128/128", "256/128"}
	smtpProtocolPool  = []string{"ESMTP", "ESMTPS", "ESMTPSA", "SMTP"}
	mtaTypePool       = []string{"Postfix", "sendmail", "Exim"}
	mtaVersionBanners = []string{
		"(Postfix)",
		"(sendmail)",
		"(Exim)",
		"(2.20.1.0.0)",
		"(DOCOMO Mail Server Ver2.0)",
		"(Postfix-2.11.7)",
		"(Microsoft SMTP Server)",
	}
)

func (vp *VariableProcessor) processProtocolVariables(content string) string {
	content = vp.replaceLiteral(content, "{TLS_VERSION}", func() string {
		return tlsVersionPool[safeIntn(vp.random, len(tlsVersionPool))]
	})
	content = vp.replaceLiteral(content, "{TLS_CIPHER}", func() string {
		return tlsCipherPool[safeIntn(vp.random, len(tlsCipherPool))]
	})
	content = vp.replaceLiteral(content, "{TLS_BITS}", func() string {
		return tlsBitsPool[safeIntn(vp.random, len(tlsBitsPool))]
	})
	content = vp.replaceLiteral(content, "{SMTP_PROTOCOL}", func() string {
		return smtpProtocolPool[safeIntn(vp.random, len(smtpProtocolPool))]
	})
	content = vp.replaceLiteral(content, "{MTA_TYPE}", func() string {
		return mtaTypePool[safeIntn(vp.random, len(mtaTypePool))]
	})
	content = vp.replaceLiteral(content, "{MTA_VERSION_BANNER}", func() string {
		return mtaVersionBanners[safeIntn(vp.random, len(mtaVersionBanners))]
	})
	return content
}

// ============================================================================
// F. JWT 变量（1 个）—— 完整 3 段 base64url 编码
// ============================================================================

// jwtHeaderPool 完整 JWT header 段（base64url 编码后）
// 对应明文：
//   - eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"HS256","typ":"JWT"}
//   - eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9 = {"alg":"HS384","typ":"JWT"}
//   - eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9 = {"alg":"HS512","typ":"JWT"}
//   - eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"RS256","typ":"JWT"}
//   - eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"ES256","typ":"JWT"}
var jwtHeaderPool = []string{
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
	"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9",
	"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
	"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
}

// jwtBase64URL 用 base64.RawURLEncoding（无 padding）编码字节
func jwtBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func (vp *VariableProcessor) processJWTVariables(content string) string {
	content = vp.replaceLiteral(content, "{JWT_TOKEN}", func() string {
		header := jwtHeaderPool[safeIntn(vp.random, len(jwtHeaderPool))]

		// payload: 80-160 字节随机数据 → base64url（结果约 107-214 字符）
		// 真实 JWT payload 常见长度 100-300 字符，落在此区间内合理
		payloadLen := 80 + safeIntn(vp.random, 81)
		payloadBytes := make([]byte, payloadLen)
		for i := range payloadBytes {
			payloadBytes[i] = byte(safeIntn(vp.random, 256))
		}
		payload := jwtBase64URL(payloadBytes)

		// signature: 32 字节（HS256 长度）或 64 字节（HS512 长度），按 header 类型粗略匹配
		// 简化：HS512 用 64 字节，其他都用 32 字节
		sigLen := 32
		if strings.Contains(header, "IUzUxMiI") { // HS512
			sigLen = 64
		} else if strings.Contains(header, "JSUzI1NiI") || strings.Contains(header, "RS256") {
			// RS256 signature 实际是 256 字节，但 base64url 后约 342 字符——太长
			// 现实折中：用 64 字节模拟（base64url 后 86 字符），保持视觉合理
			sigLen = 64
		}
		sigBytes := make([]byte, sigLen)
		for i := range sigBytes {
			sigBytes[i] = byte(safeIntn(vp.random, 256))
		}
		signature := jwtBase64URL(sigBytes)

		return header + "." + payload + "." + signature
	})

	return content
}
