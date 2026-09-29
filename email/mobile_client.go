package email

import (
	"fmt"
	"strings"
	"time"
)

// mobileClientHelos 模拟手机邮件客户端 HELO/EHLO 名（勿注入 User-Agent，docomo 会扣分）。
var mobileClientHelos = []string{
	"smtpclient.apple", "iphone.local", "iphone", "iphone.lan",
	"android-mail", "android.local", "mail-client",
}

// mobileBlockedHeaderNames 手机发信模式下禁止输出的 MTA/认证指纹头。
var mobileBlockedHeaderNames = map[string]struct{}{
	"authentication-results":              {},
	"original-authentication-results":     {},
	"received-spf":                        {},
	"arc-authentication-results":          {},
	"arc-message-signature":               {},
	"arc-seal":                            {},
	"x-mailer":                            {},
	"x-haraka":                            {},
	"x-haraka-uuid":                       {},
	"x-haraka-transaction":                {},
	"x-originating-ip":                    {},
	"x-originating-email":                 {},
	"x-priority":                          {},
	"importance":                          {},
	"x-msmail-priority":                   {},
	"x-php-originating-script":            {},
	"x-antiabuse":                         {},
	"x-source":                            {},
	"x-source-args":                       {},
	"x-authenticated-sender":              {},
	"x-authenticated-user":                {},
	"x-sender-ip":                         {},
	"x-smtpapi":                           {},
	"x-mailer-trace":                      {},
	"x-kumoref":                           {},
}

// IsMobileBlockedHeader 是否属于手机模式下应剔除的 MTA/认证头。
func IsMobileBlockedHeader(name string) bool {
	_, ok := mobileBlockedHeaderNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// GenerateMobileClientReceived 单跳「手机 ESMTPSA 提交」Received（对齐 mail_rewrite.js mobile 模式）。
func (hg *HeaderGenerator) GenerateMobileClientReceived(byDomain string) string {
	byDomain = strings.TrimSpace(byDomain)
	if byDomain == "" {
		return ""
	}
	helo := mobileClientHelos[hg.identityIndex("mobile-helo", len(mobileClientHelos))]
	r := hg.identityRand("mobile-ip")
	var ip string
	if safeIntn(r, 100) < 70 {
		ip = fmt.Sprintf("100.%d.%d.%d",
			64+safeIntn(r, 64),
			safeIntn(r, 256),
			1+safeIntn(r, 254),
		)
	} else {
		ip = fmt.Sprintf("192.168.%d.%d",
			safeIntn(r, 256),
			1+safeIntn(r, 254),
		)
	}
	queueID := strings.ToUpper(hg.generateMobileQueueID())
	stamp := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 MST")
	return fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTPSA id %s; %s\r\n",
		helo, ip, byDomain, queueID, stamp)
}

func (hg *HeaderGenerator) generateMobileQueueID() string {
	const chars = "0123456789ABCDEF"
	result := make([]byte, 6)
	for i := range result {
		result[i] = chars[safeIntn(hg.random, len(chars))]
	}
	return string(result)
}
