package email

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"__MODULE_PLACEHOLDER__/config"
)

var jstZone = time.FixedZone("JST", 9*3600)

func formatReceivedJSTDateRFC2822(t time.Time) string {
	d := t.In(jstZone)
	days := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	months := []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	return fmt.Sprintf("%s, %02d %s %d %02d:%02d:%02d +0900 (JST)",
		days[d.Weekday()], d.Day(), months[d.Month()], d.Year(),
		d.Hour(), d.Minute(), d.Second())
}

func detectChainType(envelopeTo string) string {
	d := strings.ToLower(envelopeTo)
	if idx := strings.Index(d, "@"); idx != -1 {
		d = d[idx+1:]
	}
	d = strings.TrimSpace(d)
	if strings.Contains(d, "docomo.ne.jp") || strings.Contains(d, "spmode.ne.jp") ||
		strings.Contains(d, "mopera.net") || strings.Contains(d, "biglobe.ne.jp") ||
		strings.Contains(d, "plala.or.jp") || strings.Contains(d, "ocn.ne.jp") {
		return "carrier_docomo"
	}
	if strings.Contains(d, "ezweb.ne.jp") || strings.Contains(d, "au.com") ||
		strings.Contains(d, "uqmobile.jp") || strings.Contains(d, "dion.ne.jp") {
		return "carrier_kddi"
	}
	if strings.Contains(d, "softbank.ne.jp") || strings.Contains(d, "i.softbank.jp") ||
		strings.Contains(d, "vodafone.ne.jp") || strings.Contains(d, "ymobile.ne.jp") ||
		strings.Contains(d, "yahoo.co.jp") {
		return "carrier_softbank"
	}
	if strings.Contains(d, "gmail.com") || strings.Contains(d, "googlemail.com") || strings.Contains(d, "icloud.com") {
		return "aws_tokyo"
	}
	if strings.Contains(d, "outlook.com") || strings.Contains(d, "outlook.jp") ||
		strings.Contains(d, "hotmail.com") || strings.Contains(d, "office365.com") {
		return "enterprise"
	}
	if strings.HasSuffix(d, ".jp") || strings.HasSuffix(d, ".co.jp") {
		return "japan_idc"
	}
	return "enterprise"
}

func getPublicNode(targetType, dom string, r *rand.Rand) (string, string) {
	switch targetType {
	case "carrier_docomo":
		subnets := []string{"210.150.", "211.125.", "210.140.", "203.138."}
		sub := subnets[safeIntn(r, len(subnets))]
		ip := fmt.Sprintf("%s%d.%d", sub, safeIntn(r, 221)+10, safeIntn(r, 254)+1)
		host := fmt.Sprintf("mail-gw%02d.%s", safeIntn(r, 16)+1, dom)
		return ip, host
	case "carrier_kddi":
		subnets := []string{"106.187.", "118.159.", "202.214."}
		sub := subnets[safeIntn(r, len(subnets))]
		ip := fmt.Sprintf("%s%d.%d", sub, safeIntn(r, 221)+10, safeIntn(r, 254)+1)
		host := fmt.Sprintf("telehouse-relay%02d.%s", safeIntn(r, 16)+1, dom)
		return ip, host
	case "carrier_softbank":
		subnets := []string{"101.110.", "126.140.", "126.240."}
		sub := subnets[safeIntn(r, len(subnets))]
		ip := fmt.Sprintf("%s%d.%d", sub, safeIntn(r, 221)+10, safeIntn(r, 254)+1)
		var host string
		if sub == "101.110." {
			host = fmt.Sprintf("imsa%04d.mailsv.softbank.jp", safeIntn(r, 99)+4001)
		} else {
			host = fmt.Sprintf("ty3-core%02d.%s", safeIntn(r, 16)+1, dom)
		}
		return ip, host
	case "aws_tokyo":
		subnets := []string{"52.68.", "54.64.", "13.112.", "13.230."}
		b := subnets[safeIntn(r, len(subnets))]
		o3 := safeIntn(r, 221) + 10
		o4 := safeIntn(r, 254) + 1
		ip := fmt.Sprintf("%s%d.%d", b, o3, o4)
		bDash := strings.ReplaceAll(b, ".", "-")
		host := fmt.Sprintf("ec2-%s%d-%d.ap-northeast-1.compute.amazonaws.com", bDash, o3, o4)
		return ip, host
	case "japan_idc":
		subnets := []string{"133.242.", "160.16.", "153.120."}
		sub := subnets[safeIntn(r, len(subnets))]
		ip := fmt.Sprintf("%s%d.%d", sub, safeIntn(r, 221)+10, safeIntn(r, 254)+1)
		host := fmt.Sprintf("mail-dc%02d.%s", safeIntn(r, 16)+1, dom)
		return ip, host
	default: // enterprise
		subnets := []string{"210.150.", "106.187.", "202.214.", "133.242."}
		sub := subnets[safeIntn(r, len(subnets))]
		ip := fmt.Sprintf("%s%d.%d", sub, safeIntn(r, 221)+10, safeIntn(r, 254)+1)
		host := fmt.Sprintf("mailgw%02d.%s", safeIntn(r, 16)+1, dom)
		return ip, host
	}
}

func getInternalNode(dom, style string, r *rand.Rand) (string, string) {
	ip := fmt.Sprintf("10.%d.%d.%d", safeIntn(r, 231)+10, safeIntn(r, 254)+1, safeIntn(r, 254)+1)
	roles := []string{"app-node", "worker", "core-worker", "job-runner", "dispatch", "mail-backend"}
	role := roles[safeIntn(r, len(roles))]
	num := fmt.Sprintf("%02d", safeIntn(r, 32)+1)

	var suf string
	switch strings.ToLower(style) {
	case "japan_telecom":
		suf = ".tokyo.internal.jp"
	case "cloud_vpc":
		suf = ".ap-northeast-1.internal"
	case "enterprise":
		suf = ".corp.internal"
	case "bound_domain":
		suf = fmt.Sprintf(".internal.%s", dom)
	default:
		sufs := []string{".tokyo.internal.jp", ".internal", ".vpc.internal", fmt.Sprintf(".internal.%s", dom)}
		suf = sufs[safeIntn(r, len(sufs))]
	}
	return ip, fmt.Sprintf("%s%s%s", role, num, suf)
}

func randHexUpper(r *rand.Rand, length int) string {
	const chars = "0123456789ABCDEF"
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = chars[safeIntn(r, len(chars))]
	}
	return string(buf)
}

// GenerateReceivedChain 根据 GUI 逻辑生成 1~2 跳中继链路拓扑伪装头
func (hg *HeaderGenerator) GenerateReceivedChain(envelopeFrom, envelopeTo, fromDomain string, chainCfg *config.ReceivedChainConfig, tBase time.Time) string {
	if chainCfg == nil || !chainCfg.Enabled {
		return ""
	}

	chainType := strings.ToLower(strings.TrimSpace(chainCfg.ChainType))
	if chainType == "" || chainType == "smart_auto" {
		chainType = "smart_auto"
	}

	hopsCount := chainCfg.Hops
	if hopsCount < 1 {
		hopsCount = 1
	}
	if hopsCount > 2 {
		hopsCount = 2
	}

	if chainType == "mobile_client" || chainType == "official_std" || chainType == "standard_relay" {
		hopsCount = 1
	}

	dom := strings.TrimSpace(fromDomain)
	if dom == "" {
		dom = "marketing.co.jp"
	}

	effectiveType := chainType
	if chainType == "smart_auto" {
		effectiveType = detectChainType(envelopeTo)
	}

	// 专用随机生成器 (支持 IPMode 轮转策略)
	var r *rand.Rand
	ipMode := strings.ToLower(strings.TrimSpace(chainCfg.IPMode))
	switch ipMode {
	case "sticky_user":
		h := md5.Sum([]byte(envelopeFrom))
		seed := int64(binary.BigEndian.Uint64(h[:8]))
		r = rand.New(rand.NewSource(seed))
	case "rotate_50":
		seed := time.Now().Unix() / 50
		r = rand.New(rand.NewSource(seed))
	case "rotate_100":
		seed := time.Now().Unix() / 100
		r = rand.New(rand.NewSource(seed))
	default: // dynamic
		if hg != nil && hg.random != nil {
			r = hg.random
		} else {
			r = rand.New(rand.NewSource(time.Now().UnixNano()))
		}
	}

	id1 := randHexUpper(r, 10)
	id2 := randHexUpper(r, 10)

	date1 := formatReceivedJSTDateRFC2822(tBase)
	date2 := formatReceivedJSTDateRFC2822(tBase.Add(-time.Duration(safeIntn(r, 14)+2) * time.Second))

	forPart := ""
	if envelopeTo != "" {
		forPart = fmt.Sprintf(" for <%s>", envelopeTo)
	}

	// 自定义中继模板
	if chainType == "custom" && strings.TrimSpace(chainCfg.CustomTemplate) != "" {
		cIP, cHost := getPublicNode(effectiveType, dom, r)
		rendered := chainCfg.CustomTemplate
		rendered = strings.ReplaceAll(rendered, "{client_ip}", cIP)
		rendered = strings.ReplaceAll(rendered, "{client_host}", cHost)
		rendered = strings.ReplaceAll(rendered, "{sub_host}", cHost)
		rendered = strings.ReplaceAll(rendered, "{domain}", dom)
		rendered = strings.ReplaceAll(rendered, "{id}", id1)
		rendered = strings.ReplaceAll(rendered, "{for_part}", forPart)
		rendered = strings.ReplaceAll(rendered, "{to}", envelopeTo)
		rendered = strings.ReplaceAll(rendered, "{date}", date1)
		lines := strings.Split(rendered, "\n")
		var sb strings.Builder
		for _, line := range lines {
			l := strings.TrimSpace(line)
			if l != "" {
				if !strings.HasPrefix(strings.ToLower(l), "received:") {
					l = "Received: " + l
				}
				sb.WriteString(l + "\r\n")
			}
		}
		return sb.String()
	}

	// 移动端单跳链路 (iPhone / Android)
	if chainType == "mobile_client" {
		helos := []string{"smtpclient.apple", "iphone.local", "iphone.lan", "android-mail", "mail-client"}
		helo := helos[safeIntn(r, len(helos))]
		var ip string
		if safeIntn(r, 100) < 70 {
			ip = fmt.Sprintf("100.%d.%d.%d", safeIntn(r, 64)+64, safeIntn(r, 256), safeIntn(r, 254)+1)
		} else {
			ip = fmt.Sprintf("192.168.%d.%d", safeIntn(r, 256), safeIntn(r, 254)+1)
		}
		return fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTPSA id %s%s; %s\r\n",
			helo, ip, dom, id1, forPart, date1)
	}

	// 官方标准外网单跳
	if chainType == "official_std" || chainType == "standard_relay" {
		return fmt.Sprintf("Received: from [127.0.0.1] (localhost [127.0.0.1]) by %s with ESMTPSA id %s%s; %s\r\n",
			dom, id1, forPart, date1)
	}

	// IP 网段类型策略
	ipPool := strings.ToLower(strings.TrimSpace(chainCfg.IPPool))
	if ipPool == "" {
		ipPool = "smart_pool"
	}
	usePublic := (ipPool == "japan_public") || (ipPool == "smart_pool" && (effectiveType == "carrier_docomo" || effectiveType == "carrier_softbank" || effectiveType == "carrier_kddi" || effectiveType == "aws_tokyo" || effectiveType == "japan_idc" || effectiveType == "enterprise"))
	isHybrid := (ipPool == "hybrid_mix") || (ipPool == "smart_pool" && hopsCount == 2)

	pubIP, pubHost := getPublicNode(effectiveType, dom, r)
	intIP, intHost := getInternalNode(dom, chainCfg.DomainStyle, r)

	// MTA 引擎指纹
	sw1 := "with ESMTPS"
	sw2 := "with ESMTPA"
	mtaFlavor := strings.ToLower(strings.TrimSpace(chainCfg.MTAFlavor))
	switch mtaFlavor {
	case "postfix":
		sw1 = "(Postfix) with ESMTPS"
		sw2 = "(Postfix) with ESMTPA"
	case "sendmail":
		sw1 = "(8.15.2/8.15.2) with ESMTP"
		sw2 = "with ESMTPA"
	case "cisco":
		sw1 = "(Cisco ESA 14.2) with ESMTP"
		sw2 = "with ESMTPA"
	case "smart_match":
		if effectiveType == "carrier_kddi" {
			sw1 = "(8.15.2/8.15.2) with ESMTP"
			sw2 = "with ESMTPA"
		} else if effectiveType == "carrier_softbank" {
			sw1 = "with ESMTPS"
			sw2 = "with ESMTPA"
		} else {
			sw1 = "(Postfix) with ESMTPS"
			sw2 = "(Postfix) with ESMTPA"
		}
	case "pure_rfc":
		sw1 = "with ESMTPS"
		sw2 = "with ESMTPA"
	default:
		sw1 = "with ESMTPS"
		sw2 = "with ESMTPA"
	}

	var hop1, hop2 string

	switch effectiveType {
	case "carrier_docomo":
		cIP := intIP
		if usePublic || isHybrid {
			cIP = pubIP
		}
		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
			pubHost, cIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
				intHost, intIP, pubHost, sw2, id2, forPart, date2)
		}

	case "carrier_kddi":
		cIP := intIP
		if usePublic || isHybrid {
			cIP = pubIP
		}
		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
			pubHost, cIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
				intHost, intIP, pubHost, sw2, id2, forPart, date2)
		}

	case "carrier_softbank":
		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
			pubHost, pubIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			tNow := tBase.In(jstZone)
			hop2 = fmt.Sprintf("Received: from %s by %s with ESMTP id <%s.WORB.%d.%s@mailsv.softbank.jp>%s;\r\n\t%s\r\n",
				intHost, pubHost, tNow.Format("20060102150405"), safeIntn(r, 90000)+10000, pubHost, forPart, date2)
		}

	case "aws_tokyo":
		hop1 = fmt.Sprintf("Received: from %s (%s [%s]) by mail.%s %s id %s%s;\r\n\t%s\r\n",
			pubHost, pubHost, pubIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
				intHost, intIP, pubHost, sw2, id2, forPart, date2)
		}

	case "japan_idc":
		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
			pubHost, pubIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
				intHost, intIP, pubHost, sw2, id2, forPart, date2)
		}

	default: // enterprise
		cIP := intIP
		if usePublic {
			cIP = pubIP
		}
		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
			pubHost, cIP, dom, sw1, id1, forPart, date1)
		if hopsCount == 2 {
			hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %s id %s%s;\r\n\t%s\r\n",
				intHost, intIP, pubHost, sw2, id2, forPart, date2)
		}
	}

	var sb strings.Builder
	if hop1 != "" {
		sb.WriteString(hop1)
	}
	if hopsCount == 2 && hop2 != "" {
		sb.WriteString(hop2)
	}
	return sb.String()
}
