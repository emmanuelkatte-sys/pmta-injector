package email

import (
	"fmt"
	"strings"
	"time"

	"__MODULE_PLACEHOLDER__/config"
)

// GenerateReceivedChain 生成智能中继拓扑链 (1-2 跳)
func (hg *HeaderGenerator) GenerateReceivedChain(envelopeFrom, envelopeTo, fromDomain string, chainCfg *config.ReceivedChainConfig, tBase time.Time) string {
	if chainCfg == nil || !chainCfg.Enabled {
		return ""
	}

	hopsCount := chainCfg.Hops
	if hopsCount < 1 {
		hopsCount = 1
	}
	if hopsCount > 2 {
		hopsCount = 2
	}

	chainType := strings.ToLower(strings.TrimSpace(chainCfg.ChainType))
	if chainType == "" || chainType == "smart_auto" {
		chainType = detectChainType(envelopeTo)
	}

	mtaFlavor := strings.ToLower(strings.TrimSpace(chainCfg.MTAFlavor))
	if mtaFlavor == "" || mtaFlavor == "dynamic" {
		mtaFlavor = "postfix"
	}

	dom := fromDomain
	if dom == "" {
		dom = "mail.example.com"
	}

	date1 := formatReceivedJSTDate(tBase)
	date2 := formatReceivedJSTDate(tBase.Add(-time.Duration(safeIntn(hg.random, 15)+5) * time.Second))

	id1 := randomHexString(10)
	id2 := randomHexString(10)

	forPart := ""
	if envelopeTo != "" {
		forPart = fmt.Sprintf(" for <%s>", envelopeTo)
	}

	// 自定义中继模板
	if chainType == "custom" && strings.TrimSpace(chainCfg.CustomTemplate) != "" {
		cIP := fmt.Sprintf("211.125.%d.%d", safeIntn(hg.random, 200)+10, safeIntn(hg.random, 254)+1)
		subH := fmt.Sprintf("gw-relay%02d.%s", safeIntn(hg.random, 16)+1, dom)
		rendered := chainCfg.CustomTemplate
		rendered = strings.ReplaceAll(rendered, "{client_ip}", cIP)
		rendered = strings.ReplaceAll(rendered, "{client_host}", subH)
		rendered = strings.ReplaceAll(rendered, "{sub_host}", subH)
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

	var hop1, hop2 string
	sw2 := ""
	if mtaFlavor == "postfix" {
		sw2 = "(Postfix) "
	} else if mtaFlavor == "sendmail" {
		sw2 = "(8.15.2/8.15.2) "
	}

	switch chainType {
	case "carrier_docomo":
		subgwHost := fmt.Sprintf("sub-gw%02d.%s", safeIntn(hg.random, 16)+1, dom)
		subgwIP := fmt.Sprintf("210.150.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)
		internalHost := fmt.Sprintf("core-mta%02d.tokyo.internal.jp", safeIntn(hg.random, 32)+1)
		internalIP := fmt.Sprintf("10.136.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)

		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTPS id %s%s; %s\r\n",
			subgwHost, subgwIP, dom, id1, forPart, date1)
		hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %swith ESMTP id %s%s; %s\r\n",
			internalHost, internalIP, subgwHost, sw2, id2, forPart, date2)

	case "carrier_softbank":
		sbNum := safeIntn(hg.random, 50) + 101
		sbHost := fmt.Sprintf("ebmky%03dsc.i.softbank.jp", sbNum)
		sbIP := fmt.Sprintf("101.110.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)
		internalHost := fmt.Sprintf("dimky%03dsb.mailsv.softbank.jp", sbNum)
		internalIP := fmt.Sprintf("172.16.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)

		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTPS id %s%s; %s\r\n",
			sbHost, sbIP, dom, id1, forPart, date1)
		hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %swith ESMTP id %s%s; %s\r\n",
			internalHost, internalIP, sbHost, sw2, id2, forPart, date2)

	case "carrier_kddi":
		kHost := fmt.Sprintf("telehouse-relay%02d.%s", safeIntn(hg.random, 16)+1, dom)
		kIP := fmt.Sprintf("106.187.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)
		internalHost := fmt.Sprintf("kddi-gw%02d.kanto.internal.jp", safeIntn(hg.random, 32)+1)
		internalIP := fmt.Sprintf("10.148.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)

		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTP id %s%s; %s\r\n",
			kHost, kIP, dom, id1, forPart, date1)
		hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %swith ESMTP id %s%s; %s\r\n",
			internalHost, internalIP, kHost, sw2, id2, forPart, date2)

	case "aws_tokyo":
		a1 := safeIntn(hg.random, 254) + 1
		a2 := safeIntn(hg.random, 254) + 1
		clientIP := fmt.Sprintf("52.68.%d.%d", a1, a2)
		clientHost := fmt.Sprintf("ec2-52-68-%d-%d.ap-northeast-1.compute.amazonaws.com", a1, a2)
		mtaHost := fmt.Sprintf("sdmmta%02d.mail.internal", safeIntn(hg.random, 32)+1)
		appHost := fmt.Sprintf("app-relay%02d.ap-northeast-1.internal", safeIntn(hg.random, 16)+1)
		appIP := fmt.Sprintf("10.%d.%d.%d", safeIntn(hg.random, 50)+10, safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)

		hop1 = fmt.Sprintf("Received: from %s (%s [%s]) by %s with ESMTP id %s%s; %s\r\n",
			clientHost, clientHost, clientIP, mtaHost, id1, forPart, date1)
		hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %swith ESMTP id %s%s; %s\r\n",
			appHost, appIP, clientHost, sw2, id2, forPart, date2)

	case "official_std", "standard_relay":
		// RFC 5321 标准单跳 / 外网单跳
		hop1 = fmt.Sprintf("Received: from [127.0.0.1] (localhost [127.0.0.1]) by %s with ESMTPSA id %s%s; %s\r\n",
			dom, id1, forPart, date1)
		hop2 = ""

	case "mobile_client":
		// 移动端单跳：模拟 iPhone/Android 客户端通过 ESMTPSA 直接提交
		deviceHosts := []string{
			fmt.Sprintf("iPhone-%.4X.local", safeIntn(hg.random, 0xFFFF)+1),
			fmt.Sprintf("android-%.8x.wlan.local", safeIntn(hg.random, 0xFFFFFFFF)+1),
			fmt.Sprintf("ipad-%.4X.local", safeIntn(hg.random, 0xFFFF)+1),
		}
		deviceHost := deviceHosts[safeIntn(hg.random, len(deviceHosts))]
		deviceIP := fmt.Sprintf("192.168.%d.%d", safeIntn(hg.random, 10)+1, safeIntn(hg.random, 253)+2)
		hop1 = fmt.Sprintf("Received: from %s (%s [%s]) by %s with ESMTPSA id %s%s; %s\r\n",
			deviceHost, deviceHost, deviceIP, dom, id1, forPart, date1)
		hop2 = ""

	default: // enterprise / Japanese commercial IDC
		corpHost := fmt.Sprintf("mail-dc%02d.%s", safeIntn(hg.random, 16)+1, dom)
		corpIP := fmt.Sprintf("133.242.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)
		internalHost := fmt.Sprintf("dispatch%02d.tokyo.internal.jp", safeIntn(hg.random, 32)+1)
		internalIP := fmt.Sprintf("10.10.%d.%d", safeIntn(hg.random, 254)+1, safeIntn(hg.random, 254)+1)

		hop1 = fmt.Sprintf("Received: from %s ([%s]) by %s with ESMTPS id %s%s; %s\r\n",
			corpHost, corpIP, dom, id1, forPart, date1)
		hop2 = fmt.Sprintf("Received: from %s ([%s]) by %s %swith ESMTP id %s%s; %s\r\n",
			internalHost, internalIP, corpHost, sw2, id2, forPart, date2)
	}

	var sb strings.Builder
	if hopsCount == 2 && hop2 != "" {
		sb.WriteString(hop2)
	}
	if hop1 != "" {
		sb.WriteString(hop1)
	}
	return sb.String()
}

func detectChainType(envelopeTo string) string {
	toLower := strings.ToLower(envelopeTo)
	if strings.Contains(toLower, "docomo.ne.jp") || strings.Contains(toLower, "spmode.ne.jp") {
		return "carrier_docomo"
	}
	if strings.Contains(toLower, "ezweb.ne.jp") || strings.Contains(toLower, "au.com") || strings.Contains(toLower, "uqmobile.jp") {
		return "carrier_kddi"
	}
	if strings.Contains(toLower, "softbank.ne.jp") || strings.Contains(toLower, "i.softbank.jp") || strings.Contains(toLower, "ymobile.ne.jp") {
		return "carrier_softbank"
	}
	if strings.Contains(toLower, "gmail.com") || strings.Contains(toLower, "googlemail.com") {
		return "aws_tokyo"
	}
	return "enterprise"
}
