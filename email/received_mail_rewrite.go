package email

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// mail_rewrite.js — RECEIVED_EHLO_DOMAINS / RECEIVED_MTA_LABELS / MOBILE_CLIENT_HELOS
var (
	receivedEhloDomains = []string{
		"amazon.co.jp", "rakuten.co.jp", "yahoo.co.jp", "docomo.ne.jp", "softbank.ne.jp", "ntt.com",
		"aeon.co.jp", "paypay.ne.jp", "line.me", "mercari.jp", "i.softbank.jp", "ezweb.ne.jp", "au.com",
		"kddi.com", "nifty.com", "so-net.ne.jp", "plala.or.jp", "ocn.ne.jp", "biglobe.ne.jp", "nifty.ne.jp",
		"dti.ne.jp", "jcom.zaq.ne.jp", "asahi.com", "mainichi.jp", "yomiuri.co.jp", "sony.jp", "uniqlo.com",
		"cookpad.com", "zozo.jp", "pixiv.net", "nicovideo.jp", "sbisec.co.jp", "mufg.jp", "smbc.co.jp",
		"japanpost.jp", "outlook.jp", "gmail.com", "excite.co.jp", "infoseek.jp", "goo.ne.jp", "sakura.ne.jp",
		"gmobb.jp", "eonet.ne.jp", "commufa.jp", "hi-ho.ne.jp", "ymobile.ne.jp", "uqmobile.jp", "povo.jp",
		"ahamo.com", "linemo.jp", "mineo.jp", "iijmio.jp", "biccamera.com", "yodobashi.com", "yamada-denki.jp",
		"nitori-net.jp", "muji.com", "dmm.co.jp", "fancl.co.jp", "shiseido.co.jp", "tabelog.com", "hotpepper.jp",
		"jalan.net", "ekiten.jp", "livedoor.com", "fc2.com", "ameba.jp", "hatena.ne.jp", "mixi.jp",
		"cyberagent.co.jp", "dena.com", "gree.net", "cygames.co.jp", "square-enix.com", "nintendo.co.jp",
		"bandai.co.jp", "panasonic.com", "sharp.co.jp", "toshiba.co.jp", "hitachi.co.jp", "fujitsu.com", "nec.com",
		"canon.jp", "nikon.co.jp", "toyota.co.jp", "honda.co.jp", "ana.co.jp", "jal.co.jp", "jr-central.co.jp",
		"eki-net.com", "suica.com", "sevenbank.co.jp", "jcb.co.jp", "viewcard.co.jp", "eposcard.co.jp", "life.co.jp",
		"ntt-east.co.jp", "ntt-west.co.jp", "kagoya.net", "xserver.jp", "lolipop.jp", "heteml.jp", "conoha.jp",
		"starbucks.co.jp", "matsuyafoods.co.jp", "sukiya.jp", "mos.co.jp", "lawson.co.jp", "family.co.jp", "sej.co.jp",
		"tokyo-gas.co.jp", "tepco.co.jp", "kepco.co.jp", "suumo.jp", "homes.co.jp", "kakaku.com", "qoo10.jp",
		"shop-list.com", "montbell.com", "gu-global.com", "shimamura.gr.jp", "donki.com", "matsukiyococokara.com",
		"edion.com", "kojima.net", "nojima.co.jp", "askul.co.jp", "monotaro.com", "kakuyasu.co.jp", "oisix.com",
		"zexy.net", "mynavi.jp", "rikunabi.com", "recruit.co.jp", "wantedly.com", "benesse.co.jp", "nissan.co.jp",
		"mazda.co.jp", "subaru.jp", "suzuki.co.jp", "mitsubishi-motors.com", "lexus.com", "resona-gr.co.jp",
		"shinseibank.com", "aeonfinancial.co.jp", "orico.co.jp", "cedyna.co.jp", "rakuten-card.co.jp", "auone.jp",
		"willcom.com", "emobile.ne.jp", "disney.co.jp", "animate.co.jp", "suruga-ya.jp", "tsutaya.co.jp",
		"booklive.jp", "cmoa.jp", "itmedia.co.jp", "ascii.jp", "oricon.co.jp", "rocketnews24.com", "mamastar.jp",
		"kodansha.co.jp", "shueisha.co.jp", "shogakukan.co.jp", "mail.yahoo.co.jp", "mail.goo.ne.jp", "mediba.jp",
		"gunosy.com", "smartnews.com", "news.yahoo.co.jp", "nhk.or.jp", "tbs.co.jp", "ntv.co.jp", "fujitv.co.jp",
		"tv-asahi.co.jp", "bs11.jp", "wowow.co.jp", "hulu.jp", "abema.tv", "dazn.com", "spotify.com", "netflix.com",
		"uber.com", "menu.inc", "demae-can.com", "wolt.com", "coconala.com", "crowdworks.jp", "lancers.jp",
		"freee.co.jp", "moneyforward.com", "yayoi-kk.co.jp", "sansan.com", "chatwork.com", "cybozu.co.jp",
		"kintone.com", "backlog.com", "qiita.com", "zenn.dev", "note.com", "base.shop", "stores.jp", "shopify.com",
		"future-shop.jp", "make.shop", "colorme.shop", "peachjohn.co.jp", "gelatopique.com", "beams.co.jp",
		"united-arrows.co.jp", "world.co.jp", "magaseek.com", "locondo.jp", "cosme.com", "dhc.co.jp", "kose.co.jp",
		"suntory.co.jp", "kirin.co.jp", "kikkoman.co.jp", "ajinomoto.co.jp", "meiji.co.jp", "morinaga.co.jp",
		"glico.com", "lotte.co.jp", "calbee.co.jp", "yakult.co.jp", "nissin.com", "isetan.mistore.jp",
		"takashimaya.co.jp", "lumine.jp", "parco.jp", "odakyu-deptstore.jp", "welcia.co.jp", "tsuruha.co.jp",
		"sundrug.co.jp", "matsumoto-kiyoshi.jp", "loft.co.jp", "right-on.co.jp", "mercari-shops.com", "hands.net",
		"sogo-seibu.com", "kobeshi.co.jp", "kuronekoyamato.co.jp", "sagawa-exp.co.jp", "japanpost-group.jp", "skylark.co.jp",
	}
	receivedMtaLabels = []string{
		"DOCOMO Mail Server", "MIZUHO Bank Mail", "Mitsubishi UFJ Mail", "SMBC Mail", "Resona Bank Mail",
		"Rakuten Group Mail", "NTT Communications", "SOFTBANK Mail", "KDDI Mail", "Japan Post Mail",
		"Yahoo! JAPAN Mail", "Amazon.co.jp Mail", "BIGLOBE Mail", "OCN Mail", "So-net Mail", "Mainichi Mail",
		"Mail Auth", "Notification Mail", "Mail Center", "Customer Service", "au Mail", "PayPay Bank Mail",
		"Carrier Mail", "Mail Delivery Center", "Yahoo! JAPAN", "Amazon.co.jp", "LINEMO", "T-Online", "Qoo10",
		"ZOZOTOWN", "Gunosy", "Uber Eats", "Wolt", "kintone", "STORES", "futureshop",
	}
	mailRewriteMobileHelos = []string{
		"smtpclient.apple", "smtpclient.apple", "smtpclient.apple",
		"iphone.local", "iphone.local", "iphone", "iphone", "iphone.lan",
		"android-mail", "android.local", "mail-client",
	}
	receivedIDForClauseRE = regexp.MustCompile(`(?i)\s+id\s+[A-Za-z0-9._-]+\s+for\s+<[^>]+>\s*;`)
)

func buildMailRewriteQueueID(hg *HeaderGenerator) string {
	return strings.ToUpper(randomHexString(6))
}

func mailRewriteMobileClientIP(hg *HeaderGenerator) string {
	if hg.cfg != nil && hg.cfg.ReceivedDeterministic {
		return "100.72.1.2"
	}
	r := hg.identityRand("mobile-ip")
	if safeIntn(r, 100) < 70 {
		return fmt.Sprintf("100.%d.%d.%d",
			64+safeIntn(r, 64),
			safeIntn(r, 256),
			1+safeIntn(r, 254),
		)
	}
	return fmt.Sprintf("192.168.%d.%d",
		safeIntn(r, 256),
		1+safeIntn(r, 254),
	)
}

func flattenReceivedValue(value string) string {
	out := strings.TrimSpace(strings.ReplaceAll(value, "\r\n", " "))
	out = strings.ReplaceAll(out, "\n", " ")
	return strings.Join(strings.Fields(out), " ")
}

func stripTlsFromWithClause(clause string) string {
	flat := flattenReceivedValue(clause)
	re := regexp.MustCompile(`(?i)\s*\([^)]*[Tt][Ll][Ss][^)]*\)`)
	flat = re.ReplaceAllString(flat, "")
	flat = strings.Join(strings.Fields(flat), " ")
	if flat == "" {
		return "with ESMTP"
	}
	return flat
}

func extractWithClause(originalValue string) string {
	flat := flattenReceivedValue(originalValue)
	if m := regexp.MustCompile(`(?i)(with\s+.+?)\s+id\s+`).FindStringSubmatch(flat); len(m) > 1 {
		return stripTlsFromWithClause(m[1])
	}
	if m := regexp.MustCompile(`(?i)(with\s+[^;]+)`).FindStringSubmatch(flat); len(m) > 1 {
		return stripTlsFromWithClause(m[1])
	}
	return "with ESMTP"
}

func sanitizeReceivedLine(line string) string {
	out := flattenReceivedValue(line)
	out = receivedIDForClauseRE.ReplaceAllString(out, ";")
	out = regexp.MustCompile(`;\s*;+`).ReplaceAllString(out, "; ")
	return strings.Join(strings.Fields(out), " ")
}

func (hg *HeaderGenerator) buildReceivedTraceLine(mailHost, originalWith string, mobileMode bool) string {
	stamp := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	queueID := buildMailRewriteQueueID(hg)
	if mobileMode {
		helo := mailRewriteMobileHelos[0]
		if hg.cfg == nil || !hg.cfg.ReceivedDeterministic {
			helo = mailRewriteMobileHelos[hg.identityIndex("mobile-helo", len(mailRewriteMobileHelos))]
		}
		ip := mailRewriteMobileClientIP(hg)
		return fmt.Sprintf("from %s ([%s]) by %s with ESMTPSA id %s; %s", helo, ip, mailHost, queueID, stamp)
	}
	ehlo := receivedEhloDomains[0]
	label := receivedMtaLabels[0]
	if hg.cfg == nil || !hg.cfg.ReceivedDeterministic {
		ehlo = receivedEhloDomains[hg.identityIndex("received-ehlo", len(receivedEhloDomains))]
		label = receivedMtaLabels[hg.identityIndex("received-label", len(receivedMtaLabels))]
	}
	withClause := extractWithClause(originalWith)
	return fmt.Sprintf("from %s by %s (%s) %s id %s; %s", ehlo, mailHost, label, withClause, queueID, stamp)
}

// generateReceivedMailRewrite 对齐 mail_rewrite.js buildReceivedTraceLine / processReceivedList
func (hg *HeaderGenerator) generateReceivedMailRewrite(fromAddress, toAddress, mailHost string) string {
	_ = fromAddress
	_ = toAddress
	mailHost = strings.TrimSpace(mailHost)
	if mailHost == "" {
		return ""
	}
	mobileMode := hg.cfg != nil && hg.cfg.MobileClientHeaders
	originalWith := "with ESMTP"
	if mobileMode {
		originalWith = "with ESMTPSA"
	}
	line := sanitizeReceivedLine(hg.buildReceivedTraceLine(mailHost, originalWith, mobileMode))
	if line == "" {
		return ""
	}
	return "Received: " + line + "\r\n"
}
