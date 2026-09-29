package email

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/types"
)

// ========================================================================
// 【方案 B】伪 DKIM-Signature 的外部域签名池
// 设计思路：
//   伪签名故意将 d= 设为外部大厂域名（而非发件方真实域名），让接收方反垃圾系统
//   将"DKIM 校验失败"归因于"邮件经过外部中转链路时签名损坏"——这是邮件世界
//   常态（邮件列表/转发/反垃圾扫描都会破坏原始签名），反垃圾系统对此宽容。
//   而非"发件方自家签名都对不上"——后者被视为伪造，扣分严重。
//
// 域名 + selector 选取策略：
//   - 静态 selector 池：覆盖真实大厂当前/历史 selector 风格
//     （gmail 日期格式 / outlook selector1/2 / yahoo s2048 / icloud 1a1hai 等）
//   - SES 风格：每次动态生成 32 字符 base32 随机串（amazonses.com 每客户独立）
//   - 加权抽样：模拟真实邮件流量比例（gmail/outlook 高频，企业 SaaS 低频）
//   - 反指纹环形缓冲区：每个 worker 内记忆最近 8 次用过的源索引，避免短期重复
// ========================================================================

// dkimExternalSource 一个伪签名候选源（外部大厂域 + 该域的合理 selector 池 + 抽样权重）
type dkimExternalSource struct {
	domain    string   // d= 字段使用的外部域名
	selectors []string // 候选 selector（每封邮件从中随机一个）；isSESLike=true 时忽略
	weight    int      // 加权抽样权重（值越高被抽中概率越大，模拟真实流量分布）
	isSESLike bool     // true 时 selector 每次动态生成 32 字符 base32 随机串
	rsaBits   int      // 【2026-05-22 从 PowerMTA 移植】RSA 密钥长度（1024/2048/4096），决定 b= base64 长度（172/344/684 字符）
}

// dkimExternalSources 外部大厂域签名池（约 50 个组合，按真实邮件流量加权）
// 权重总和约 130，单源最大 20（gmail.com ~15%），最小 1（长尾企业域）
// 【2026-05-22 从 PowerMTA 移植】扩容到 72 条 + 全部条目补 rsaBits（含日本运营商/MVNO/ISP 共 20 域占 28% 权重）
var dkimExternalSources = []dkimExternalSource{
	// ===== Google 系（~20%）=====
	{"gmail.com", []string{"20230601", "20221208", "20210112", "20161025"}, 20, false, 2048},
	{"googlemail.com", []string{"20230601", "20221208"}, 4, false, 2048},
	{"google.com", []string{"20221208", "20230601"}, 4, false, 2048},

	// ===== Microsoft 系（~16%）=====
	{"outlook.com", []string{"selector1", "selector2"}, 12, false, 2048},
	{"hotmail.com", []string{"selector1", "selector2"}, 7, false, 2048},
	{"live.com", []string{"selector1", "selector2"}, 4, false, 2048},
	{"microsoft.com", []string{"selector1", "selector2"}, 3, false, 2048},
	{"office365.com", []string{"selector1"}, 2, false, 2048},

	// ===== Yahoo 系（~8%，含日本 Yahoo 针对 docomo 场景加分）=====
	{"yahoo.com", []string{"s2048", "s1024", "s1"}, 6, false, 2048},
	{"yahoo.co.jp", []string{"s2048", "s1024"}, 6, false, 2048},
	{"ymail.com", []string{"s2048"}, 2, false, 2048},

	// ===== Apple 系（~4%）=====
	{"icloud.com", []string{"1a1hai", "sig1"}, 5, false, 2048},
	{"me.com", []string{"1a1hai"}, 2, false, 2048},

	// ===== Amazon SES（~6%，selector 每次动态 32 字符随机生成）=====
	{"amazonses.com", nil, 10, true, 2048},

	// ===== ESP 邮件服务商（~11%）=====
	{"sendgrid.net", []string{"s1", "smtpapi", "m1"}, 5, false, 2048},
	{"sendgrid.me", []string{"s1"}, 1, false, 2048},
	{"mailgun.org", []string{"k1", "mg", "pic"}, 4, false, 2048},
	{"mandrillapp.com", []string{"mandrill", "mte1"}, 3, false, 2048},
	{"mcsv.net", []string{"k2"}, 2, false, 2048},
	{"mtasv.net", []string{"20150623"}, 1, false, 2048},
	{"sparkpostmail.com", []string{"scph1220"}, 1, false, 2048},
	{"hubspotemail.net", []string{"hs1"}, 2, false, 2048},

	// ===== 日本运营商域（~10%，2026-05-18 新增，针对日本市场加权）=====
	{"docomo.ne.jp", []string{"docomo", "mail"}, 5, false, 2048},
	{"softbank.ne.jp", []string{"sb", "softbank"}, 4, false, 2048},
	{"au.com", []string{"au", "default"}, 4, false, 2048},
	{"ezweb.ne.jp", []string{"ezweb"}, 3, false, 2048},
	{"kddi.com", []string{"kddi"}, 2, false, 2048},

	// ===== 日本本地邮件商（~5%）=====
	{"nifty.com", []string{"default"}, 2, false, 2048},
	{"biglobe.ne.jp", []string{"default"}, 2, false, 2048},
	{"so-net.ne.jp", []string{"s1024"}, 2, false, 1024},
	{"ocn.ad.jp", []string{"default"}, 1, false, 2048},
	{"plala.or.jp", []string{"default"}, 1, false, 2048},

	// ===== 韩国（~5%，2026-05-18 新增）=====
	{"naver.com", []string{"s2048", "naver"}, 3, false, 2048},
	{"daum.net", []string{"daum"}, 2, false, 2048},
	{"kakao.com", []string{"kakao"}, 2, false, 2048},
	{"hanmail.net", []string{"hanmail"}, 1, false, 1024},

	// ===== 欧洲（~5%，2026-05-18 新增）=====
	{"gmx.de", []string{"s1", "k1"}, 2, false, 2048},
	{"web.de", []string{"webde", "default"}, 2, false, 2048},
	{"mail.ru", []string{"mailru", "selector"}, 2, false, 2048},
	{"yandex.ru", []string{"mail", "yandex"}, 2, false, 2048},
	{"tutanota.com", []string{"tutanota"}, 1, false, 4096},

	// ===== 国内主流（~7%，2026-05-18 新增，留作未来扩国内市场）=====
	{"163.com", []string{"s2048", "s1024"}, 3, false, 2048},
	{"qq.com", []string{"s201512", "s202004"}, 3, false, 2048},
	{"126.com", []string{"s2048"}, 2, false, 2048},
	{"sina.com", []string{"s1024"}, 1, false, 1024},
	{"sohu.com", []string{"sohu"}, 1, false, 1024},
	{"aliyun.com", []string{"aliyun"}, 2, false, 2048},
	{"foxmail.com", []string{"foxmail"}, 1, false, 1024},

	// ===== 企业 SaaS / 营销邮件（~6%，长尾多样性）=====
	{"salesforce.com", []string{"200608"}, 1, false, 2048},
	{"pardot.com", []string{"pardotdkim"}, 1, false, 2048},
	{"linkedin.com", []string{"proddkim1024"}, 1, false, 1024},
	{"paypal.com", []string{"pp-dkim1"}, 1, false, 2048},
	{"adobe.com", []string{"s2048"}, 1, false, 2048},
	{"zoho.com", []string{"zmail"}, 1, false, 2048},
	{"zendesk.com", []string{"mail"}, 1, false, 2048},
	{"intercom-mail.com", []string{"intercom"}, 1, false, 2048},
	{"protonmail.com", []string{"protonmail"}, 1, false, 4096},
	{"fastmail.com", []string{"fm1"}, 1, false, 2048},

	// ===== 长尾欧美（~3%，2026-05-18 新增）=====
	{"fastmail.fm", []string{"fm1"}, 1, false, 2048},
	{"gmx.com", []string{"k1"}, 1, false, 2048},
	{"mailbox.org", []string{"mbo1"}, 1, false, 2048},
	{"runbox.com", []string{"runbox"}, 1, false, 2048},

	// ===== 日本运营商 / MVNO / ISP 扩展（~12%，2026-05-18 第二批新增）=====
	// 针对日本市场加权：iPhone Softbank 邮箱 / Y!mobile / UQ / 楽天 / mineo / IIJmio / 老牌 ISP
	// 配合 dkimHFieldsByStyle["japan"] 风格池 → d= 日本域 + h= 日本风格，协调一致
	{"i.softbank.jp", []string{"sb-iphone", "softbank"}, 5, false, 2048}, // iPhone 用户 Softbank 邮箱（日本 iPhone 市占 60%+）
	{"ymobile.ne.jp", []string{"ymobile"}, 3, false, 2048},               // Y!mobile（Softbank 子品牌）
	{"uqmobile.jp", []string{"uqmobile"}, 3, false, 2048},                // UQ mobile（KDDI 子品牌）
	{"rakuten-mobile.jp", []string{"rakuten-mobile"}, 3, false, 2048},    // 楽天モバイル（第四大运营商）
	{"mineo.jp", []string{"mineo"}, 2, false, 2048},                      // Mineo（最大独立 MVNO）
	{"iijmio.jp", []string{"iijmio"}, 2, false, 2048},                    // IIJ mio
	{"ocn.ne.jp", []string{"ocn", "default"}, 2, false, 2048},            // OCN（跟 ocn.ad.jp 配套）
	{"dion.ne.jp", []string{"dion"}, 1, false, 2048},                     // DION（KDDI 旗下老 ISP）
	{"odn.ne.jp", []string{"odn"}, 1, false, 1024},                       // ODN（Softbank 旗下偏老 ISP，1024 RSA）
	{"zaq.ne.jp", []string{"zaq"}, 1, false, 1024},                       // J:COM CATV（偏老，1024 RSA）
}

// 反指纹环形缓冲区容量（每个 HeaderGenerator/worker 独立维护）
// 8 = 同一 worker 最近 8 次抽样不重复；50 个池子下避免重复几乎不会失败
const dkimRecentRingSize = 8

// Amazon SES 风格 selector 的字符集（base32 小写字母 + 数字 2-7，共 32 字符）
const dkimSESCharset = "abcdefghijklmnopqrstuvwxyz234567"

// HeaderGenerator 邮件头生成器
// 【修复问题2】每个实例拥有独立的随机数生成器，避免全局rand争锁
// 【方案 B 新增】dkimRecent 环形缓冲区用于伪 DKIM 选源的反指纹去重
// 【扩展邮件头 2026-05-13】headerCurrentSet/headerEmailsLeft 实现 worker 级随机邮件头反指纹
type HeaderGenerator struct {
	cfg    *config.HeadersConfig
	random *mathrand.Rand

	// 【方案 B】伪 DKIM 反指纹：记录最近用过的 dkimExternalSources 索引，
	// 抽样时排除最近 N 次结果，避免短时间内同一 worker 反复使用相同 d+s 组合
	dkimRecent    []int // 环形缓冲区（容量 = dkimRecentRingSize）
	dkimRecentPos int   // 下一次写入的位置

	// 【扩展邮件头】worker 级随机邮件头反指纹：每个 worker 维持一组随机抽样的头组合,
	// 持续 50-200 封邮件后才重抽。同一 worker 内邮件特征一致（像同一系统出站），
	// 不同 worker 之间和长期内特征不同（避免整体指纹固化）。
	headerCurrentSet []int // 当前组合：候选池里被选中的索引列表
	headerEmailsLeft int   // 当前组合还能用多少封邮件（≤0 时下封邮件触发重抽）

	// 【2026-05-27 从 PowerMTA 移植】Received（随机）顺序模式 worker 独立索引（B3 决策：worker 内顺序）
	// 顺序模式下：第 N 封邮件用第 (N % len(templates)) 个模板
	// 随机模式下：此字段不用
	receivedRandomSeqIdx int

	// 【2026-06-15】Message-ID 计数类风格（javamail/ts_uuid_counter/uuid_seq/enterprise_multiseg）
	// 用的 worker 独立递增计数器（HeaderGenerator 为 per-worker 单线程，与 receivedRandomSeqIdx 同模式，无需加锁）
	messageIDSeqIdx int

	// 【2026-05-27 从 PowerMTA 移植】List-Unsubscribe 顺序模式索引（三套模板各自独立，批次 4 启用）
	// real / custom / random 各自独立计数，互不影响
	listUnsubRealSeqIdx   int
	listUnsubCustomSeqIdx int
	listUnsubRandomSeqIdx int

	// fingerprintKey 发信身份指纹（hostname/发信域），跨任务稳定；不含 job。
	fingerprintKey string
}

// NewHeaderGenerator 创建邮件头生成器
// 【v62修复】使用 crypto/rand 生成安全种子 + workerID 偏移，彻底避免并发种子碰撞
// 【方案 B 新增】初始化伪 DKIM 反指纹环形缓冲区
// 【扩展邮件头 2026-05-13】随机邮件头组合的状态默认空，首封邮件触发首次抽样
func NewHeaderGenerator(cfg *config.HeadersConfig, workerID int) *HeaderGenerator {
	// 全部填 -1 表示"空槽" —— 不能填 0，因为 0 是 dkimExternalSources 的有效索引,
	// 否则第一次抽样会把 idx=0 误判为"最近用过"，导致选源逻辑首轮异常
	recent := make([]int, dkimRecentRingSize)
	for i := range recent {
		recent[i] = -1
	}
	return &HeaderGenerator{
		cfg:                   cfg,
		random:                mathrand.New(mathrand.NewSource(cryptoSeed(workerID))),
		dkimRecent:            recent,
		dkimRecentPos:         0,
		headerCurrentSet:      nil,
		headerEmailsLeft:      0,
		receivedRandomSeqIdx:  0, // 【2026-05-27 从 PowerMTA 移植】Received 随机顺序索引
		messageIDSeqIdx:       0, // 【2026-06-15】Message-ID 计数类风格 worker 独立计数器
		listUnsubRealSeqIdx:   0, // 批次 4 用
		listUnsubCustomSeqIdx: 0, // 批次 4 用
		listUnsubRandomSeqIdx: 0, // 批次 4 用
	}
}

// GenerateHeaders 生成启用的自定义邮件头（不含Received和DKIM，它们在builder中单独处理）
// fromAddress: 发件人地址, toAddress: 收件人地址, domain: 发件域名
// 【2026-05-27 从 PowerMTA 移植】签名扩展加 vp + recipient（vp/recipient 可为 nil；批次 4 List-Unsub 4 模式池模式下需要）
func (hg *HeaderGenerator) GenerateHeaders(fromAddress, toAddress, domain string, vp *VariableProcessor, recipient *types.Recipient) string {
	if hg.cfg == nil || !hg.cfg.Enabled {
		return ""
	}

	var sb strings.Builder

	// Reply-To
	if hg.cfg.ReplyTo {
		sb.WriteString(fmt.Sprintf("Reply-To: %s\r\n", hg.getReplyToAddress(fromAddress, domain)))
	}

	// Return-Path
	if hg.cfg.ReturnPath {
		sb.WriteString(fmt.Sprintf("Return-Path: <%s>\r\n", hg.getReturnPathAddress(fromAddress, domain)))
	}

	// X-Mailer（按 client_profile 池轮换）
	if hg.cfg.XMailer {
		sb.WriteString(fmt.Sprintf("X-Mailer: %s\r\n", hg.getProfileXMailer()))
	}

	// User-Agent（部分客户端/Web 发信会带；按 profile 轮换）
	if hg.cfg.UserAgent {
		if ua := hg.getProfileUserAgent(); ua != "" {
			sb.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
		}
	}

	// X-Priority
	if hg.cfg.XPriority {
		sb.WriteString(fmt.Sprintf("X-Priority: %s\r\n", hg.getXPriorityValue()))
	}

	// Importance
	if hg.cfg.Importance {
		sb.WriteString(fmt.Sprintf("Importance: %s\r\n", hg.getImportanceValue()))
	}

	// Accept-Language
	if hg.cfg.AcceptLanguage {
		sb.WriteString(fmt.Sprintf("Accept-Language: %s\r\n", hg.getAcceptLanguageValue()))
	}

	// Content-Language
	if hg.cfg.ContentLanguage {
		sb.WriteString(fmt.Sprintf("Content-Language: %s\r\n", hg.getContentLanguageValue()))
	}

	// 注意：用户自定义邮件头（CustomHeadersText）已移到 builder.go 的 buildRawEmail 中处理，
	// 因为 builder 那里有完整的 recipient 和 data 上下文，可以正确做变量替换和模板渲染。
	// 不要在这里处理！

	// 【扩展邮件头 2026-05-13】P0 必加 + P1/P2/P3 反指纹头（可选随机抽样）
	// 从 fromAddress 提取实际域名以保险（domain 参数已是发件域但容错）
	emitDomain := domain
	if idx := strings.LastIndex(fromAddress, "@"); idx >= 0 && idx < len(fromAddress)-1 {
		emitDomain = fromAddress[idx+1:]
	}
	// 【2026-05-27 批次 4 从 PowerMTA 移植】emitExtendedHeaders 签名扩展加 fromAddress + vp + recipient
	sb.WriteString(hg.emitExtendedHeaders(fromAddress, emitDomain, vp, recipient))

	return sb.String()
}

// ===== Received 头生成 =====

// generateReceived 生成 Received 头链
// 【2026-05-22 从 PowerMTA 移植】多 hop 重写
//   - 加权抽样 hop 数：1 hop 20% / 2 hop 50% / 3 hop 30%
//   - 1 hop：用 ESMTPSA 客户端提交格式（与旧 generateReceived 100% 等价，向后兼容）
//   - 多 hop：bottom（客户端 ESMTPSA 提交）→ middle（内部中继 ESMTP，仅 3 hop）→ top（MX 接收 ESMTPS）
//   - 时序：times[0]=top=now，每往下 hop 减 1-30 秒，保证 top > middle > bottom
//   - 节点链接：top.from = 中继节点 = middle.by（3 hop）/ = internal.by（2 hop）
//                middle.from = internal = bottom.by
//   - 输出顺序：top → middle → bottom（新 Received 在上面，符合 RFC 5321 §4.4 邮件头追加规则）
//
// 设计目的：原单 hop 是反指纹最大短板（真实邮件 95% 有 2-4 hop）
func (hg *HeaderGenerator) generateReceived(fromAddress, toAddress, domain string) string {
	_ = fromAddress // 暂未使用，保留以维持函数签名兼容
	now := time.Now()
	tlsVersion := "TLS1_2,"
	cipher := tlsCiphers[0]
	hopCount := 2
	if hg.cfg != nil && hg.cfg.ReceivedDeterministic {
		// 固定 2-hop + TLS1_2，消除 50/50 TLS 与 hop 数随机导致的进箱波动
	} else {
		tlsVersion = hg.randomChoice([]string{"TLS1_2,", "TLS1_3,"})
		cipher = hg.randomChoice(tlsCiphers)
		r := safeIntn(hg.random, 100)
		switch {
		case r < 20:
			hopCount = 1
		case r < 70:
			hopCount = 2
		default:
			hopCount = 3
		}
	}

	// 时序：times[0]=top=now；每往下 hop 减 1-30 秒
	times := make([]time.Time, hopCount)
	times[0] = now
	for i := 1; i < hopCount; i++ {
		delta := time.Duration(safeIntn(hg.random, 29)+1) * time.Second
		times[i] = times[i-1].Add(-delta)
	}

	// 客户端节点（bottom hop 用，始终生成）
	clientDomain := hg.generateRandomDomain()
	clientIP := hg.generateRandomIPRealistic()
	username := hg.generateRandomUsername()

	// 单 hop：与旧 generateReceived 行为完全一致（向后兼容）
	if hopCount == 1 {
		return formatReceivedClientSubmit(
			clientDomain, clientIP, username, domain,
			domain, hg.randomChoice(mailServerSoftware), hg.generateMailID(),
			toAddress, tlsVersion, cipher, now,
		)
	}

	// 多 hop：构造节点链
	internalDomain := hg.generateRandomDomain()
	internalIP := hg.generateRandomIPRealistic()
	var relayDomain, relayIP string
	if hopCount == 3 {
		relayDomain = hg.generateRandomDomain()
		relayIP = hg.generateRandomIPRealistic()
	}

	// 拼装顺序：top → middle → bottom
	var sb strings.Builder

	// top hop：MX 接收 ESMTPS（by 发件方域，from 来自上一个中继）
	topFromDomain := internalDomain
	topFromIP := internalIP
	if hopCount == 3 {
		topFromDomain = relayDomain
		topFromIP = relayIP
	}
	sb.WriteString(formatReceivedMxAccept(
		topFromDomain, topFromIP,
		domain, hg.randomChoice(mailServerSoftware), hg.generateMailID(),
		toAddress, tlsVersion, cipher, times[0],
	))

	// middle hop（仅 3 hop）：内部中继 ESMTP（不带 AUTH）
	if hopCount == 3 {
		sb.WriteString(formatReceivedInternalRelay(
			internalDomain, internalIP,
			relayDomain, relayIP,
			hg.generateMailID(),
			toAddress, tlsVersion, cipher, times[1],
		))
	}

	// bottom hop：客户端 ESMTPSA 提交（与单 hop 同款格式）
	sb.WriteString(formatReceivedClientSubmit(
		clientDomain, clientIP, username, domain,
		internalDomain, hg.randomChoice(mailServerSoftware), hg.generateMailID(),
		toAddress, tlsVersion, cipher, times[hopCount-1],
	))

	return sb.String()
}

// formatReceivedClientSubmit 生成"客户端 ESMTPSA 提交"风格 Received 头
// 与旧 generateReceived 输出格式 100% 一致（确保 1 hop 模式向后兼容）
func formatReceivedClientSubmit(fromDomain, fromIP, user, userDomain,
	byDomain, software, mailID, toAddress, tls, cipher string, t time.Time) string {
	return fmt.Sprintf("Received: from %s ([%s])\r\n"+
		" (Authenticated sender: %s@%s)\r\n"+
		" by %s (%s) with ESMTPSA id %s\r\n"+
		" for <%s>;\r\n"+
		" %s %s %s\r\n",
		fromDomain, fromIP,
		user, userDomain,
		byDomain, software, mailID,
		toAddress,
		tls, cipher, t.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

// formatReceivedInternalRelay 生成"内部中继 ESMTP"风格 Received 头（不带 AUTH）
// 真实场景：邮件从客户端进入内部中继后，由内部中继转给下一个外部中继
func formatReceivedInternalRelay(fromDomain, fromIP, byDomain, byIP,
	mailID, toAddress, tls, cipher string, t time.Time) string {
	return fmt.Sprintf("Received: from %s (%s [%s])\r\n"+
		" by %s ([%s]) with ESMTP id %s\r\n"+
		" for <%s>;\r\n"+
		" %s %s %s\r\n",
		fromDomain, fromDomain, fromIP,
		byDomain, byIP, mailID,
		toAddress,
		tls, cipher, t.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

// formatReceivedMxAccept 生成"MX 接收 ESMTPS"风格 Received 头
// 真实场景：邮件从最后一个中继投递到目标域 MX 时的接收记录
func formatReceivedMxAccept(fromDomain, fromIP, byDomain, software, mailID,
	toAddress, tls, cipher string, t time.Time) string {
	return fmt.Sprintf("Received: from %s ([%s])\r\n"+
		" by %s (%s) with ESMTPS id %s\r\n"+
		" for <%s>;\r\n"+
		" %s %s %s\r\n",
		fromDomain, fromIP,
		byDomain, software, mailID,
		toAddress,
		tls, cipher, t.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

// ===== DKIM-Signature 头生成 =====

// 【2026-05-22 从 PowerMTA 移植】DKIM 规范化算法加权池（c= 字段）
// 按真实邮件世界的实际分布加权，避免 c= 永远是 relaxed/relaxed 形成指纹
var dkimCanonicalizations = []struct {
	value  string
	weight int
}{
	{"relaxed/relaxed", 70},
	{"relaxed/simple", 15},
	{"simple/simple", 10},
	{"simple/relaxed", 5},
}

// 【2026-05-22 从 PowerMTA 移植】h= 字段按发件方风格的真实模板池
// 不同 ESP 的 h= 字段在大小写、顺序、长度上差异显著，按风格池模拟真实分布
// gmail 系一律小写 / outlook 系一律首字大写 / yahoo 系含 Received / SES 自己的顺序 /
// japan 针对日本 ESP（docomo / softbank / au / Y!mobile / UQ / 楽天 / MVNO / 老牌 ISP）/ 其他归 generic
var dkimHFieldsByStyle = map[string][]string{
	"gmail": {
		"from:to:subject:date:message-id:mime-version:content-type",
		"from:to:subject:date:message-id:mime-version:reply-to",
		"to:cc:from:subject:message-id:date:mime-version",
	},
	"outlook": {
		"From:To:Subject:Date:Message-ID:Content-Type:Content-Transfer-Encoding:MIME-Version",
		"MIME-Version:Date:From:To:Subject:Message-ID:Content-Type:Content-Transfer-Encoding",
	},
	"yahoo": {
		"Received:From:Reply-To:Subject:Date:To:Message-ID:Content-Type:Content-Transfer-Encoding:MIME-Version",
		"Date:From:Reply-To:Subject:To:MIME-Version:Content-Type:Message-ID",
	},
	"ses": {
		"Date:From:Reply-To:To:Message-ID:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding",
		"From:To:Subject:Date:Message-ID:MIME-Version:Content-Type",
	},
	// japan 风格：针对日本运营商 / MVNO / ISP 域名
	// 配合 dkimExternalSources 中 20 个日本域使用，实现 d= 日本域 + h= 日本风格协调一致
	"japan": {
		// 模板 1：日本 ESP 经典风格（含 Received，长形式，常见于 nifty / biglobe / so-net 等）
		"Received:From:Reply-To:To:Subject:Date:Message-ID:MIME-Version:Content-Type:Content-Transfer-Encoding",
		// 模板 2：docomo / softbank 运营商风格（首字大写，含 Sender）
		"From:Sender:Reply-To:To:Subject:Date:Message-ID:Content-Type:MIME-Version",
		// 模板 3：楽天 / MVNO 现代风格（全小写）
		"from:to:subject:date:message-id:mime-version:content-type:content-transfer-encoding",
	},
	"generic": {
		"From:To:Subject:Date:Message-ID:MIME-Version:Content-Type:Content-Transfer-Encoding",
		"from:to:subject:date:message-id:mime-version:content-type",
		"From:Reply-To:To:Subject:Date:Message-ID:Content-Type",
	},
}

// generateDkimSignature 生成伪 DKIM-Signature 头（【方案 B】外部域伪转发签名）
// 设计要点见文件顶部 dkimExternalSources 的注释块。
//
// 参数 fromAddress / domain 保留以维持函数签名与调用方兼容，但本实现故意不使用 ——
// 伪签名的 d= 指向外部大厂域而非发件方真实域名，将校验失败归因于"中转链路签名损坏"
// （邮件常态、反垃圾宽容），而非"发件方自家签名都对不上"（被视为伪造、严重扣分）。
//
// 【2026-05-22 字段多样化】c=/h=/b= 长度不再固定：
//   - c= 按 dkimCanonicalizations 加权抽样（relaxed/relaxed 70% 等真实分布）
//   - h= 按发件方风格池抽样（gmail 小写 / outlook 大写 / yahoo 含 Received / ses / japan / generic）
//   - b= 长度对应 selector 的 RSA 位数（1024/2048/4096 → 不同 base64 长度）
//   消除"d= 在 72 个域之间换、但其他字段固定"的反指纹漏洞。
func (hg *HeaderGenerator) generateDkimSignature(fromAddress, domain string) string {
	_ = fromAddress // 故意不使用，理由见上方注释
	_ = domain

	src := hg.pickDkimExternalSource()

	// selector：SES 风格的每次动态生成 32 字符 base32 串，其余从该源的候选池里随机选
	var selector string
	if src.isSESLike {
		selector = hg.generateSESLikeSelector()
	} else if len(src.selectors) > 0 {
		selector = src.selectors[safeIntn(hg.random, len(src.selectors))]
	} else {
		// 兜底：数据池不一致时落到该分支（正常配置不会到达）
		selector = "default"
	}

	// 【2026-05-22】字段多样化
	canonicalization := hg.pickDkimCanonicalization()
	hFields := hg.pickDkimHFields(src.domain)
	bByteCount := dkimSignatureByteCount(src.rsaBits)

	bh := generateRandomBase64(32)
	sig := generateRandomBase64Multiline(bByteCount)
	timestamp := time.Now().Unix()

	return fmt.Sprintf("DKIM-Signature: v=1; a=rsa-sha256; c=%s;\r\n"+
		" d=%s; s=%s; t=%d;\r\n"+
		" h=%s;\r\n"+
		" bh=%s;\r\n"+
		" b=%s\r\n",
		canonicalization,
		src.domain, selector, timestamp,
		hFields,
		bh,
		sig)
}

// pickDkimCanonicalization 按权重抽样 c= 字段值
// 【2026-05-22 从 PowerMTA 移植】避免 c= 永远是 relaxed/relaxed 形成单一指纹
func (hg *HeaderGenerator) pickDkimCanonicalization() string {
	totalWeight := 0
	for i := range dkimCanonicalizations {
		totalWeight += dkimCanonicalizations[i].weight
	}
	if totalWeight <= 0 {
		return "relaxed/relaxed"
	}
	r := safeIntn(hg.random, totalWeight)
	for i := range dkimCanonicalizations {
		r -= dkimCanonicalizations[i].weight
		if r < 0 {
			return dkimCanonicalizations[i].value
		}
	}
	// 兜底（理论上 r < totalWeight 不会到达）
	return dkimCanonicalizations[len(dkimCanonicalizations)-1].value
}

// pickDkimHFields 根据发件方域名选择对应风格的 h= 字段
// 【2026-05-22 从 PowerMTA 移植】根据 dkimExternalSource.domain 匹配 dkimHFieldsByStyle 中的风格模板
// 匹配不到的归 generic 风格（覆盖所有非主流大厂域）
func (hg *HeaderGenerator) pickDkimHFields(srcDomain string) string {
	var style string
	switch srcDomain {
	case "gmail.com", "googlemail.com", "google.com":
		style = "gmail"
	case "outlook.com", "hotmail.com", "live.com", "microsoft.com", "office365.com":
		style = "outlook"
	case "yahoo.com", "yahoo.co.jp", "ymail.com":
		// 注：yahoo.co.jp 保留在 yahoo 风格（真实 Yahoo Japan DKIM 签名跟 yahoo.com 风格非常接近）
		style = "yahoo"
	case "amazonses.com":
		style = "ses"
	// 日本运营商 / MVNO / ISP 共 20 个域 → japan 风格
	// 5 个原运营商 + 5 个原本地 ISP + 10 个新增（含 i.softbank.jp / Y!mobile / UQ / 楽天 / mineo / IIJmio 等）
	case "docomo.ne.jp", "softbank.ne.jp", "au.com", "ezweb.ne.jp", "kddi.com",
		"nifty.com", "biglobe.ne.jp", "so-net.ne.jp", "ocn.ad.jp", "plala.or.jp",
		"i.softbank.jp", "ymobile.ne.jp", "uqmobile.jp", "rakuten-mobile.jp",
		"mineo.jp", "iijmio.jp", "ocn.ne.jp", "dion.ne.jp", "odn.ne.jp", "zaq.ne.jp":
		style = "japan"
	default:
		style = "generic"
	}
	pool := dkimHFieldsByStyle[style]
	if len(pool) == 0 {
		// 兜底（如果某天 dkimHFieldsByStyle 被改坏了，仍能返回合法 h= 值）
		return "From:To:Subject:Date:Message-ID:MIME-Version:Content-Type:Content-Transfer-Encoding"
	}
	return pool[safeIntn(hg.random, len(pool))]
}

// dkimSignatureByteCount 根据 RSA 位数计算 b= 字段的字节数
// 【2026-05-22 从 PowerMTA 移植】b= 的字节数 = RSA 密钥位数 / 8（base64 后字符数约 byteCount * 4/3 向上取整）
//   1024-bit → 128 字节 → 172 字符 base64
//   2048-bit → 256 字节 → 344 字符 base64
//   4096-bit → 512 字节 → 684 字符 base64
// 未知位数兜底 256 字节（与历史行为兼容）
func dkimSignatureByteCount(rsaBits int) int {
	switch rsaBits {
	case 1024:
		return 128
	case 4096:
		return 512
	case 2048:
		return 256
	default:
		return 256
	}
}

// pickDkimExternalSource 按权重加权抽样 dkimExternalSources，并尽量避开 worker 最近用过的源
//
// 实现要点：
//  1. 累计 totalWeight 后用一次 safeIntn 实现加权抽样（O(n) 扫描）
//  2. 最多重试 dkimRecentRingSize+2 次以躲开最近历史；超过仍未找到就接受重复
//     （50 个源、最近 8 个，理论上必然能找到非重复项；上限是兜底防极端 case）
func (hg *HeaderGenerator) pickDkimExternalSource() *dkimExternalSource {
	// 兜底：数据池为空（理论不可能）
	if len(dkimExternalSources) == 0 {
		return &dkimExternalSource{domain: "gmail.com", selectors: []string{"20230601"}}
	}

	totalWeight := 0
	for i := range dkimExternalSources {
		totalWeight += dkimExternalSources[i].weight
	}
	// 兜底：所有权重均 ≤ 0（理论不可能），退化为首项
	if totalWeight <= 0 {
		return &dkimExternalSources[0]
	}

	maxRetry := dkimRecentRingSize + 2
	lastIdx := 0
	for retry := 0; retry < maxRetry; retry++ {
		r := safeIntn(hg.random, totalWeight)
		idx := 0
		for i := range dkimExternalSources {
			r -= dkimExternalSources[i].weight
			if r < 0 {
				idx = i
				break
			}
		}
		lastIdx = idx
		if !hg.isDkimSourceRecent(idx) {
			hg.recordDkimSource(idx)
			return &dkimExternalSources[idx]
		}
	}

	// 重试用完仍未避开最近历史 —— 接受重复（极端情况下池子过小或权重过偏）
	hg.recordDkimSource(lastIdx)
	return &dkimExternalSources[lastIdx]
}

// isDkimSourceRecent 检查源索引 idx 是否在最近用过的环形缓冲区中
func (hg *HeaderGenerator) isDkimSourceRecent(idx int) bool {
	for _, v := range hg.dkimRecent {
		if v == idx {
			return true
		}
	}
	return false
}

// recordDkimSource 把刚使用的源索引写入环形缓冲区（覆盖最旧的一条）
func (hg *HeaderGenerator) recordDkimSource(idx int) {
	hg.dkimRecent[hg.dkimRecentPos] = idx
	hg.dkimRecentPos = (hg.dkimRecentPos + 1) % dkimRecentRingSize
}

// generateSESLikeSelector 生成 Amazon SES 风格的 32 字符 base32 随机 selector
// 真实 SES 中每个客户独立分配此类 selector，因此动态生成不会暴露指纹
func (hg *HeaderGenerator) generateSESLikeSelector() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = dkimSESCharset[safeIntn(hg.random, len(dkimSESCharset))]
	}
	return string(b)
}

// ========================================================================
// 【扩展邮件头 2026-05-13】emitExtendedHeaders 实现
// 调度逻辑:
//   1. P0 头（送达率刚需）：勾选了就总是加，不参与随机
//   2. P1/P2/P3 头：
//      - RandomEnabled=false 时：勾选了就加（多少加多少）
//      - RandomEnabled=true 时：从勾选项里随机抽 N 个（N 在 [RandomMin, RandomMax] 范围）
//   3. 联动组（XTMASGroup / XSFMCGroup）：作为单个槽位参与，被选中则一次加多个头
//   4. Worker 级反指纹：随机抽样的组合在 50-200 封邮件后才重抽，避免每封都不同造成
//      "该 IP 邮件特征飘忽不定" 的反向指纹
// ========================================================================

// headerSlot 一个候选随机槽位（独立头 = 1 个头；联动组 = 多个头）
type headerSlot struct {
	enabled  func(cfg *config.HeadersConfig) bool
	generate func(hg *HeaderGenerator, domain string) string
}

// extendedHeaderSlots 候选池注册表（顺序固定，索引稳定）
// 注意：P0 头不在此列（它们走单独的"总是加"路径）
var extendedHeaderSlots = []headerSlot{
	// P1
	{func(c *config.HeadersConfig) bool { return c.ErrorsTo }, (*HeaderGenerator).getErrorsTo},
	//开启伪装的时候插入sender字段
	{func(c *config.HeadersConfig) bool { return c.Sender && !c.CustomFromEnabled }, (*HeaderGenerator).getSender},
	{func(c *config.HeadersConfig) bool { return c.Organization }, func(hg *HeaderGenerator, _ string) string { return hg.getOrganization() }},
	{func(c *config.HeadersConfig) bool { return c.XOriginatingIP }, func(hg *HeaderGenerator, _ string) string { return hg.getXOriginatingIP() }},
	{func(c *config.HeadersConfig) bool { return c.AutoSubmitted }, func(_ *HeaderGenerator, _ string) string { return "Auto-Submitted: auto-generated\r\n" }},
	{func(c *config.HeadersConfig) bool { return c.Comments }, func(hg *HeaderGenerator, _ string) string { return hg.getComments() }},
	{func(c *config.HeadersConfig) bool { return c.Keywords }, func(hg *HeaderGenerator, _ string) string { return hg.getKeywords() }},
	{func(c *config.HeadersConfig) bool { return c.XReportAbuse }, (*HeaderGenerator).getXReportAbuse},
	{func(c *config.HeadersConfig) bool { return c.XCSAComplaints }, func(_ *HeaderGenerator, _ string) string { return "X-CSA-Complaints: whitelist-complaints@eco.de\r\n" }},
	// P2 Outlook
	{func(c *config.HeadersConfig) bool { return c.XMSMailPriority }, func(hg *HeaderGenerator, _ string) string { return hg.getXMSMailPriority() }},
	{func(c *config.HeadersConfig) bool { return c.ThreadIndex }, func(hg *HeaderGenerator, _ string) string { return hg.getThreadIndex() }},
	{func(c *config.HeadersConfig) bool { return c.ThreadTopic }, func(hg *HeaderGenerator, _ string) string { return hg.getThreadTopic() }},
	{func(c *config.HeadersConfig) bool { return c.XAutoResponseSuppress }, func(hg *HeaderGenerator, _ string) string { return hg.getXAutoResponseSuppress() }},
	// P2 行为
	{func(c *config.HeadersConfig) bool { return c.ReturnReceiptTo }, (*HeaderGenerator).getReturnReceiptTo},
	{func(c *config.HeadersConfig) bool { return c.DispositionNotificationTo }, (*HeaderGenerator).getDispositionNotificationTo},
	{func(c *config.HeadersConfig) bool { return c.XEntityRefID }, func(_ *HeaderGenerator, _ string) string { return "X-Entity-Ref-ID: " + generateGUID() + "\r\n" }},
	// P3 营销
	{func(c *config.HeadersConfig) bool { return c.XCampaignID }, func(hg *HeaderGenerator, _ string) string { return hg.getXCampaignID() }},
	{func(c *config.HeadersConfig) bool { return c.XMailerLID }, func(hg *HeaderGenerator, _ string) string { return hg.getXMailerLID() }},
	{func(c *config.HeadersConfig) bool { return c.CampaignID }, func(hg *HeaderGenerator, _ string) string { return hg.getCampaignID() }},
	// P3 联动组（单槽位 → 多头）
	{func(c *config.HeadersConfig) bool { return c.XTMASGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXTMASGroup() }},
	{func(c *config.HeadersConfig) bool { return c.XSFMCGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXSFMCGroup() }},
	// 【2026-05-21 从 PowerMTA 移植】4 组企业网关联动头（IP 段不敏感，仿 X-TM-AS-* / X-SFMC-* 套路）
	{func(c *config.HeadersConfig) bool { return c.XBarracudaGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXBarracudaGroup() }},
	{func(c *config.HeadersConfig) bool { return c.XProofpointGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXProofpointGroup() }},
	{func(c *config.HeadersConfig) bool { return c.XMimecastGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXMimecastGroup() }},
	{func(c *config.HeadersConfig) bool { return c.XSymantecGroup }, func(hg *HeaderGenerator, _ string) string { return hg.getXSymantecGroup() }},
	// 【扩展邮件头 v2 2026-05-14】4 个新独立头（List-ID 是 P0 不进随机池，单独处理）
	{func(c *config.HeadersConfig) bool { return c.XOriginatingEmail }, (*HeaderGenerator).getXOriginatingEmail},
	{func(c *config.HeadersConfig) bool { return c.XMimeOLE }, func(hg *HeaderGenerator, _ string) string { return hg.getXMimeOLE() }},
	{func(c *config.HeadersConfig) bool { return c.XMailerVersion }, func(hg *HeaderGenerator, _ string) string { return hg.getXMailerVersion() }},
	{func(c *config.HeadersConfig) bool { return c.XOriginalArrivalTime }, func(hg *HeaderGenerator, _ string) string { return hg.getXOriginalArrivalTime() }},
}

// 当前随机组合的"使用寿命"区间：每次重抽后用 50 + Intn(151) 封邮件
// 50 是最短（避免每封都换造成反向指纹），200 是最长（避免一组用太久全靠这几个头）
const (
	headerRandomLifespanMin = 50
	headerRandomLifespanGap = 151 // 上限 = Min + Gap - 1 = 200
)

// emitExtendedHeaders 生成扩展邮件头的总入口
// 【2026-05-27 批次 4 从 PowerMTA 移植】签名扩展加 fromAddress + vp + recipient
func (hg *HeaderGenerator) emitExtendedHeaders(fromAddress, domain string, vp *VariableProcessor, recipient *types.Recipient) string {
	cfg := hg.cfg
	if cfg == nil {
		return ""
	}
	var sb strings.Builder

	// ----- P0 组（送达率刚需）：勾选了就总是加，不参与随机 -----
	if cfg.ListUnsubscribe {
		if lu := hg.getListUnsubscribe(fromAddress, domain, vp, recipient); lu != "" {
			sb.WriteString(lu)
			sb.WriteString("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")
		}
	} else if cfg.ListUnsubscribePost {
		sb.WriteString("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")
	}
	// 【扩展邮件头 v2 2026-05-14】List-ID 也属于 P0（与 List-Unsubscribe 配套）
	if cfg.ListID {
		sb.WriteString(hg.getListID(domain))
	}
	if cfg.FeedbackID {
		sb.WriteString(hg.getFeedbackID(domain))
	}
	if cfg.Precedence {
		sb.WriteString(hg.getPrecedence())
	}

	// ----- P1/P2/P3 池 -----
	// 收集"用户勾选了的"候选槽位索引
	candidates := make([]int, 0, len(extendedHeaderSlots))
	for i, slot := range extendedHeaderSlots {
		if slot.enabled(cfg) {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return sb.String()
	}

	if !cfg.RandomEnabled {
		// 非随机模式：勾选了的都加
		for _, idx := range candidates {
			sb.WriteString(extendedHeaderSlots[idx].generate(hg, domain))
		}
		return sb.String()
	}

	// 随机模式 + worker 级反指纹：若当前组合用完寿命则重抽
	if hg.headerEmailsLeft <= 0 || len(hg.headerCurrentSet) == 0 {
		hg.refreshRandomHeaderSet(candidates)
	}
	hg.headerEmailsLeft--
	for _, idx := range hg.headerCurrentSet {
		// 用户可能在运行中改动勾选状态，校验 idx 仍有效
		if idx >= 0 && idx < len(extendedHeaderSlots) && extendedHeaderSlots[idx].enabled(cfg) {
			sb.WriteString(extendedHeaderSlots[idx].generate(hg, domain))
		}
	}
	return sb.String()
}

// refreshRandomHeaderSet 重抽一组随机邮件头组合（Worker 级反指纹的核心）
func (hg *HeaderGenerator) refreshRandomHeaderSet(candidates []int) {
	if len(candidates) == 0 {
		hg.headerCurrentSet = nil
		hg.headerEmailsLeft = 0
		return
	}

	// 校验 + 修正 [RandomMin, RandomMax]：
	//   1 ≤ min ≤ max ≤ 10
	//   min/max 不超过候选数（不可能"选 10 个但只有 5 个候选"）
	rmin := hg.cfg.RandomMin
	rmax := hg.cfg.RandomMax
	if rmin < 1 {
		rmin = 1
	}
	if rmax > 10 {
		rmax = 10
	}
	if rmax < rmin {
		rmax = rmin
	}
	if rmin > len(candidates) {
		rmin = len(candidates)
	}
	if rmax > len(candidates) {
		rmax = len(candidates)
	}

	// 抽样数量 n ∈ [rmin, rmax]
	var n int
	if rmin == rmax {
		n = rmin
	} else {
		n = rmin + safeIntn(hg.random, rmax-rmin+1)
	}
	if n > len(candidates) {
		n = len(candidates)
	}
	if n < 0 {
		n = 0
	}

	// Fisher-Yates 部分洗牌：从 candidates 抽 n 个无重复
	pool := make([]int, len(candidates))
	copy(pool, candidates)
	for i := 0; i < n; i++ {
		j := i + safeIntn(hg.random, len(pool)-i)
		pool[i], pool[j] = pool[j], pool[i]
	}
	chosen := make([]int, n)
	copy(chosen, pool[:n])

	hg.headerCurrentSet = chosen
	hg.headerEmailsLeft = headerRandomLifespanMin + safeIntn(hg.random, headerRandomLifespanGap)
}

// ========================================================================
// 【扩展邮件头】各头部值生成器
// 设计原则：值要"看起来真"（用真实大厂的命名风格、真实业界格式）
// 注意：generateGUID / randomHexString / generateRandomBase64 是文件级函数,
// 用 crypto/rand，并发安全；hg.random 是 worker 独立实例，无锁。
// ========================================================================

// ----- P0 组 -----

// getListUnsubscribe 生成 List-Unsubscribe 头（go-sender 风格 + 旧 4 模式池兼容）
func (hg *HeaderGenerator) getListUnsubscribe(fromAddress, domain string, vp *VariableProcessor, recipient *types.Recipient) string {
	mode := strings.ToLower(strings.TrimSpace(hg.cfg.ListUnsubMode))

	switch mode {
	case "real":
		if s := hg.renderListUnsubFromPool(hg.cfg.ListUnsubRealTemplates, hg.cfg.ListUnsubRealMode, &hg.listUnsubRealSeqIdx, vp, recipient); s != "" {
			return s
		}
	case "custom":
		if s := hg.renderListUnsubFromPool(hg.cfg.ListUnsubCustomTemplates, hg.cfg.ListUnsubCustomMode, &hg.listUnsubCustomSeqIdx, vp, recipient); s != "" {
			return s
		}
	case "random":
		if s := hg.renderListUnsubFromPool(hg.cfg.ListUnsubRandomTemplates, hg.cfg.ListUnsubRandomMode, &hg.listUnsubRandomSeqIdx, vp, recipient); s != "" {
			return s
		}
	}

	to := ""
	if recipient != nil {
		to = recipient.Email
	}
	if raw := buildListUnsubscribeHeaderValue(to, fromAddress, hg.cfg, domain); raw != "" {
		encoded := encodeListUnsubscribeHeader(raw, hg.cfg)
		return "List-Unsubscribe: " + encoded + "\r\n"
	}

	token := randomHexString(16)
	return fmt.Sprintf("List-Unsubscribe: <mailto:unsubscribe-%s@%s>\r\n", token, domain)
}

// renderListUnsubFromPool 从模板池里选一条 → 渲染变量 → 折叠 → 包装为 "List-Unsubscribe: ...\r\n"
//
// 返回空串表示该模式不可用（池空或 vp/recipient 缺失），调用方应 fallback
// seqIdxPtr 是 worker 独立的顺序模式索引指针（real/custom/random 三套各自传不同的）
func (hg *HeaderGenerator) renderListUnsubFromPool(tpls []string, mode string, seqIdxPtr *int, vp *VariableProcessor, recipient *types.Recipient) string {
	if len(tpls) == 0 || vp == nil || recipient == nil {
		return ""
	}

	// 选模板（顺序 vs 随机）
	// 大小写规范化（防御用户手改 config.json 写成 "Sequential"）
	var tpl string
	n := len(tpls)
	if strings.EqualFold(strings.TrimSpace(mode), "sequential") {
		tpl = tpls[*seqIdxPtr%n]
		*seqIdxPtr++
	} else {
		tpl = tpls[safeIntn(hg.random, n)]
	}

	tpl = strings.TrimSpace(tpl)
	if tpl == "" {
		return ""
	}

	// 渲染变量
	rendered := vp.Process(tpl, recipient)

	// 折叠
	folded := foldHeaderValue(rendered, len("List-Unsubscribe: "))

	return "List-Unsubscribe: " + folded + "\r\n"
}

// getFeedbackID 生成 Feedback-ID
// 格式：{活动 ID}:{发件域}:{邮件类型}:{发件人短 ID}
// 同一 worker 在当前组合寿命内 senderID 保持稳定（增加 Gmail Postmaster Tools 聚合稳定性）
func (hg *HeaderGenerator) getFeedbackID(domain string) string {
	campaign := 100000 + safeIntn(hg.random, 900000)
	categories := []string{"newsletter", "promo", "tx", "campaign"}
	cat := categories[safeIntn(hg.random, len(categories))]
	senderID := randomHexString(8)
	return fmt.Sprintf("Feedback-ID: %d:%s:%s:%s\r\n", campaign, domain, cat, senderID)
}

// getPrecedence 生成 Precedence: bulk / list / auto_reply / junk
func (hg *HeaderGenerator) getPrecedence() string {
	choices := []string{"bulk", "list", "auto_reply", "junk"}
	return fmt.Sprintf("Precedence: %s\r\n", choices[safeIntn(hg.random, len(choices))])
}

// ----- P1 组 -----

func (hg *HeaderGenerator) getErrorsTo(domain string) string {
	token := randomHexString(12)
	return fmt.Sprintf("Errors-To: bounce-%s@%s\r\n", token, domain)
}

func (hg *HeaderGenerator) getSender(domain string) string {
	prefixes := []string{"noreply", "mailer", "no-reply", "info", "newsletter", "notify"}
	p := prefixes[safeIntn(hg.random, len(prefixes))]
	return fmt.Sprintf("Sender: %s@%s\r\n", p, domain)
}

func (hg *HeaderGenerator) getOrganization() string {
	orgs := []string{
		"Customer Service", "Marketing Department", "Notifications",
		"Mail Service", "Newsletter Team", "Support Team",
		"Communications", "Member Services", "Contact Center",
		"Online Service", "Account Service", "Promotions",
	}
	return fmt.Sprintf("Organization: %s\r\n", orgs[safeIntn(hg.random, len(orgs))])
}

func (hg *HeaderGenerator) getXOriginatingIP() string {
	return fmt.Sprintf("X-Originating-IP: [%s]\r\n", hg.generateRandomIPRealistic())
}

func (hg *HeaderGenerator) getComments() string {
	comments := []string{
		"Authenticated sender",
		"Mass mailer notification",
		"Subscriber notification",
		"Promotional email",
		"Automated delivery",
		"Transactional notification",
	}
	return fmt.Sprintf("Comments: %s\r\n", comments[safeIntn(hg.random, len(comments))])
}

func (hg *HeaderGenerator) getKeywords() string {
	sets := []string{
		"newsletter, promotion",
		"notification, account",
		"marketing, offer",
		"announcement, update",
		"transactional",
		"campaign, news",
	}
	return fmt.Sprintf("Keywords: %s\r\n", sets[safeIntn(hg.random, len(sets))])
}

func (hg *HeaderGenerator) getXReportAbuse(domain string) string {
	return fmt.Sprintf("X-Report-Abuse: Please report abuse to abuse@%s\r\n", domain)
}

// ----- P2 Outlook 风格 -----

func (hg *HeaderGenerator) getXMSMailPriority() string {
	choices := []string{"High", "Normal", "Low"}
	return fmt.Sprintf("X-MSMail-Priority: %s\r\n", choices[safeIntn(hg.random, len(choices))])
}

// getThreadIndex 生成 Outlook Thread-Index：22-30 字节 base64
// 真实 Outlook 用 28 字节左右；我们随机 22-30 增加多样性
func (hg *HeaderGenerator) getThreadIndex() string {
	n := 22 + safeIntn(hg.random, 9)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(safeIntn(hg.random, 256))
	}
	return fmt.Sprintf("Thread-Index: %s\r\n", base64.StdEncoding.EncodeToString(b))
}

func (hg *HeaderGenerator) getThreadTopic() string {
	topics := []string{
		"Information",
		"Notification",
		"Important Update",
		"Newsletter",
		"Service Update",
		"Account Activity",
		"Subscription",
	}
	return fmt.Sprintf("Thread-Topic: %s\r\n", topics[safeIntn(hg.random, len(topics))])
}

func (hg *HeaderGenerator) getXAutoResponseSuppress() string {
	choices := []string{"OOF", "AutoReply", "All", "DR", "NRN", "RN"}
	return fmt.Sprintf("X-Auto-Response-Suppress: %s\r\n", choices[safeIntn(hg.random, len(choices))])
}

// ----- P2 行为标识 -----

func (hg *HeaderGenerator) getReturnReceiptTo(domain string) string {
	prefixes := []string{"noreply", "receipt", "delivery"}
	p := prefixes[safeIntn(hg.random, len(prefixes))]
	return fmt.Sprintf("Return-Receipt-To: <%s@%s>\r\n", p, domain)
}

func (hg *HeaderGenerator) getDispositionNotificationTo(domain string) string {
	prefixes := []string{"noreply", "read-receipt", "notification"}
	p := prefixes[safeIntn(hg.random, len(prefixes))]
	return fmt.Sprintf("Disposition-Notification-To: <%s@%s>\r\n", p, domain)
}

// ----- P3 营销活动 -----

func (hg *HeaderGenerator) getXCampaignID() string {
	return fmt.Sprintf("X-Campaign-ID: cmp-%s\r\n", randomHexString(8))
}

func (hg *HeaderGenerator) getXMailerLID() string {
	return fmt.Sprintf("X-Mailer-LID: lid-%06d\r\n", safeIntn(hg.random, 1000000))
}

func (hg *HeaderGenerator) getCampaignID() string {
	return fmt.Sprintf("Campaign-ID: %06d\r\n", safeIntn(hg.random, 1000000))
}

// ----- P3 联动组：单开关 → 多头（一致性是关键，不要孤立生成）-----

// getXTMASGroup 模拟 Trend Micro IMSS 扫描产物（6 个头一致）
// 【v2 2026-05-14】从 3 头扩到 6 头，包含 GCONF / MatchedRID / SNAP-Result
// 真实邮件中这 6 个头同时出现，缺任何一个反向暴露伪造
func (hg *HeaderGenerator) getXTMASGroup() string {
	// 版本字符串故意保持一致（真实 Trend Micro 出站时也这样）
	productVer := "IMSS-9.1.0.1195-8.1.0.1062-29286.002"

	// GCONF：Global Config 标识，90% 是 "00"，10% 是 "01"（仿真实分布）
	gconf := "00"
	if safeIntn(hg.random, 10) == 0 {
		gconf = "01"
	}

	// X-TMASE-Result：固定头部 + 浮点分数（5.0-10.0 随机）
	score := 5.0 + hg.random.Float64()*5.0

	// MatchedRID：多行 base64（256 字节 → ~344 base64 字符，自动 72 字符/行折行）
	// generateRandomBase64Multiline 返回的字符串内含 "\r\n   " 折行（3 空格 = continuation）
	matchedRID := generateRandomBase64Multiline(256)

	// SNAP-Result：1.{6位}.{4位}-0-1-{N}:0,{M}:0,{K}:0-0 格式
	snap1 := 800000 + safeIntn(hg.random, 200000) // 6 位数字
	snap2 := safeIntn(hg.random, 10000)           // 4 位数字
	snapN := 1 + safeIntn(hg.random, 50)
	snapM := 1 + safeIntn(hg.random, 50)
	snapK := 1 + safeIntn(hg.random, 50)

	return fmt.Sprintf("X-TM-AS-GCONF: %s\r\n", gconf) +
		fmt.Sprintf("X-TM-AS-Product-Ver: %s\r\n", productVer) +
		fmt.Sprintf("X-TMASE-Version: %s\r\n", productVer) +
		fmt.Sprintf("X-TMASE-Result: 10--%.6f-10.000000\r\n", score) +
		fmt.Sprintf("X-TMASE-MatchedRID: %s\r\n", matchedRID) +
		fmt.Sprintf("X-TMASE-SNAP-Result: 1.%d.%04d-0-1-%d:0,%d:0,%d:0-0\r\n",
			snap1, snap2, snapN, snapM, snapK)
}

// getXSFMCGroup 模拟 Salesforce Marketing Cloud 出站（2 个头一致）
// 真实 SFMC 邮件这两个头总是同时出现，job ID 格式 {7 位}_{7 位}
func (hg *HeaderGenerator) getXSFMCGroup() string {
	stack := 1 + safeIntn(hg.random, 7) // 1-7
	job1 := 7000000 + safeIntn(hg.random, 1000000)
	job2 := 2000000 + safeIntn(hg.random, 1000000)
	return fmt.Sprintf("X-SFMC-Stack: %d\r\n", stack) +
		fmt.Sprintf("x-job: %d_%d\r\n", job1, job2)
}

// ========================================================================
// 【2026-05-21 从 PowerMTA 移植】4 组企业网关联动头（IP 段不敏感的企业级反垃圾产品）
// 设计与 getXTMASGroup / getXSFMCGroup 同套路：单开关 → 多头一致输出
// 这 4 组的真实场景是企业内部部署的反垃圾 / 邮件安全网关，
// 跟云 ESP 头（X-SG-* / X-Mailgun-* 等）不同：IP 段不绑定特定厂商 → 不会被反垃圾系统 IP 反查打脸
// ========================================================================

// getXBarracudaGroup 模拟 Barracuda Email Security Gateway 出站痕迹（6 个头一致）
// 真实场景：邮件经过企业部署的 Barracuda 网关过滤后投递
func (hg *HeaderGenerator) getXBarracudaGroup() string {
	connectDomain := hg.generateRandomDomain()
	connectIP := hg.generateRandomIPRealistic()
	sourceIP := hg.generateRandomIPRealistic()
	startTime := time.Now().Unix()
	port := 8000 + safeIntn(hg.random, 1000) // Barracuda 管理端口常见范围
	spamScore := hg.random.Float64() * 2.0   // 0.00-2.00（出站合规邮件应该低分）
	scanTimeFrac := safeIntn(hg.random, 100)

	return fmt.Sprintf("X-Barracuda-Connect: %s[%s]\r\n", connectDomain, connectIP) +
		fmt.Sprintf("X-Barracuda-Start-Time: %d\r\n", startTime) +
		fmt.Sprintf("X-Barracuda-URL: https://%s:%d/cgi-mod/markup.cgi\r\n", connectIP, port) +
		fmt.Sprintf("X-Barracuda-Apparent-Source-IP: %s\r\n", sourceIP) +
		fmt.Sprintf("X-Barracuda-Spam-Score: %.2f\r\n", spamScore) +
		fmt.Sprintf("X-Barracuda-Spam-Status: No, SCORE=%.2f using global-scores tests=BSF_SC0_MISMATCH_TO autolearn=disabled scantime=0.%02d\r\n",
			spamScore, scanTimeFrac)
}

// getXProofpointGroup 模拟 Proofpoint Protection Server 出站痕迹（4 个头一致）
// 真实场景：经过 Proofpoint 反垃圾 / 反病毒过滤的合规出站邮件
func (hg *HeaderGenerator) getXProofpointGroup() string {
	engineMain := 10000 + safeIntn(hg.random, 1000) // 10000-10999（类似真实 10434）
	engineSub1 := 100 + safeIntn(hg.random, 900)    // 100-999
	engineSub2 := 100 + safeIntn(hg.random, 900)    // 100-999
	score := safeIntn(hg.random, 101)               // 0-100
	suspect := safeIntn(hg.random, 21)              // 0-20
	guid := strings.ToUpper(randomHexString(32))
	origGuid := strings.ToUpper(randomHexString(32))

	return fmt.Sprintf("X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.%d:6.0.%d, 1.0.%d, db=signed\r\n",
		engineMain, engineSub1, engineSub2) +
		fmt.Sprintf("X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=%d suspectscore=%d spamscore=0 malwarescore=0 phishscore=0 lowpriorityscore=0 mlxscore=0 adultscore=0 mlxlogscore=0 classifier=spam adjust=0 reason=mlx scancount=1 engineversion=8.0.1-2202160000 definitions=main-2202170025\r\n",
			score, suspect) +
		fmt.Sprintf("X-Proofpoint-GUID: %s\r\n", guid) +
		fmt.Sprintf("X-Proofpoint-ORIG-GUID: %s\r\n", origGuid)
}

// getXMimecastGroup 模拟 Mimecast 邮件安全网关出站痕迹（4 个头一致）
// 真实场景：经过 Mimecast 云邮件安全过滤的企业出站邮件
func (hg *HeaderGenerator) getXMimecastGroup() string {
	score := hg.random.Float64() * 10.0 // 0.00-10.00
	spamSig := generateRandomBase64(24) // 24 字节 → 32 字符 base64
	bulkSig := randomHexString(32)

	return fmt.Sprintf("X-Mimecast-Spam-Score: %.2f\r\n", score) +
		fmt.Sprintf("X-Mimecast-Spam-Signature: %s\r\n", spamSig) +
		fmt.Sprintf("X-Mimecast-Bulk-Signature: %s\r\n", bulkSig) +
		"X-Mimecast-Impersonation-Protect: Policy=Outbound; Similar Internal Domain=false; Similar Monitored External Domain=false; Custom External Domain=false; Mimecast External Domain=false; Newly Observed Domain=false; Internal User Name=false; Reply-to Address Mismatch=false; Targeted Threat Dictionary=false; Mimecast Threat Dictionary=false; Custom Threat Dictionary=false\r\n"
}

// getXSymantecGroup 模拟 Symantec MessageLabs（CMAE）出站痕迹（4 个头一致）
// 真实场景：经过 Symantec.cloud 邮件安全过滤的企业出站邮件
func (hg *HeaderGenerator) getXSymantecGroup() string {
	cmaeScore := hg.random.Float64() * 3.0 // 0.00-3.00
	cv := generateRandomBase64(24)         // 24 字节 → 32 字符 base64
	c := 100 + safeIntn(hg.random, 100)    // 100-199
	a := randomHexString(32)               // 32 字符 hex
	rulesN := safeIntn(hg.random, 10)
	rulesM := safeIntn(hg.random, 10)

	return fmt.Sprintf("X-CMAE-Score: %.2f\r\n", cmaeScore) +
		fmt.Sprintf("X-CMAE-Analysis: v=2.4 cv=%s c=%d a=%s\r\n", cv, c, a) +
		"X-MessageSniffer-Scan-Result: 0\r\n" +
		fmt.Sprintf("X-MessageSniffer-Rules: 0-0-0-%d-%d\r\n", rulesN, rulesM)
}

// ========================================================================
// 【扩展邮件头 v2 2026-05-14】方案 B 5 个新独立头生成器
// 设计原则同前：用真实大厂的命名风格 / 真实业界格式
// ========================================================================

// getListID 生成 List-ID（RFC 2369）
// 与 List-Unsubscribe 配套：专业邮件列表平台必加，让 Gmail 收件箱按 List-ID 聚合
func (hg *HeaderGenerator) getListID(domain string) string {
	prefixes := []string{"newsletter", "promo", "notification", "list", "campaign", "updates"}
	p := prefixes[safeIntn(hg.random, len(prefixes))]
	return fmt.Sprintf("List-ID: <%s.%s>\r\n", p, domain)
}

// getXOriginatingEmail 生成 X-Originating-Email
// 与 X-Originating-IP 配对：真实 webmail（早期 Hotmail/Yahoo）出站邮件这俩一起加
func (hg *HeaderGenerator) getXOriginatingEmail(domain string) string {
	prefixes := []string{"noreply", "sender", "mailer", "notify", "info"}
	p := prefixes[safeIntn(hg.random, len(prefixes))]
	return fmt.Sprintf("X-Originating-Email: [%s@%s]\r\n", p, domain)
}

// getXMimeOLE 生成 X-MimeOLE
// 模拟老版 Outlook (2003-2010) 或 Exchange 出站邮件标识
// 反垃圾系统对老软件出站的邮件普遍宽容（很多企业老系统就这样）
func (hg *HeaderGenerator) getXMimeOLE() string {
	versions := []string{
		"Produced By Microsoft MimeOLE V6.00.2900.6157",
		"Produced By Microsoft MimeOLE V6.00.2900.6109",
		"Produced By Microsoft MimeOLE V6.00.2900.3138",
		"Produced By Microsoft MimeOLE V6.00.2900.2180",
		"Produced By Microsoft Exchange V14.0.694.0",
		"Produced By Microsoft Exchange V15.0.4569.1503",
	}
	return fmt.Sprintf("X-MimeOLE: %s\r\n", versions[safeIntn(hg.random, len(versions))])
}

// getXMailerVersion 生成 X-Mailer-Version
// 与 X-Mailer 配套：真实 Outlook 出站时两个头一起出现，孤立的 X-Mailer 略不真实
func (hg *HeaderGenerator) getXMailerVersion() string {
	versions := []string{
		"16.0.5505.1000",   // Office 2016/365
		"15.0.4569.1503",   // Office 2013
		"14.0.7268.5000",   // Office 2010
		"12.0.6612.1000",   // Office 2007
		"16.0.16327.20214", // Office 365 较新
		"16.0.14931.20648", // Office 365 中等
	}
	return fmt.Sprintf("X-Mailer-Version: %s\r\n", versions[safeIntn(hg.random, len(versions))])
}

// getXOriginalArrivalTime 生成 X-OriginalArrivalTime
// 格式：dd MMM yyyy HH:mm:ss.SSSS (UTC) FILETIME=[XXXXXXXX:XXXXXXXX]
// Exchange 出站邮件几乎必加，与 X-MimeOLE 配套完整模拟老 Exchange 出站
func (hg *HeaderGenerator) getXOriginalArrivalTime() string {
	now := time.Now().UTC()
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	monthStr := months[int(now.Month())-1]
	// FILETIME 是 Windows 时间戳的两段 32-bit hex
	high := hg.random.Uint32()
	low := hg.random.Uint32()
	return fmt.Sprintf("X-OriginalArrivalTime: %02d %s %d %02d:%02d:%02d.0000 (UTC) FILETIME=[%08X:%08X]\r\n",
		now.Day(), monthStr, now.Year(), now.Hour(), now.Minute(), now.Second(),
		high, low)
}

// ===== Message-ID 生成（模拟不同客户端风格）=====

// GenerateCustomMessageID 生成模拟不同客户端风格的 Message-ID
// 【修复问题2】改为实例方法，使用独立随机源
func (hg *HeaderGenerator) GenerateCustomMessageID(domain string) string {
	// 提取域名（决策点 2：@ 右边一律用该服务器 From 发信域，不伪造主机名）
	if idx := strings.Index(domain, "@"); idx != -1 {
		domain = domain[idx+1:]
	}

	// 决定候选风格集合：
	//   - RandomAll=true（"随机Message-ID"，默认）→ 全部风格
	//   - RandomAll=false 且勾了具体风格 → 仅勾选的（按 messageIDStyleKeys 固定顺序过滤，去掉非法 key）
	//   - 取消随机却一个有效的都没勾（空选）→ 兜底回退全部风格（决策点 4）
	candidates := hg.messageIDStyleCandidates()

	key := candidates[safeIntn(hg.random, len(candidates))]
	return hg.buildMessageIDByStyle(key, domain)
}

// messageIDStyleKeys 是去重后所有 Message-ID 风格的稳定 key（25 种）。
// 【契约】此列表必须与 C# 端 MessageIdStyleForm 复选框 key 字节级一致；
// 顺序固定（仅影响"全随机"抽样候选顺序，不影响正确性），新增风格往末尾加。
// 去重说明：原 9 风格里 Gmail 已删；原 Outlook/Apple(大写 UUID) 并入 uuid_v4_upper；
//           原 Thunderbird(32hex) 并入 hex32；原时间戳风→ns_hex；原短随机→hex16；Exim/Sendmail/Becky 保留。
var messageIDStyleKeys = []string{
	"uuid_v4_lower",       // 1. 小写 UUID v4
	"hex32",               // 2. 32 位十六进制（含原 Thunderbird）
	"javamail",            // 3. JavaMail 点分多段
	"uuid_v4_upper",       // 4. 大写 UUID v4（含原 Outlook / Apple）
	"ts_uuid_counter",     // 5. 时间戳 + UUID + 计数复合（Amazon SES 类）
	"base64url",           // 6. Base64url 短随机串
	"readable_ts",         // 7. 可读时间戳前缀 + 短随机
	"uuid_seq",            // 8. UUID + 序号后缀
	"hex40",               // 9. 40 位十六进制（sha1 风）
	"hex_underscore",      // 10. hex_hex 下划线
	"ms_ts_hex",           // 11. 毫秒时间戳 + 短 hex
	"uuid_v1",             // 12. UUID v1（时间 + 节点）
	"biz_prefix",          // 13. 业务前缀 + 唯一串
	"hex64",               // 14. 64 位十六进制（sha256 风）
	"enterprise_multiseg", // 15. 多段企业平台格式
	"epoch_counter",       // 16. Epoch 秒 + 计数（老式 MTA 风）
	"bigint_hex",          // 17. 大随机整数 + 短 hex
	"mixed_alnum",         // 18. 混合大小写字母数字
	"compact_date_ns",     // 19. 紧凑日期 + 纳秒/计数
	"tag_uuid",            // 20. 前缀标签 + UUID
	"ns_hex",              // 21. 纳秒时间戳 + 12 hex（原默认/时间戳风）
	"hex16",               // 22. 16 位十六进制（原短随机风）
	"exim",                // 23. Exim 风格
	"sendmail",            // 24. Sendmail 风格
	"becky",               // 25. Becky! 风格（日本本土客户端）
}

// Message-ID 风格用到的词池（业务前缀 / 平台标签 / 类型标签）
var messageIDBizPrefixes = []string{"mkt", "promo", "news", "notify", "sys", "mail", "camp", "info", "noreply", "alert"}
var messageIDPlatformLabels = []string{"promo", "news", "txn", "sys", "camp", "mkt", "bulk", "auto"}
var messageIDTags = []string{"notify", "alert", "txn", "sys", "msg", "info", "mail", "auto", "noreply"}

// buildMessageIDByStyle 按风格 key 生成 Message-ID 左半部分 + "@domain"（不含尖括号，由 builder 包裹）。
// 计数类风格用 worker 独立递增计数器 hg.messageIDSeqIdx（per-worker 单线程，无需加锁）。
// 任何分支都不返回空串：未知 key 走 default 兜底，保证总有合法 Message-ID。
func (hg *HeaderGenerator) buildMessageIDByStyle(key, d string) string {
	switch key {
	case "uuid_v4_lower":
		return fmt.Sprintf("%s@%s", messageIDUUIDv4(false), d)
	case "hex32":
		return fmt.Sprintf("%s@%s", randomHexString(32), d)
	case "javamail":
		hg.messageIDSeqIdx++
		num := hg.random.Int63n(9000000000) + 1000000000 // 10 位随机数
		return fmt.Sprintf("%d.%d.%d@%s", num, hg.messageIDSeqIdx, time.Now().UnixMilli(), d)
	case "uuid_v4_upper":
		return fmt.Sprintf("%s@%s", messageIDUUIDv4(true), d)
	case "ts_uuid_counter":
		hg.messageIDSeqIdx++
		return fmt.Sprintf("%s-%s-%06d@%s",
			time.Now().Format("20060102t150405"), messageIDUUIDv4(false), hg.messageIDSeqIdx, d)
	case "base64url":
		b := make([]byte, 16)
		rand.Read(b)
		return fmt.Sprintf("%s@%s", base64.RawURLEncoding.EncodeToString(b), d) // 16 字节 -> 22 字符
	case "readable_ts":
		now := time.Now()
		ts17 := now.Format("20060102150405") + fmt.Sprintf("%03d", now.Nanosecond()/1e6)
		return fmt.Sprintf("%s.%s@%s", ts17, randomHexString(4), d)
	case "uuid_seq":
		hg.messageIDSeqIdx++
		return fmt.Sprintf("%s.%d@%s", messageIDUUIDv4(false), hg.messageIDSeqIdx, d)
	case "hex40":
		return fmt.Sprintf("%s@%s", randomHexString(40), d)
	case "hex_underscore":
		return fmt.Sprintf("%s_%s@%s", randomHexString(13), randomHexString(13), d)
	case "ms_ts_hex":
		return fmt.Sprintf("%d.%s@%s", time.Now().UnixMilli(), randomHexString(12), d)
	case "uuid_v1":
		return fmt.Sprintf("%s@%s", messageIDUUIDv1(), d)
	case "biz_prefix":
		return fmt.Sprintf("%s_%s@%s", hg.randomChoice(messageIDBizPrefixes), randomHexString(32), d)
	case "hex64":
		return fmt.Sprintf("%s@%s", randomHexString(64), d)
	case "enterprise_multiseg":
		hg.messageIDSeqIdx++
		return fmt.Sprintf("%d.%s.%s.%d.%06d.%06d@%s",
			time.Now().UnixMilli(), time.Now().Format("20060102"),
			hg.randomChoice(messageIDPlatformLabels), hg.messageIDSeqIdx,
			safeIntn(hg.random, 1000000), safeIntn(hg.random, 1000000), d)
	case "epoch_counter":
		return fmt.Sprintf("%d.%08d@%s", time.Now().Unix(), safeIntn(hg.random, 100000000), d)
	case "bigint_hex":
		return fmt.Sprintf("%d.%s@%s", hg.random.Int63(), randomHexString(8), d)
	case "mixed_alnum":
		return fmt.Sprintf("%s@%s", messageIDRandAlnum(32+safeIntn(hg.random, 9)), d) // 32-40 位
	case "compact_date_ns":
		return fmt.Sprintf("%s%012d%s@%s",
			time.Now().Format("20060102"), time.Now().UnixNano()%1000000000000, randomHexString(6), d)
	case "tag_uuid":
		return fmt.Sprintf("%s-%s@%s", hg.randomChoice(messageIDTags), messageIDUUIDv4(false), d)
	case "ns_hex":
		return fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), randomHexString(12), d)
	case "hex16":
		return fmt.Sprintf("%s@%s", randomHexString(16), d)
	case "exim":
		part1 := strings.ToUpper(randomHexString(7))
		part2 := strings.ToUpper(randomHexString(6))
		const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		last := make([]byte, 2)
		for i := range last {
			last[i] = letters[safeIntn(hg.random, len(letters))]
		}
		return fmt.Sprintf("E1%s-%s-%s@%s", part1, part2, string(last), d)
	case "sendmail":
		return fmt.Sprintf("%s.%s@%s", time.Now().Format("20060102150405"), randomHexString(6), d)
	case "becky":
		b := make([]byte, 4)
		rand.Read(b)
		return fmt.Sprintf("%02X.%02X.%02X.%02X@%s", b[0], b[1], b[2], b[3], d)
	case "yahoo_mimepart":
		n := 1000 + safeIntn(hg.random, 9000)
		return fmt.Sprintf("%s_%s@worker%d.%s.%s.%s.yahoo.co.jp.mail",
			randomHexString(13), randomHexString(15), n,
			hg.randomChoice(yahooWorkerLabels),
			hg.randomChoice(yahooWorkerLabels),
			hg.randomChoice(yahooWorkerLabels))
	case "phpmailer_ts_digits":
		now := time.Now()
		if loc, err := time.LoadLocation("Asia/Tokyo"); err == nil {
			now = now.In(loc)
		}
		digits := make([]byte, 20)
		for i := range digits {
			digits[i] = byte('0' + safeIntn(hg.random, 10))
		}
		return now.Format("20060102150405") + string(digits) + "@" + d
	default:
		// 未知 key 兜底：回退纳秒风（永不返回空）
		return fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), randomHexString(12), d)
	}
}

// messageIDUUIDv4 生成 RFC 4122 v4 UUID（upper=true 输出大写，否则小写）
func messageIDUUIDv4(upper bool) string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
	if upper {
		return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// messageIDUUIDv1 生成时间型 UUID v1（小写）。节点用随机字节 + 组播位（非真实网卡 MAC），
// 时钟序列随机，版本位=1、变体位=10。
func messageIDUUIDv1() string {
	const gregorianOffset = 122192928000000000 // 1582-10-15 ~ 1970-01-01 的 100ns 间隔数
	ts := uint64(time.Now().UnixNano()/100) + gregorianOffset
	timeLow := uint32(ts & 0xffffffff)
	timeMid := uint16((ts >> 32) & 0xffff)
	timeHiVer := uint16((ts>>48)&0x0fff) | 0x1000 // version 1
	var rb [8]byte
	rand.Read(rb[:])
	clockSeq := (uint16(rb[0])<<8|uint16(rb[1]))&0x3fff | 0x8000 // variant 10xx
	var node [6]byte
	copy(node[:], rb[2:8])
	node[0] |= 0x01 // 组播位=1，表明非真实网卡 MAC
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", timeLow, timeMid, timeHiVer, clockSeq, node[:])
}

// messageIDRandAlnum 生成长度 n 的混合大小写字母数字随机串（无分隔符）
func messageIDRandAlnum(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

// ===== X-Priority =====

func (hg *HeaderGenerator) getXPriorityValue() string {
	val := hg.cfg.XPriorityValue
	switch val {
	case "1 (Highest)":
		return "1"
	case "2 (High)":
		return "2"
	case "3 (Normal)":
		return "3"
	default: // 随机选择
		choices := []string{"1", "2", "3"}
		return hg.randomChoice(choices)
	}
}

// ===== Importance =====

func (hg *HeaderGenerator) getImportanceValue() string {
	val := hg.cfg.ImportanceValue
	switch val {
	case "high", "normal", "low":
		return val
	default: // 随机选择
		choices := []string{"high", "normal", "low"}
		return hg.randomChoice(choices)
	}
}

// ===== Reply-To =====

func (hg *HeaderGenerator) getReplyToAddress(fromAddress, domain string) string {
	switch hg.cfg.ReplyToMode {
	case "random_prefix":
		return hg.generateRandomEmailPrefix() + "@" + domain
	default: // from_address
		return fromAddress
	}
}

// ===== Return-Path =====

func (hg *HeaderGenerator) getReturnPathAddress(fromAddress, domain string) string {
	switch hg.cfg.ReturnPathMode {
	case "random_prefix":
		return hg.generateRandomEmailPrefix() + "@" + domain
	default: // from_address
		return fromAddress
	}
}

// ===== Accept-Language =====

func (hg *HeaderGenerator) getAcceptLanguageValue() string {
	val := hg.cfg.AcceptLangValue
	switch val {
	case "ja", "en", "ja-JP", "en-US", "zh-CN":
		return val
	default: // 随机选择
		choices := []string{"ja", "en", "ja-JP", "en-US", "zh-CN"}
		return hg.randomChoice(choices)
	}
}

// ===== Content-Language =====

func (hg *HeaderGenerator) getContentLanguageValue() string {
	val := hg.cfg.ContentLangValue
	switch val {
	case "ja", "en", "ja-JP", "en-US", "zh-CN":
		return val
	default: // 随机选择
		choices := []string{"ja", "en", "ja-JP", "en-US", "zh-CN"}
		return hg.randomChoice(choices)
	}
}

// ===== 辅助函数 =====

// randomChoice 从切片中随机选择一个元素
// 【修复问题2】使用实例级别随机源替代全局rand
// 【v62修复】使用 safeIntn 确保索引永远不越界
func (hg *HeaderGenerator) randomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}
	return choices[safeIntn(hg.random, len(choices))]
}

// generateRandomDomain 生成随机域名
func (hg *HeaderGenerator) generateRandomDomain() string {
	formats := []func() string{
		// 格式1: mail.random.tld
		func() string {
			suffix := randomHexString(7)
			tld := hg.randomChoice(domainTLDs)
			return fmt.Sprintf("mail.%s.%s", suffix, tld)
		},
		// 格式2: smtp.word-suffix.tld
		func() string {
			word := hg.randomChoice(domainWords)
			suffix := hg.randomChoice(domainSuffixes)
			tld := hg.randomChoice(domainTLDs)
			return fmt.Sprintf("smtp.%s-%s.%s", word, suffix, tld)
		},
	}
	return formats[safeIntn(hg.random, len(formats))]()
}

// generateRandomIPRealistic 生成真实范围的随机IP
func (hg *HeaderGenerator) generateRandomIPRealistic() string {
	validRanges := [][2]int{
		{1, 9}, {11, 126}, {128, 169}, {171, 171},
		{173, 191}, {193, 223},
	}
	r := validRanges[safeIntn(hg.random, len(validRanges))]
	first := safeIntn(hg.random, r[1]-r[0]+1) + r[0]
	second := safeIntn(hg.random, 255)
	third := safeIntn(hg.random, 255)
	fourth := safeIntn(hg.random, 254) + 1
	return fmt.Sprintf("%d.%d.%d.%d", first, second, third, fourth)
}

// generateMailID 生成随机邮件传输ID
func (hg *HeaderGenerator) generateMailID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 8)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	dash1 := randomHexString(4)
	dash2 := randomHexString(4)
	dash3 := randomHexString(4)
	return fmt.Sprintf("%s-%s-%s-%s.%d", strings.ToUpper(string(result)), strings.ToUpper(dash1), strings.ToUpper(dash2), strings.ToUpper(dash3), safeIntn(hg.random, 9)+1)
}

// generateRandomUsername 生成随机用户名
func (hg *HeaderGenerator) generateRandomUsername() string {
	usernames := []string{
		"username", "user", "mail", "admin", "sender", "client",
		"account", "mailer", "webmaster", "system", "daemon",
		"notification", "postmaster", "mailsystem", "automated", "monitor",
	}
	name := hg.randomChoice(usernames)
	number := safeIntn(hg.random, 1000)
	return fmt.Sprintf("%s%03d", name, number)
}

// generateRandomEmailPrefix 生成随机邮箱前缀
func (hg *HeaderGenerator) generateRandomEmailPrefix() string {
	prefixes := []string{
		"noreply", "no-reply", "info", "support", "admin", "contact",
		"service", "notification", "alert", "mail", "system", "notice",
		"account", "security", "verify", "update", "billing", "help",
	}
	prefix := hg.randomChoice(prefixes)
	if safeIntn(hg.random, 3) == 0 {
		// 30%概率添加数字后缀
		prefix = fmt.Sprintf("%s%d", prefix, safeIntn(hg.random, 100))
	}
	return prefix
}

// generateGUID 生成GUID格式字符串
func generateGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateRandomBase64 生成指定字节数的随机Base64字符串
func generateRandomBase64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// generateRandomBase64Multiline 生成多行随机Base64（模拟DKIM签名）
func generateRandomBase64Multiline(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	encoded := base64.StdEncoding.EncodeToString(b)
	var lines []string
	lineLen := 72
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		lines = append(lines, encoded[i:end])
	}
	return strings.Join(lines, "\r\n   ")
}

// randomHexString 生成随机十六进制字符串
func randomHexString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// randomLetterPrefix 生成 1..maxLen 位随机字母前缀（不含数字）
func randomLetterPrefix(maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxLen)))
	if err != nil {
		nBig = big.NewInt(0)
	}
	length := int(nBig.Int64()) + 1
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// ===== TLS加密套件列表 =====

var tlsCiphers = []string{
	"cipher=TLS_RSA_WITH_AES_128_GCM_SHA256 (authenticated bits=0);",
	"cipher=TLS_RSA_WITH_AES_256_GCM_SHA384 (authenticated bits=0);",
	"cipher=TLS_RSA_WITH_AES_128_CBC_SHA (authenticated bits=0);",
	"cipher=TLS_RSA_WITH_AES_256_CBC_SHA (authenticated bits=0);",
	"cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (authenticated bits=0);",
	"cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (authenticated bits=0);",
	"cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (authenticated bits=0);",
	"cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (authenticated bits=0);",
	"cipher=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (authenticated bits=0);",
	"cipher=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (authenticated bits=0);",
	"cipher=TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (authenticated bits=0);",
	"cipher=TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (authenticated bits=0);",
	"cipher=TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (authenticated bits=0);",
	"cipher=TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (authenticated bits=0);",
	"cipher=TLS_AES_128_GCM_SHA256 (authenticated bits=0);",
	"cipher=TLS_AES_256_GCM_SHA384 (authenticated bits=0);",
	"cipher=TLS_CHACHA20_POLY1305_SHA256 (authenticated bits=0);",
}

// ===== 域名生成用数据 =====

var domainTLDs = []string{
	"com", "net", "org", "jp", "ne.jp", "co.jp", "or.jp", "ac.jp", "ad.jp", "ed.jp",
	"go.jp", "gr.jp", "lg.jp", "edu", "gov", "app", "blog", "shop", "online", "site",
	"store", "tech", "cloud", "email", "news", "media", "agency", "company", "business",
	"services", "aichi.jp", "akita.jp", "aomori.jp", "chiba.jp", "ehime.jp", "fukui.jp",
	"fukuoka.jp", "fukushima.jp", "gifu.jp", "gunma.jp", "hiroshima.jp", "hokkaido.jp",
	"hyogo.jp", "ibaraki.jp", "ishikawa.jp", "iwate.jp", "kagawa.jp", "kagoshima.jp",
	"kanagawa.jp", "kochi.jp", "kumamoto.jp", "kyoto.jp", "mie.jp", "miyagi.jp",
	"miyazaki.jp", "nagano.jp", "nagasaki.jp", "nara.jp", "niigata.jp", "oita.jp",
	"okayama.jp", "okinawa.jp", "osaka.jp", "saga.jp", "saitama.jp", "shiga.jp",
	"shimane.jp", "shizuoka.jp", "tochigi.jp", "tokushima.jp", "tokyo.jp", "tottori.jp",
	"toyama.jp", "wakayama.jp", "yamagata.jp", "yamaguchi.jp", "yamanashi.jp",
	"yokohama.jp", "kawasaki.jp", "sapporo.jp", "sendai.jp",
	"pref.aichi.jp", "pref.osaka.jp", "pref.kanagawa.jp", "pref.saitama.jp",
	"pref.chiba.jp", "pref.fukuoka.jp", "pref.hiroshima.jp", "pref.hokkaido.jp",
	"pref.hyogo.jp", "pref.kyoto.jp",
	"waseda.jp", "keio.jp", "u-tokyo.jp", "kyoto-u.jp", "osaka-u.jp",
	"ntt.jp", "softbank.jp", "kddi.jp", "docomo.jp", "rakuten.jp",
	"smbc.jp", "mufg.jp", "mizuho.jp", "japanpost.jp",
	"nerima.tokyo.jp", "shibuya.tokyo.jp", "shinjuku.tokyo.jp", "minato.tokyo.jp",
}

var domainWords = []string{
	"care", "mail", "tech", "data", "info", "auto", "plan", "node", "core", "form",
	"sync", "push", "base", "bank", "auth", "main", "flow", "tool", "link", "user",
	"help", "pool", "email", "promo", "event", "stats", "batch", "queue", "guide",
	"route", "agent", "chain", "reply", "vault", "store", "group", "order", "entry",
	"setup", "blast", "stage", "score", "cache", "proxy", "admin", "token", "audit",
	"reset", "office", "notify", "alerts", "system", "notice", "report", "mailer",
	"sender", "signal", "client", "search", "config", "update", "member", "action",
	"verify", "stream", "crypto", "daemon", "policy", "server", "branch", "filter",
	"access", "record", "source", "broker", "worker", "engine", "portal", "assist",
	"ticket", "status", "health", "secure", "manage", "safety", "shield", "custom",
	"signup", "backup", "repair", "noreply", "manager", "premium", "monitor", "network",
	"traffic", "checker", "mailbot", "cleaner", "reports", "content", "archive",
	"account", "billing", "payment", "profile", "confirm", "welcome", "service",
	"gateway", "support",
}

var domainSuffixes = []string{
	"corp", "solutions", "systems", "services", "group", "tech", "resolve", "contact",
	"process", "inquiry", "checking", "verifier", "computer", "security", "reminder",
	"messages", "recovery", "dispatch", "delivery", "tracking", "solution", "benefits",
	"endpoint", "notifier", "campaign", "priority", "packages", "progress", "customer",
	"platform", "feedback", "settings", "database", "research", "helpdesk", "response",
	"resource", "pipeline", "workflow", "engineer", "accounts", "firewall", "protocol",
	"incident", "sentinel", "guardian", "operator", "broadcast", "scheduler", "publisher",
	"processor", "connector", "framework", "component", "dashboard", "analytics",
	"collector", "community", "validator", "operation", "management", "onboarding",
	"encryption", "technology", "specialist", "membership", "automation", "middleware",
	"newsletter", "compliance", "statistics", "activation", "checkpoint", "dispatcher",
	"monitoring", "foundation", "protection", "diagnostic", "maintenance", "integration",
	"coordinator", "application", "performance", "information", "confirmation",
	"administrator", "communication", "notifications", "infrastructure", "authentication",
}

// ===== 邮件服务器软件/API标识列表 =====

var mailServerSoftware = []string{
	// ===== 主流邮件服务商API =====
	"Google API",
	"Google SMTP",
	"Google Mail Service",
	"Gmail SMTP",
	"Google Workspace SMTP",
	"Google Apps SMTP",
	"Google Cloud SMTP",
	"Google Relay",
	"Google Mail Relay",
	"Microsoft SMTP",
	"Microsoft SMTP Server",
	"Microsoft Exchange Online",
	"Microsoft 365 SMTP",
	"Office 365 SMTP",
	"Outlook SMTP",
	"Outlook.com SMTP",
	"Exchange SMTP Gateway",
	"Microsoft Exchange Server",
	"Microsoft Exchange Transport",
	"Amazon SES",
	"Amazon SES API",
	"Amazon Simple Email Service",
	"AWS SES SMTP",
	"AWS Mail Service",
	"Amazon SES Relay",
	"SendGrid",
	"SendGrid API",
	"SendGrid SMTP",
	"SendGrid Mail Service",
	"Twilio SendGrid",
	"Mailgun",
	"Mailgun API",
	"Mailgun SMTP",
	"Mailgun Relay",
	"Mailgun Mail Service",
	"Mailchimp",
	"Mailchimp API",
	"Mailchimp Transactional",
	"Mandrill",
	"Mandrill API",
	"Mandrill SMTP",
	"Postmark",
	"Postmark API",
	"Postmark SMTP",
	"Postmark Mail Service",
	"SparkPost",
	"SparkPost API",
	"SparkPost SMTP",
	"SparkPost Relay",
	"Brevo SMTP",
	"Brevo API",
	"Brevo Mail Service",
	"Sendinblue",
	"Sendinblue API",
	"Sendinblue SMTP",
	"Elastic Email",
	"Elastic Email API",
	"Elastic Email SMTP",
	"MailerSend",
	"MailerSend API",
	"MailerSend SMTP",
	"Mailjet",
	"Mailjet API",
	"Mailjet SMTP",
	"Mailjet Relay",
	"Constant Contact",
	"Constant Contact SMTP",
	"Campaign Monitor",
	"Campaign Monitor SMTP",
	"GetResponse",
	"GetResponse SMTP",
	"AWeber",
	"AWeber SMTP",
	"ConvertKit",
	"ConvertKit SMTP",
	"ActiveCampaign",
	"ActiveCampaign SMTP",
	"Drip",
	"Drip SMTP",
	"Klaviyo",
	"Klaviyo SMTP",
	"HubSpot SMTP",
	"HubSpot Mail Service",
	"Salesforce SMTP",
	"Salesforce Marketing Cloud",
	"Oracle Email Delivery",
	"Oracle Cloud SMTP",
	"IBM Cloud Email",
	"SocketLabs",
	"SocketLabs SMTP",
	"SocketLabs API",
	"SMTP2GO",
	"SMTP2GO SMTP",
	"SMTP2GO API",
	"Pepipost",
	"Pepipost SMTP",
	"Pepipost API",
	"Moosend",
	"Moosend SMTP",
	"Omnisend",
	"Omnisend SMTP",
	"Customer.io",
	"Customer.io SMTP",
	"Intercom Mail",
	"Intercom SMTP",
	"Zendesk SMTP",
	"Zendesk Mail Service",
	"Freshdesk SMTP",
	"Freshdesk Mail",

	// ===== MTA邮件服务器软件 =====
	"Postfix",
	"Postfix MTA",
	"Postfix SMTP",
	"Postfix/smtpd",
	"Sendmail",
	"Sendmail MTA",
	"Sendmail/8.15.2",
	"Sendmail/8.16.1",
	"Sendmail/8.17.1",
	"Exim",
	"Exim SMTP",
	"Exim 4.94",
	"Exim 4.96",
	"Exim 4.97",
	"Exim MTA",
	"Dovecot",
	"Dovecot LMTP",
	"Dovecot SMTP",
	"Dovecot/2.3",
	"Zimbra",
	"Zimbra SMTP",
	"Zimbra 8.8",
	"Zimbra 9.0",
	"Zimbra Collaboration",
	"Zimbra MTA",
	"hMailServer",
	"hMailServer 5.6",
	"hMailServer SMTP",
	"Haraka",
	"Haraka SMTP",
	"Haraka MTA",
	"Haraka/2.8",
	"OpenSMTPD",
	"OpenSMTPD 6.8",
	"OpenSMTPD 7.0",
	"qmail",
	"qmail SMTP",
	"qmail-smtpd",
	"Courier",
	"Courier Mail Server",
	"Courier MTA",
	"Courier SMTP",
	"MailEnable",
	"MailEnable SMTP",
	"MailEnable Professional",
	"MailEnable Enterprise",
	"Kerio Connect",
	"Kerio Connect SMTP",
	"Kerio Connect 9.4",
	"IceWarp",
	"IceWarp SMTP",
	"IceWarp Server",
	"IceWarp 13",
	"Axigen",
	"Axigen SMTP",
	"Axigen Mail Server",
	"CommuniGate Pro",
	"CommuniGate Pro SMTP",
	"CommuniGate Pro 6.3",
	"MDaemon",
	"MDaemon SMTP",
	"MDaemon Mail Server",
	"MDaemon 21.5",
	"MDaemon 23.0",
	"Lotus Domino",
	"Lotus Domino SMTP",
	"HCL Domino",
	"HCL Domino SMTP",
	"Novell GroupWise",
	"GroupWise SMTP",
	"GroupWise Internet Agent",
	"PowerMTA",
	"PowerMTA SMTP",
	"PowerMTA/5.0",
	"Apache James",
	"Apache James SMTP",
	"Apache James 3.7",
	"Open-Xchange",
	"Open-Xchange SMTP",
	"Maildrop",
	"Maildrop SMTP",
	"Prosody SMTP",
	"Cyrus SMTP",
	"Cyrus/IMAPd",
	"MailCow",
	"MailCow SMTP",
	"Mailcow Dockerized",
	"Mail-in-a-Box",
	"iRedMail",
	"iRedMail SMTP",
	"Modoboa",
	"Modoboa SMTP",
	"Kolab",
	"Kolab SMTP",
	"Citadel",
	"Citadel SMTP",
	"Hmailserver",

	// ===== 企业/云平台邮件 =====
	"Zoho Mail",
	"Zoho Mail SMTP",
	"Zoho SMTP",
	"Zoho ZeptoMail",
	"Yahoo SMTP",
	"Yahoo Mail SMTP",
	"Yahoo Mail Service",
	"Rackspace Email",
	"Rackspace SMTP",
	"Rackspace Cloud Email",
	"GoDaddy SMTP",
	"GoDaddy Email",
	"GoDaddy Workspace",
	"Fastmail",
	"Fastmail SMTP",
	"Fastmail MTA",
	"ProtonMail",
	"ProtonMail SMTP",
	"ProtonMail Bridge",
	"Proton Mail SMTP",
	"Tutanota",
	"Tutanota SMTP",
	"GMX SMTP",
	"GMX Mail",
	"Mail.Ru SMTP",
	"Mail.Ru",
	"Yandex SMTP",
	"Yandex Mail",
	"Yandex Cloud SMTP",
	"Apple Mail",
	"Apple iCloud Mail",
	"iCloud SMTP",
	"Tencent Mail",
	"Tencent SMTP",
	"QQ Mail SMTP",
	"NetEase Mail",
	"NetEase SMTP",
	"163 Mail SMTP",
	"Alibaba Mail",
	"Alibaba Cloud Mail",
	"Alibaba DirectMail",
	"Naver SMTP",
	"Naver Mail",
	"Daum SMTP",
	"Daum Mail",
	"OVH SMTP",
	"OVH Mail",
	"OVH Cloud Email",
	"Hetzner SMTP",
	"Hetzner Mail",
	"DigitalOcean SMTP",
	"Linode SMTP",
	"Vultr SMTP",
	"Scaleway SMTP",
	"Gandi SMTP",
	"Gandi Mail",
	"Namecheap SMTP",
	"Namecheap Email",
	"Bluehost SMTP",
	"HostGator SMTP",
	"SiteGround SMTP",
	"DreamHost SMTP",
	"Ionos SMTP",
	"1and1 SMTP",
	"Aruba SMTP",
	"Register.it SMTP",

	// ===== 日本邮件服务 =====
	"Sakura Internet",
	"Sakura SMTP",
	"Sakura Mail",
	"GMO SMTP",
	"GMO Mail",
	"GMO Cloud SMTP",
	"KAGOYA SMTP",
	"KAGOYA Mail",
	"KAGOYA Internet",
	"Xserver SMTP",
	"Xserver Mail",
	"Xserver MTA",
	"ConoHa SMTP",
	"ConoHa Mail",
	"ConoHa MTA",
	"IIJ SMTP",
	"IIJ Mail",
	"IIJ Secure MX",
	"BIGLOBE SMTP",
	"BIGLOBE Mail",
	"OCN SMTP",
	"OCN Mail",
	"Nifty SMTP",
	"Nifty Mail",
	"So-net SMTP",
	"So-net Mail",
	"KDDI Mail",
	"KDDI SMTP",
	"au Mail SMTP",
	"NTT Mail SMTP",
	"NTT Communications SMTP",
	"Plala SMTP",
	"Plala Mail",
	"DTI SMTP",
	"DTI Mail",
	"Interlink SMTP",
	"WebARENA SMTP",
	"WADAX SMTP",
	"CPI SMTP",
	"Lolipop SMTP",
	"Lolipop Mail",
	"MuuMuu SMTP",
	"Onamae SMTP",
	"Onamae Mail",
	"ValueServer SMTP",
	"Core Server SMTP",
	"Heteml SMTP",

	// ===== 安全网关/邮件过滤器 =====
	"Barracuda",
	"Barracuda SMTP",
	"Barracuda Email Gateway",
	"Barracuda Spam Firewall",
	"Proofpoint",
	"Proofpoint SMTP",
	"Proofpoint Protection",
	"Proofpoint Essentials",
	"Proofpoint Gateway",
	"Sophos Email",
	"Sophos SMTP",
	"Sophos Email Appliance",
	"Symantec Messaging Gateway",
	"Symantec SMTP",
	"Broadcom Email Security",
	"FortiMail",
	"FortiMail SMTP",
	"Fortinet FortiMail",
	"Cisco IronPort",
	"Cisco ESA",
	"Cisco Email Security",
	"Cisco SMTP",
	"Trend Micro",
	"Trend Micro SMTP",
	"Trend Micro Email Security",
	"Trend Micro IMSVA",
	"SpamAssassin",
	"Amavis",
	"Amavisd-new",
	"Amavis SMTP",
	"Mimecast",
	"Mimecast SMTP",
	"Mimecast Gateway",
	"Mimecast Email Security",
	"Cloudmark",
	"Cloudmark SMTP",
	"McAfee Email Gateway",
	"McAfee SMTP",
	"Trellix Email Security",
	"FireEye SMTP",
	"FireEye Email Security",
	"Palo Alto SMTP",
	"Juniper SMTP",
	"F-Secure SMTP",
	"ESET Mail Security",
	"ESET SMTP",
	"Kaspersky SMTP",
	"Kaspersky Security for Mail",
	"Bitdefender SMTP",
	"Avira SMTP",
	"ClamAV SMTP",
	"Rspamd",
	"Rspamd SMTP",
	"MailScanner",
	"MailScanner SMTP",
	"SpamTitan",
	"SpamTitan SMTP",
	"MailGuard SMTP",
	"N-able Mail Assure",
	"SolarWinds Mail Assure",
	"Hornetsecurity",
	"Hornetsecurity SMTP",
	"Retarus SMTP",
	"Retarus Email Security",
	"Zix SMTP",
	"Zix Email Encryption",
	"Virtru SMTP",
	"Egress SMTP",
	"Libraesva SMTP",
	"Libraesva ESG",
	"GFI MailEssentials",
	"GFI SMTP",
	"Spam Experts",
	"SpamExperts SMTP",

	// ===== 开发框架/库 =====
	"PHPMailer",
	"PHPMailer SMTP",
	"SwiftMailer",
	"SwiftMailer SMTP",
	"Symfony Mailer",
	"Laravel SMTP",
	"Django SMTP",
	"Rails SMTP",
	"Nodemailer",
	"Nodemailer SMTP",
	"JavaMail",
	"JavaMail SMTP",
	"Jakarta Mail",
	"Jakarta Mail SMTP",
	"Spring Mail",
	"Spring SMTP",
	"Python smtplib",
	"Go net/smtp",
	"Ruby Net::SMTP",
	"Perl Net::SMTP",

	// ===== 虚拟/通用标识 =====
	"SMTP Gateway",
	"SMTP Relay",
	"SMTP Service",
	"Mail Gateway",
	"Mail Relay",
	"Mail Service",
	"Mail Transfer Agent",
	"MTA Gateway",
	"MTA Relay",
	"MTA Service",
	"Email Gateway",
	"Email Relay",
	"Email Service",
	"Outbound SMTP",
	"Outbound Relay",
	"Inbound SMTP",
	"Cloud SMTP",
	"Cloud Mail",
	"Cloud Relay",
	"Managed SMTP",
	"Managed Mail Service",
	"Secure SMTP",
	"Secure Mail Gateway",
	"Enterprise SMTP",
	"Enterprise Mail",
	"Corporate SMTP",
	"Corporate Mail Gateway",
	"Dedicated SMTP",
	"Hosted SMTP",
	"Hosted Mail Service",
	"Private SMTP",
	"Internal SMTP",
	"Local MTA",
	"Relay SMTP",
	"Smarthost SMTP",
	"Submission SMTP",
	"MSA SMTP",
	"MX Gateway",
	"MX Relay",
	"MX Service",
	"Mail Hub",
	"Mail Proxy",
	"Mail Router",
	"Mail Bridge",
	"Mail Dispatcher",
	"Mail Processor",
	"Mail Handler",
	"SMTP Processor",
	"SMTP Dispatcher",
	"SMTP Handler",
	"SMTP Forwarder",
	"SMTP Router",
	"SMTP Proxy",
	"SMTP Bridge",
	"SMTP Hub",
	"Messaging Gateway",
	"Messaging Service",
	"Messaging Relay",
	"Message Transfer",
	"Message Router",
	"Message Gateway",
	"Delivery Service",
	"Delivery Gateway",
	"Delivery Agent",
	"Delivery Relay",
	"Transaction Mail",
	"Transactional SMTP",
	"Bulk Mail Service",
	"Mass Mail Service",
	"Notification Service",
	"Notification SMTP",
	"Alert Service",
	"Alert SMTP",
}

// ============================================================================
// 【ESP Received 2026-05-21 从 PowerMTA 移植】5 个特定 ESP 风格 Received 头
//
// 设计原则：
//   1. 5 个 ESP Received（雅虎/软银/au/docomo/三井）是独立开关，不进入扩展头随机池
//   2. 多个并存时按 D1 方案 A 固定顺序拼接：三井 → docomo → au → softbank → 雅虎 → 原 Received
//      新 5 个用累积时间链（顶=now，往下递减 1-30 秒）；原 Received 独立用自己内部 time.Now()
//   3. 每封邮件每个字段独立随机（不做 worker 级缓存——Received 本就是高频每封不同字段）
//   4. 收件人为空时跳过 `for <>` 子句（合 RFC 5322）
//   5. 所有日期使用日本时区 +0900（用 time.FixedZone 固定，不依赖服务器本地 TZ）
//   6. CIDR / 域名 / 编号池硬编码，不参与 fatcode 替换（避免不同机器 Received 风格漂移）
//
// 危险提示（写在帮助文档，不在 UI 弹窗）：
//   - Received 总数建议 ≤ 2 个，6 个全开反指纹效果反向
//   - 雅虎+发件域 docomo 组合容易被反查识破
//   - softbank 含 172.16-31 私网 IP 是真实特征，不要"修复"
//   - 勾选任意 ESP Received 时，强烈建议同时取消"Received（随机生成）"避免与 Haraka 自家
//     custom_received_header.js 追加的 Received 累积过多
// ============================================================================

// receivedJST 日本时区（固定 +0900，不依赖服务器本地 TZ）
var receivedJST = time.FixedZone("JST", 9*3600)

// yahooCidrStrings 雅虎 Japan 的 122 条 CIDR 段（由用户提供，按原样硬编码）
// 含重叠段（如 43.223.0.0/24 和 43.223.0.0/16 都保留）—— 按"段数量均匀随机"逻辑各算一条
var yahooCidrStrings = []string{
	"43.223.91.0/24", "43.223.90.0/24", "43.223.89.0/24", "43.223.88.0/24",
	"43.223.87.0/24", "43.223.86.0/24", "43.223.85.0/24", "43.223.84.0/24",
	"43.223.83.0/24", "43.223.82.0/24", "43.223.81.0/24", "43.223.80.0/24",
	"43.223.79.0/24", "43.223.78.0/24", "43.223.77.0/24", "43.223.76.0/24",
	"43.223.75.0/24", "43.223.74.0/24", "43.223.73.0/24", "43.223.72.0/24",
	"43.223.71.0/24", "43.223.70.0/24", "43.223.7.0/24", "43.223.69.0/24",
	"43.223.68.0/24", "43.223.67.0/24", "43.223.66.0/24", "43.223.65.0/24",
	"43.223.64.0/24", "43.223.6.0/24", "43.223.5.0/24", "43.223.47.0/24",
	"43.223.46.0/24", "43.223.45.0/24", "43.223.44.0/24", "43.223.43.0/24",
	"43.223.42.0/24", "43.223.41.0/24", "43.223.40.0/24", "43.223.4.0/24",
	"43.223.39.0/24", "43.223.38.0/24", "43.223.37.0/24", "43.223.36.0/24",
	"43.223.35.0/24", "43.223.34.0/24", "43.223.33.0/24", "43.223.32.0/24",
	"43.223.31.0/24", "43.223.30.0/24", "43.223.3.0/24", "43.223.29.0/24",
	"43.223.28.0/24", "43.223.25.0/24", "43.223.24.0/24", "43.223.23.0/24",
	"43.223.22.0/24", "43.223.21.0/24", "43.223.20.0/24", "43.223.2.0/24",
	"43.223.19.0/24", "43.223.18.0/24", "43.223.17.0/24", "43.223.16.0/24",
	"43.223.1.0/24", "43.223.0.0/24", "43.223.0.0/16",
	"103.2.244.0/22", "103.2.28.0/24", "103.2.30.0/23", "103.2.30.0/24",
	"103.2.31.0/24",
	"104.145.16.0/20", "114.110.48.0/20", "114.111.64.0/18", "118.151.224.0/19",
	"119.235.236.0/24", "119.235.237.0/24", "119.235.236.0/23",
	"119.235.224.0/24", "119.235.232.0/24", "119.235.235.0/24",
	"124.83.128.0/17",
	"147.92.130.0/24", "147.92.129.0/24", "147.92.128.0/24", "147.92.128.0/17",
	"147.92.169.0/24", "147.92.202.0/24", "147.92.201.0/24", "147.92.200.0/24",
	"147.92.188.0/24", "147.92.168.0/24", "147.92.167.0/24", "147.92.166.0/24",
	"147.92.165.0/24", "147.92.164.0/24", "147.92.135.0/24", "147.92.134.0/24",
	"147.92.133.0/24", "147.92.132.0/24", "147.92.131.0/24",
	"182.22.0.0/17", "183.79.0.0/16",
	"202.239.0.0/20", "202.93.64.0/19",
	"203.104.156.0/23", "203.104.128.0/20", "203.104.144.0/21", "203.104.152.0/22",
	"203.141.32.0/20", "203.141.54.0/24",
	"203.216.224.0/19",
	"210.171.36.0/22", "210.171.60.0/22", "210.229.224.0/19", "210.250.224.0/19",
	"210.252.64.0/19",
	"211.14.28.0/23", "211.14.26.0/23", "211.14.12.0/22", "211.14.8.0/24",
}

// yahooNets 启动时解析好的 CIDR 池（package init，避免每封邮件解析的开销）
// 任何一条解析失败会 panic 并明确指出哪一条（避免运行时静默用空池）
var yahooNets []*net.IPNet

// nonRoutableNets 非公网可路由段（"随机 IP"模式时排除的 9 段，业界标准）
var nonRoutableNets []*net.IPNet

// nonRoutableCidrs 9 段非公网（4 段经典私网 + 业界标准补全 5 段）
var nonRoutableCidrs = []string{
	"0.0.0.0/8",       // 本地/保留
	"10.0.0.0/8",      // Private A
	"100.64.0.0/10",   // CGN 运营商级 NAT（RFC 6598）
	"127.0.0.0/8",     // Loopback
	"169.254.0.0/16",  // APIPA 链路本地
	"172.16.0.0/12",   // Private B
	"192.168.0.0/16",  // Private C
	"224.0.0.0/4",     // 组播 D 类
	"240.0.0.0/4",     // 保留 E 类
}

// softbank172Net 软银 Received 的"内部中继私网 IP"段（172.16.0.0/12）
var softbank172Net *net.IPNet

func init() {
	yahooNets = make([]*net.IPNet, 0, len(yahooCidrStrings))
	for _, s := range yahooCidrStrings {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("ESP Received: 雅虎 CIDR 池解析失败 %q: %v", s, err))
		}
		yahooNets = append(yahooNets, n)
	}

	nonRoutableNets = make([]*net.IPNet, 0, len(nonRoutableCidrs))
	for _, s := range nonRoutableCidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("ESP Received: 非公网排除段解析失败 %q: %v", s, err))
		}
		nonRoutableNets = append(nonRoutableNets, n)
	}

	_, sb172, err := net.ParseCIDR("172.16.0.0/12")
	if err != nil {
		panic(fmt.Sprintf("ESP Received: softbank 172.16.0.0/12 解析失败: %v", err))
	}
	softbank172Net = sb172
}

// ===== 通用辅助函数 =====

// ipToUint32 将 net.IP 转为 uint32（IPv4 only）
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// uint32ToIPv4 将 uint32 转为点分十进制 IPv4
func uint32ToIPv4(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", (u>>24)&0xFF, (u>>16)&0xFF, (u>>8)&0xFF, u&0xFF)
}

// randomIPInCIDR 在 CIDR 段内随机一个 IP，避开网络号（.0）和广播号（.255 等）
// /31 和 /32 直接返回段基地址（这俩没有"内部地址"概念）
func randomIPInCIDR(r *mathrand.Rand, n *net.IPNet) string {
	ones, bits := n.Mask.Size()
	hostBits := uint(bits - ones)
	if hostBits <= 1 {
		// /31 /32：直接返回基地址
		return uint32ToIPv4(ipToUint32(n.IP))
	}
	size := uint32(1) << hostBits
	// 可用偏移 [1, size-2]
	offset := uint32(safeIntn(r, int(size)-2)) + 1
	return uint32ToIPv4(ipToUint32(n.IP) + offset)
}

// randomYahooIP 从 122 条雅虎 CIDR 池里均匀随机选一段，再段内随机一个 IP
func randomYahooIP(r *mathrand.Rand) string {
	if len(yahooNets) == 0 {
		// 兜底防御（理论上 init() 会 panic，不会到这）
		return "183.79.0.1"
	}
	idx := safeIntn(r, len(yahooNets))
	return randomIPInCIDR(r, yahooNets[idx])
}

// randomPublicIP 全球随机公网可路由 IPv4，排除 9 段非公网
// 用拒绝采样：随机 32 位 → 落在排除段就重抽。9 段总覆盖 < 14%，平均 1.16 次命中
func randomPublicIP(r *mathrand.Rand) string {
	for tries := 0; tries < 100; tries++ {
		u := uint32(r.Int63n(int64(1) << 32))
		ip := net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
		excluded := false
		for _, n := range nonRoutableNets {
			if n.Contains(ip) {
				excluded = true
				break
			}
		}
		if !excluded {
			return uint32ToIPv4(u)
		}
	}
	// 兜底：100 次都没选中（概率 < 10^-90），返回一个保证公网的 IP
	return "203.0.114.1"
}

// randomSoftbank172IP 软银 Received 用的 172.16.0.0/12 内随机 IP（避开网络号/广播号）
func randomSoftbank172IP(r *mathrand.Rand) string {
	return randomIPInCIDR(r, softbank172Net)
}

// random4UpperLetters 4 个大写字母随机（A-Z）
func random4UpperLetters(r *mathrand.Rand) string {
	b := make([]byte, 4)
	for i := range b {
		b[i] = byte('A' + safeIntn(r, 26))
	}
	return string(b)
}

// random5Digits 5 位数字随机（可有前导零）
func random5Digits(r *mathrand.Rand) string {
	return fmt.Sprintf("%05d", safeIntn(r, 100000))
}

// random11AlphaNumUpper 11 位大写字母+数字混合（Postfix queue ID 风格）
func random11AlphaNumUpper(r *mathrand.Rand) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 11)
	for i := range b {
		b[i] = charset[safeIntn(r, len(charset))]
	}
	return string(b)
}

// format17Timestamp yyyyMMddHHmmssfff（17 位：年4 月2 日2 时2 分2 秒2 + 毫秒3）
// 输入 t 应已转为 JST（调用方负责）
func format17Timestamp(t time.Time) string {
	return t.Format("20060102150405") + fmt.Sprintf("%03d", t.Nanosecond()/1000000)
}

// formatReceivedJSTDate 普通日期格式 "Mon, 02 Jan 2006 15:04:05 +0900"
// 输入 t 应已转为 JST（调用方负责）
func formatReceivedJSTDate(t time.Time) string {
	return t.Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

// formatReceivedJSTDateWithJST 带 (JST) 后缀（docomo 风格）
func formatReceivedJSTDateWithJST(t time.Time) string {
	return t.Format("Mon, 02 Jan 2006 15:04:05 -0700") + " (JST)"
}

// ===== Yahoo Received =====

// yahooEhloSubdomains EHLO 内层域的 3 个子分类（每个 600 个编号 mta001-600）
var yahooEhloSubdomains = []string{"kks", "kth", "ssk"}

// yahooByPool by 外层域的 6 个范式（每个 160 个编号）
// 第 1 字段 = 前缀模板（用 %04d 或 %03d）；第 2 字段 = 起始编号；第 3 字段 = 数字位宽
type yahooByPattern struct {
	template string // 前缀如 "mta%04d.mail.otm.ynwp.yahoo.co.jp"
	startNum int    // 起始编号（含）
	endNum   int    // 结束编号（含）
}

var yahooByPool = []yahooByPattern{
	{"mta%04d.mail.otm.ynwp.yahoo.co.jp", 1, 160},      // mta0001-0160.mail.otm
	{"mta%04d.mail.snz.ynwp.yahoo.co.jp", 2001, 2160},  // mta2001-2160.mail.snz
	{"mtaat%04d.mail.otm.ynwp.yahoo.co.jp", 1, 160},    // mtaat0001-0160.mail.otm
	{"mtaat%04d.mail.snz.ynwp.yahoo.co.jp", 2001, 2160}, // mtaat2001-2160.mail.snz
	{"mta%03d.kks.gm.yahoo.co.jp", 1, 160},             // mta001-160.kks.gm
	{"mta%03d.ssk.gm.yahoo.co.jp", 1, 160},             // mta001-160.ssk.gm
}

// generateReceivedYahoo 生成"雅虎"风格 Received 头
//
// 格式（缩进严格按用户示例：from 后 2 个空格，第 2 行前 2 个空格）：
//
//	Received: from {IP1}  (EHLO {EHLO域}) ({IP2})
//	  by {BY域} with SMTP; {日期}
//
// 参数：
//   - toAddress: 收件人地址（雅虎风格没有 for <> 子句，此参数仅为统一签名）
//   - useYahooIP: true=从 CIDR 池抽 IP；false=全球随机公网 IP（排 9 段非公网）
//   - t: 该 Received 的时间戳（已含 JST 时区，调用方算好）
func (hg *HeaderGenerator) generateReceivedYahoo(toAddress string, useYahooIP bool, t time.Time) string {
	_ = toAddress // 雅虎示例没有 for <>，保留参数维持签名统一

	var ip1, ip2 string
	if useYahooIP {
		ip1 = randomYahooIP(hg.random)
		ip2 = randomYahooIP(hg.random)
	} else {
		ip1 = randomPublicIP(hg.random)
		ip2 = randomPublicIP(hg.random)
	}

	// EHLO 内层域：mta{001-600}.{kks|kth|ssk}.gm.yahoo.co.jp
	ehloSub := yahooEhloSubdomains[safeIntn(hg.random, len(yahooEhloSubdomains))]
	ehloNum := safeIntn(hg.random, 600) + 1 // 1-600
	ehloDomain := fmt.Sprintf("mta%03d.%s.gm.yahoo.co.jp", ehloNum, ehloSub)

	// by 外层域：6 种范式之一
	byPat := yahooByPool[safeIntn(hg.random, len(yahooByPool))]
	byNum := safeIntn(hg.random, byPat.endNum-byPat.startNum+1) + byPat.startNum
	byDomain := fmt.Sprintf(byPat.template, byNum)

	return fmt.Sprintf("Received: from %s  (EHLO %s) (%s)\r\n"+
		"  by %s with SMTP; %s\r\n",
		ip1, ehloDomain, ip2,
		byDomain, formatReceivedJSTDate(t))
}

// ===== au Received =====

// generateReceivedAu 生成"au"风格 Received 头
//
// 格式：
//
//	Received: from mail.au.com by mta-snd-e{NN}.au.com with ESMTP
//	  id <{17位时间}.{4大写}.{5数字}.mail.au.com@mta-snd-e{NN}.au.com>
//	  for <{收件人}>;
//	  {日期}
//
// e 编号 01-99 两处一致；收件人为空时跳过 for 子句
func (hg *HeaderGenerator) generateReceivedAu(toAddress string, t time.Time) string {
	eNum := safeIntn(hg.random, 99) + 1 // 1-99
	eStr := fmt.Sprintf("e%02d", eNum)  // e01-e99
	mtaSndDomain := fmt.Sprintf("mta-snd-%s.au.com", eStr)

	timestamp17 := format17Timestamp(t)
	letters4 := random4UpperLetters(hg.random)
	digits5 := random5Digits(hg.random)

	idStr := fmt.Sprintf("%s.%s.%s.mail.au.com@%s",
		timestamp17, letters4, digits5, mtaSndDomain)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Received: from mail.au.com by %s with ESMTP\r\n", mtaSndDomain))
	sb.WriteString(fmt.Sprintf("  id <%s>\r\n", idStr))
	if toAddress != "" {
		sb.WriteString(fmt.Sprintf("  for <%s>;\r\n", toAddress))
	}
	sb.WriteString(fmt.Sprintf("  %s\r\n", formatReceivedJSTDate(t)))

	return sb.String()
}

// ===== Softbank Received =====

// generateReceivedSoftbank 生成"软银"风格 Received 头
//
// 格式（注意续行缩进 = 10 个空格，是 softbank 真实邮件特征）：
//
//	Received: from ebmky{XXX}sc.i.softbank.jp ([{172.X.X.X}])
//	          by dimky{XXX}sc.i.softbank.jp with ESMTP
//	          id <{17位时间}.{4大写}.{5数字}.dimky{XXX}sc.i.softbank.jp@dimky{XXX}sb.mailsv.softbank.jp>
//	          for <{收件人}>; {日期}
//
//   - ebmky 编号 101-150（3 位）
//   - dimky-sc 编号 101-150（by 行 和 id 内 @ 之前的 dimky 一致）
//   - dimky-sb 编号 101-150（独立于 dimky-sc）
//   - IP 来自 172.16.0.0/12 私网段（真实软银特征）
//   - 收件人为空时跳过 for 子句，但保留日期
func (hg *HeaderGenerator) generateReceivedSoftbank(toAddress string, t time.Time) string {
	const indent = "          " // 10 个空格

	ebmkyNum := safeIntn(hg.random, 50) + 101  // 101-150
	dimkyScNum := safeIntn(hg.random, 50) + 101 // 101-150
	dimkySbNum := safeIntn(hg.random, 50) + 101 // 101-150

	ebmkyDomain := fmt.Sprintf("ebmky%03dsc.i.softbank.jp", ebmkyNum)
	dimkyScDomain := fmt.Sprintf("dimky%03dsc.i.softbank.jp", dimkyScNum)
	dimkySbDomain := fmt.Sprintf("dimky%03dsb.mailsv.softbank.jp", dimkySbNum)
	ip := randomSoftbank172IP(hg.random)

	timestamp17 := format17Timestamp(t)
	letters4 := random4UpperLetters(hg.random)
	digits5 := random5Digits(hg.random)

	idStr := fmt.Sprintf("%s.%s.%s.%s@%s",
		timestamp17, letters4, digits5, dimkyScDomain, dimkySbDomain)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Received: from %s ([%s])\r\n", ebmkyDomain, ip))
	sb.WriteString(fmt.Sprintf("%sby %s with ESMTP\r\n", indent, dimkyScDomain))
	sb.WriteString(fmt.Sprintf("%sid <%s>\r\n", indent, idStr))
	if toAddress != "" {
		sb.WriteString(fmt.Sprintf("%sfor <%s>; %s\r\n", indent, toAddress, formatReceivedJSTDate(t)))
	} else {
		sb.WriteString(fmt.Sprintf("%s%s\r\n", indent, formatReceivedJSTDate(t)))
	}

	return sb.String()
}

// ===== Docomo Received =====

// generateReceivedDocomo 生成"docomo"风格 Received 头
//
// 格式（Postfix 标准 1 空格缩进，日期后带 (JST)）：
//
//	Received: from mail{N}.docomo-bill.ne.jp (localhost [127.0.0.1])
//	 by localhost.docomo.ne.jp (Postfix) with ESMTP id {11位大写+数字}
//	 for <{收件人}>; {日期} (JST)
//
//   - mail{N}：N 是 1-10 整数（无前导零）
//   - 11 位大写字母+数字混合（Postfix queue ID 风格）
func (hg *HeaderGenerator) generateReceivedDocomo(toAddress string, t time.Time) string {
	mailNum := safeIntn(hg.random, 10) + 1 // 1-10
	mailDomain := fmt.Sprintf("mail%d.docomo-bill.ne.jp", mailNum)
	queueID := random11AlphaNumUpper(hg.random)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Received: from %s (localhost [127.0.0.1])\r\n", mailDomain))
	sb.WriteString(fmt.Sprintf(" by localhost.docomo.ne.jp (Postfix) with ESMTP id %s\r\n", queueID))
	if toAddress != "" {
		sb.WriteString(fmt.Sprintf(" for <%s>; %s\r\n", toAddress, formatReceivedJSTDateWithJST(t)))
	} else {
		sb.WriteString(fmt.Sprintf(" %s\r\n", formatReceivedJSTDateWithJST(t)))
	}

	return sb.String()
}

// ===== 三井 Received =====

// generateReceivedMitsui 生成"三井"风格 Received 头
//
// 格式（vpass→smbc，几乎全固定，仅日期变化）：
//
//	Received: from mail.vpass.ne.jp by mail.smbc.co.jp;
//	   {日期}
//
// 第 2 行 3 空格缩进。没有 for <> 子句，不接收 toAddress
func (hg *HeaderGenerator) generateReceivedMitsui(t time.Time) string {
	return fmt.Sprintf("Received: from mail.vpass.ne.jp by mail.smbc.co.jp;\r\n"+
		"   %s\r\n", formatReceivedJSTDate(t))
}

// ===== 统一入口：按 D1 方案 A 拼接 6 个 Received =====

// GenerateAllReceived 按 D1 方案 A 拼接所有勾选的 Received 头
//
// 顺序（从顶到底，符合 RFC 5321：越靠上越是最新一跳）：
//
//	三井 → docomo → au → softbank → 雅虎 → 原 Received（随机生成）
//
// 时间链：
//   - 新 5 个 ESP Received 用累积时间链：顶 = now(JST)，每往下减 1-30 秒
//   - 原 Received 不参与时间链，独立用自己内部的 time.Now()（B2/D1 用户决策）
//
// 返回值已含全部勾选 Received 的 raw 字符串（每个头以 "\r\n" 结尾）；若全部未勾选，返回空串
//
// 调用方约定：builder.go 在自定义邮件头段调用一次本函数即可，取代原 if Received { generateReceived(...) } 两行
// 【2026-05-27 从 PowerMTA 移植】签名扩展加 vp + recipient（用于 Received 随机模板渲染）
func (hg *HeaderGenerator) GenerateAllReceived(envelopeFrom, envelopeTo, fromDomain string, vp *VariableProcessor, recipient *types.Recipient) string {
	if hg.cfg == nil || !hg.cfg.Enabled {
		return ""
	}

	// JST 基准时间（与示例 +0900 对齐）
	tBase := time.Now().In(receivedJST)

	// 按顺序收集启用的生成器
	type receivedFn func(t time.Time) string
	var generators []receivedFn

	if hg.cfg.ReceivedMitsui {
		generators = append(generators, func(t time.Time) string {
			return hg.generateReceivedMitsui(t)
		})
	}
	if hg.cfg.ReceivedDocomo {
		generators = append(generators, func(t time.Time) string {
			return hg.generateReceivedDocomo(envelopeTo, t)
		})
	}
	if hg.cfg.ReceivedAu {
		generators = append(generators, func(t time.Time) string {
			return hg.generateReceivedAu(envelopeTo, t)
		})
	}
	if hg.cfg.ReceivedSoftbank {
		generators = append(generators, func(t time.Time) string {
			return hg.generateReceivedSoftbank(envelopeTo, t)
		})
	}
	if hg.cfg.ReceivedYahoo {
		useYahooIP := hg.cfg.ReceivedYahooIPMode != "random" // 默认 yahoo（含空串、"yahoo"），仅 "random" 走全球随机
		generators = append(generators, func(t time.Time) string {
			return hg.generateReceivedYahoo(envelopeTo, useYahooIP, t)
		})
	}

	// 【2026-05-27 从 PowerMTA 移植】Received（随机）—— 插在雅虎和原 Received 之间
	// 注意：闭包接收 t（generators slice 协议要求）但丢弃；Received 随机模板内部用 {RFC2822_*} 自取时间
	if hg.cfg.ReceivedRandomEnabled && len(hg.cfg.ReceivedRandomTemplates) > 0 && vp != nil && recipient != nil {
		generators = append(generators, func(_ time.Time) string {
			return hg.generateReceivedRandom(vp, recipient)
		})
	}

	// 按累积时间链生成（顶 = now，每往下减 1-30 秒）
	var sb strings.Builder
	currentTime := tBase
	for i, gen := range generators {
		if i > 0 {
			delta := time.Duration(safeIntn(hg.random, 30)+1) * time.Second
			currentTime = currentTime.Add(-delta)
		}
		sb.WriteString(gen(currentTime))
	}

	// Received：对齐 mail_rewrite.js，by 使用 VPS 绑定域
	if hg.cfg.Received {
		sb.WriteString(hg.generateReceivedMailRewrite(envelopeFrom, envelopeTo, fromDomain))
	}

	return sb.String()
}

// 【2026-05-27 从 PowerMTA 移植】generateReceivedRandom 生成"Received（随机）"头
//
// 工作流程：
//  1. 从 cfg.ReceivedRandomTemplates 池里选一条模板（按 mode = sequential | random）
//  2. 用 vp.Process 渲染模板中的变量占位符（{IP_YAHOO_JP} / {RFC2822_*} 等）
//  3. RFC 5322 §2.2.3 折叠（长行 > 78 字符断行 + CRLF + TAB）
//  4. 拼上 "Received: " 前缀和 "\r\n" 收尾
//
// 【B3 决策】顺序模式用 worker 独立计数器（worker 内顺序但 worker 间交错）
// 【B4 决策】不走 Worker 50-200 寿命池，每封都重新挑（最大反指纹熵）
//
// 注意：模板设计上时间由 {RFC2822_*} 等变量自己取 time.Now()，本函数不接受外部 t 参数。
// 上层调用方（GenerateAllReceived）在 generators 闭包里会丢弃 t 参数。
func (hg *HeaderGenerator) generateReceivedRandom(vp *VariableProcessor, recipient *types.Recipient) string {
	tpls := hg.cfg.ReceivedRandomTemplates
	n := len(tpls)
	if n == 0 {
		return ""
	}

	// 选模板（顺序 vs 随机）
	// 大小写规范化（防御用户手改 config.json 写成 "Sequential"）
	var tpl string
	if strings.EqualFold(strings.TrimSpace(hg.cfg.ReceivedRandomMode), "sequential") {
		tpl = tpls[hg.receivedRandomSeqIdx%n]
		hg.receivedRandomSeqIdx++
	} else {
		// 默认随机（空串、"random" 都走这里）
		tpl = tpls[safeIntn(hg.random, n)]
	}

	// 防御性：跳过空模板（用户可能粘了空行）
	tpl = strings.TrimSpace(tpl)
	if tpl == "" {
		return ""
	}

	// 渲染变量
	rendered := vp.Process(tpl, recipient)

	// 折叠（含 "Received: " 前缀的宽度预留）
	folded := foldHeaderValue(rendered, len("Received: "))

	return "Received: " + folded + "\r\n"
}
