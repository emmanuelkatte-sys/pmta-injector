// Package email 负责邮件内容的完整构建与后处理。
//
// 功能包括：HTML 模板渲染、变量替换、MIME 多部分组装、
// 扩展邮件头生成（Received/DKIM/List-Unsubscribe 等）、字符集编码、
// 附件/CID 内嵌图片，以及 headers_postprocess 的字段名随机大小写与锚定乱序。
package email

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/types"
	"__MODULE_PLACEHOLDER__/utils"
)

const undisclosedRecipientsTo = "undisclosed-recipients:;"

// cidInboxPlainBodyLabel legacy 模式：HTML 正文按 text/plain 投递（au 20/20 进箱结构）。
func (b *Builder) cidInboxPlainBodyLabel() bool {
	if len(b.cfg.Email.EmbeddedImages) == 0 {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(b.cfg.Email.CidInboxMode))
	return mode == "legacy" || mode == "plain"
}

// mimeBodyContentType 返回正文 MIME Content-Type（legacy=plain 标签 bypass 过滤）。
func (b *Builder) mimeBodyContentType(content string) string {
	if b.cidInboxPlainBodyLabel() {
		return "text/plain"
	}
	if b.bodyIsHTML(content) {
		return "text/html"
	}
	return "text/plain"
}

// Email 邮件结构
type Email struct {
	// 信封信息
	EnvelopeFrom string
	EnvelopeTo   string
	VirtualMTA   string
	JobID        string

	// 邮件头
	From      string
	FromAddress string // 裸发件邮箱（List-Unsubscribe 等）
	To        string
	Subject   string
	Date      time.Time
	MessageID string

	// 【2026-05-27 从 PowerMTA 移植】主邮件的 Cc 头(已 RFC 5322 编码,逗号分隔多个地址)
	// 仅主邮件构建时由 Build 根据 BuildOptions.CcHeaderList 填充
	// CC/BCC 独立邮件构建时 CcHeader 为空,buildRawEmail 跳过 Cc 头输出
	// (BCC 永远不出现在 raw 中,所以这里没有 BccHeader 字段)
	CcHeader string

	// 【2026-05-27 β 决策 - Haraka 独有】CC/BCC 独立邮件标记
	// true → buildRawEmail 输出 X-Internal-CcBcc-Skip-Tg: 1 头
	//        Haraka log_delivered.js 在 hook_data_post 检测此头 → 跳过 Telegram 推送
	// 设计目的: 1000 主收件人 × 10 CC = 10000 条 Telegram 推送会把频控打爆,
	//          所以 CC/BCC 独立邮件不进 Telegram 推送(仍正常进 counter_total + 投递)
	// 安全: hook_data_post 会同步删除该头,接收方看不到
	SkipTelegram bool

	// 内容
	HTMLBody string
	TextBody string

	// 附件
	Attachments []Attachment

	// 【Haraka24】CID 内嵌图片
	EmbeddedImages []EmbeddedImage

	// 完整内容
	Raw string
}

// 【2026-05-27 从 PowerMTA 移植】BuildOptions Build 的可选参数
//
// 设计说明:
//   - 默认零值 (BuildOptions{}) 等价于旧行为(单收件人主邮件,不含 Cc 头)
//   - 主邮件构建: CcHeaderList = 本封分配的 CC 地址列表(非空时 Build 自动编码进 email.CcHeader)
//   - CC/BCC 独立邮件构建: 全部字段保持零值,Build 行为与旧版完全一致
//
// 为什么用 struct 而不是可变参数:
//   - 未来加 BccHeader / Headers 等字段时不破坏二进制兼容
//   - 调用方意图明确(builder.Build(data, email.BuildOptions{CcHeaderList: ccList}))
type BuildOptions struct {
	// CcHeaderList 主邮件的 CC 地址列表
	// 非空时 buildRawEmail 在 To 头后输出 "Cc: addr1, addr2, ..."
	// 用于让主收件人能看到本封邮件还抄送给了谁(传统 CC 语义)
	CcHeaderList []string

	// 【2026-05-27 β 决策 - Haraka 独有】SkipTelegram 标记此封为 CC/BCC 独立邮件
	// true → builder 输出 X-Internal-CcBcc-Skip-Tg: 1 头到 raw,
	//        Haraka log_delivered.js 在 hook_data_post 检测到此头时跳过 Telegram 推送
	// 仅 dispatcher.buildAndInjectOne 在 CC/BCC 独立邮件分支应传 true,主邮件传 false(零值)
	SkipTelegram bool

	IsBacktest bool
}

// 【Haraka24】CID 内嵌图片数据（已加载到内存）
type EmbeddedImage struct {
	CID         string // Content-ID 标识
	ContentType string // MIME 类型
	FileName    string // 原始文件名（用于 Content-Type name 和 Content-Disposition filename）
	Content     []byte // 图片二进制数据
}

// Attachment 附件结构
type Attachment struct {
	FileName    string
	FilePath    string
	ContentType string
	Content     []byte
}

// Builder 邮件构建器
type Builder struct {
	cfg        *config.Config
	tmplEngine *TemplateEngine
	varProc    *VariableProcessor
	headerGen  *HeaderGenerator

	// 【修复问题11】附件内容缓存：每个文件只从硬盘读取一次
	attachmentCache map[string]*Attachment

	// 【Haraka26】自定义 From 邮箱轮选计数器
	customFromIndex int

	mime *mimeIdentity
	arc  *arcSealer
}

// NewBuilder 创建构建器
// 【v62修复】增加 workerID 参数，确保每个 worker 的随机数种子唯一
func NewBuilder(cfg *config.Config, tmplEngine *TemplateEngine, workerID int) *Builder {
	hg := NewHeaderGenerator(&cfg.Headers, workerID)
	hg.fingerprintKey = identityFingerprint(cfg)
	return &Builder{
		cfg:             cfg,
		tmplEngine:      tmplEngine,
		varProc:         NewVariableProcessor(cfg, workerID),
		headerGen:       hg,
		attachmentCache: make(map[string]*Attachment),
		arc:             newArcSealer(cfg),
	}
}

// 【v66新增】getCharset 获取已解析的字符集配置
// 统一 charset 的获取逻辑，确保 Build() 和 buildRawEmail() 用同一个值
func (b *Builder) getCharset() string {
	charset := b.cfg.Encoding.Charset
	if charset == "" {
		charset = b.cfg.Email.Charset
	}
	if isUTF8Charset(charset) && !isUTF8Charset(b.cfg.Email.Charset) {
		charset = b.cfg.Email.Charset
	}
	if charset == "" {
		charset = "UTF-8"
	}
	return charset
}

// bidiRNG 按发信身份固定倒序分组（同一 IP/域名跨任务一致，不跟批次/收件人/纳秒走）。
func (b *Builder) bidiRNG() *rand.Rand {
	return identityRNG(b.cfg, "bidi")
}

// keywordsForTemplate 返回当前模板的关键字列表；空路径时使用合并后的 zero_width.keywords
func (b *Builder) keywordsForTemplate(templatePath string) []string {
	if templatePath != "" && b.cfg.Email.TemplateKeywords != nil {
		if raw, ok := b.cfg.Email.TemplateKeywords[templatePath]; ok && strings.TrimSpace(raw) != "" {
			return ParseKeywords(raw)
		}
		base := filepath.Base(templatePath)
		if raw, ok := b.cfg.Email.TemplateKeywords[base]; ok && strings.TrimSpace(raw) != "" {
			return ParseKeywords(raw)
		}
	}
	return ParseKeywords(b.cfg.ZeroWidth.Keywords)
}

// deriveTextTemplatePath 由 HTML 模板路径推导同名 .txt 纯文本模板路径。
func deriveTextTemplatePath(htmlPath string) string {
	htmlPath = strings.TrimSpace(htmlPath)
	if htmlPath == "" {
		return ""
	}
	ext := filepath.Ext(htmlPath)
	if ext == "" {
		return htmlPath + ".txt"
	}
	return strings.TrimSuffix(htmlPath, ext) + ".txt"
}

// renderTextBody 渲染与 HTML 模板配对的纯文本模板（template.txt）。
func (b *Builder) renderTextBody(templatePath string, data *TemplateData, recipient *types.Recipient, bidiRNG *rand.Rand) string {
	textPath := deriveTextTemplatePath(templatePath)
	if textPath == "" {
		return ""
	}
	if _, err := os.Stat(textPath); err != nil {
		return ""
	}
	textBody, err := b.tmplEngine.RenderFile(textPath, data)
	if err != nil {
		return ""
	}
	textBody = b.varProc.Process(textBody, recipient)
	tplKeywords := b.keywordsForTemplate(templatePath)
	if b.cfg.ReverseBidi.TemplateContent && bidiCharsetSupported(b.getCharset()) {
		textBody = RestoreBidiPlaintext(textBody)
		textBody = applyBidiAtKeywordsEveryTwoChars(textBody, tplKeywords, false, bidiRNG)
	}
	if b.cfg.ZeroWidth.Enabled && b.cfg.ZeroWidth.TemplateContent && len(tplKeywords) > 0 {
		textBody = InsertZeroWidthAtKeywords(textBody, tplKeywords, false)
	}
	return NormalizeLineEndings(textBody)
}

// messageIDDomain 按配置选择 Message-ID 的 @ 右侧域名（主域名或完整发信子域）
func (b *Builder) messageIDDomain(fallbackFrom string) string {
	h := b.cfg.Headers
	if strings.EqualFold(strings.TrimSpace(h.MessageIDDomainMode), "main") && strings.TrimSpace(h.MessageIDMainDomain) != "" {
		return strings.TrimSpace(h.MessageIDMainDomain)
	}
	if strings.TrimSpace(h.MessageIDFullDomain) != "" {
		return strings.TrimSpace(h.MessageIDFullDomain)
	}
	d := fallbackFrom
	if idx := strings.Index(d, "@"); idx != -1 {
		return d[idx+1:]
	}
	return d
}

// Build 构建邮件
// 【2026-05-27 从 PowerMTA 移植】兼容签名:旧调用方不需要改动,新调用方可传 BuildOptions
// 主邮件: Build(data, BuildOptions{CcHeaderList: ccList}) → 邮件含 Cc 头
// CC/BCC 独立邮件: Build(data) 或 Build(data, BuildOptions{}) → 不含 Cc 头(与旧行为一致)
func (b *Builder) Build(data *TemplateData, opts ...BuildOptions) (*Email, error) {
	var opt BuildOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	b.resetMimeIdentity()
	messageID := b.familyMessageID(b.cfg.Sender.FromAddress)
	data.System.MessageID = messageID

	// 更新系统时间
	now := time.Now()
	data.System.Date = now.Format("2006-01-02")
	data.System.DateTime = now.Format("2006-01-02 15:04:05")
	data.System.Timestamp = now.Unix()
	data.System.Year = now.Year()
	if data.System.UUID == "" {
		data.System.UUID = utils.GenerateUUID()
	}

	// 计算变量
	data.Computed.EmailHash = utils.MD5Hash(data.Email)

	// 创建收件人对象用于变量处理
	recipient := &types.Recipient{
		Email:        data.Email,
		Name:         data.Name,
		FirstName:    data.FirstName,
		LastName:     data.LastName,
		CustomFields: data.Data,
		Index:        data.System.Index,
	}
	bidiRNG := b.bidiRNG()

	// 获取主题（支持多主题）
	subject := b.varProc.GetNextSubject()
	// 处理主题中的变量
	subject = b.varProc.Process(subject, recipient)
	// 也使用模板引擎处理
	if renderedSubject, err := b.tmplEngine.RenderString(subject, data); err == nil {
		subject = renderedSubject
	}
	// 【Haraka26】零宽字符 - 主题（按模板关键字，合并列表）
	subjectKeywords := b.keywordsForTemplate("")
	if b.cfg.ReverseBidi.Subject || b.cfg.Email.SubjectBidiReverse {
		subject = RestoreBidiPlaintext(subject)
		if bidiCharsetSupported(b.getCharset()) {
			subject = applyBidiAtKeywordsEveryTwoChars(subject, subjectKeywords, false, bidiRNG)
		}
		subject = FinalizeBidiHeaderField(subject, bidiRNG)
	}
	if b.cfg.ZeroWidth.Enabled && b.cfg.ZeroWidth.Subject && len(subjectKeywords) > 0 {
		subject = InsertZeroWidthAtKeywords(subject, subjectKeywords, false)
	}
	if !hasRtlOverride(subject) && !strings.Contains(subject, "\u200b") {
		subject = FinalizeBidiHeaderField(subject, bidiRNG)
	}
	if opt.IsBacktest {
		subject = prefixBacktestSubject(subject)
	}

	// 获取显示名（支持多显示名）
	displayName := b.varProc.GetNextDisplayName()
	// 处理显示名中的变量
	displayName = b.varProc.Process(displayName, recipient)
	// 【Haraka26】显示名支持 \r\n（将字面量 \r\n 替换为真正的回车换行字节）
	if b.cfg.Headers.DisplayNameNewline {
		displayName = strings.ReplaceAll(displayName, `\r\n`, "\r\n")
	}
	// 对齐 PHPMailer MailSender：倒序则关键字混淆 + finalize(isolate 保留零宽)；否则仅零宽；已有 RLO 不 Restore、不 balance。
	if b.cfg.ReverseBidi.DisplayName || b.cfg.Sender.DisplayNameBidiReverse {
		if bidiCharsetSupported(b.getCharset()) {
			dispKeywords := b.keywordsForTemplate("")
			if len(dispKeywords) > 0 {
				displayName = applyBidiAtKeywordsEveryTwoChars(displayName, dispKeywords, false, bidiRNG)
			}
			if !hasRtlOverride(displayName) {
				displayName = bidiReverseHide(displayName)
			}
			displayName = NormalizeBidiControlsRawUnicode(displayName)
			displayName = EnsureBidiIsolatedFormat(displayName, bidiRNG)
			displayName = isolateKeepZW(displayName)
		}
	}
	if b.cfg.ZeroWidth.Enabled && b.cfg.ZeroWidth.DisplayName {
		dispKeywords := b.keywordsForTemplate("")
		if len(dispKeywords) > 0 {
			displayName = InsertZeroWidthAtKeywords(displayName, dispKeywords, false)
		}
	}

	// 获取模板路径（支持多模板）
	templatePath := b.varProc.GetNextTemplate()

	// 渲染模板
	var htmlBody string
	var err error

	if templatePath != "" && templatePath != b.cfg.Email.TemplatePath {
		// 使用新的模板路径
		htmlBody, err = b.tmplEngine.RenderFile(templatePath, data)
	} else {
		htmlBody, err = b.tmplEngine.Render(data)
	}

	if err != nil {
		return nil, fmt.Errorf("渲染模板失败: %w", err)
	}

	// 处理模板内容中的变量
	htmlBody = b.varProc.Process(htmlBody, recipient)

	// HTML 模板结构变异（CSS 微扰 / 属性注入 / 标签替换）
	if b.cfg.HtmlMutator.Enabled {
		htmlBody = MutateHTML(htmlBody, b.cfg.HtmlMutator, mutatorSeed(b.cfg, templatePath))
	}

	tplKeywords := b.keywordsForTemplate(templatePath)
	if b.cfg.ReverseBidi.TemplateContent && bidiCharsetSupported(b.getCharset()) {
		htmlBody = RestoreBidiPlaintext(htmlBody)
		htmlBody = NormalizeBidiControlsRawUnicode(htmlBody)
		htmlBody = applyBidiAtKeywordsEveryTwoChars(htmlBody, tplKeywords, b.bodyIsHTML(htmlBody), bidiRNG)
		htmlBody = NormalizeBidiControlsRawUnicode(htmlBody)
	}
	if b.cfg.ZeroWidth.Enabled && b.cfg.ZeroWidth.TemplateContent && len(tplKeywords) > 0 {
		htmlBody = InsertZeroWidthAtKeywords(htmlBody, tplKeywords, b.bodyIsHTML(htmlBody))
	}

	// 检查是否是TXT文件且需要转换为HTML
	// 【v66修复】TextToHTML 使用配置的 charset，不再硬编码 UTF-8
	if b.cfg.Email.ConvertTxtToHtml && !isHTMLContent(htmlBody) {
		htmlBody = TextToHTML(htmlBody, b.getCharset())
	} else if !isHTMLContent(htmlBody) {
		// 纯文本，确保换行符正确
		htmlBody = NormalizeLineEndings(htmlBody)
	}

	// 【v66修复-问题4】构建发件人/收件人地址（使用配置的 charset 编码显示名）
	charset := b.getCharset()
	headerEncoding := b.cfg.Encoding.HeaderEncoding

	// 【Haraka26】自定义 From 邮箱地址（强制替换原始发件箱地址）
	fromEmail := b.cfg.Sender.FromAddress
	if b.cfg.Headers.CustomFromEnabled && len(b.cfg.Headers.CustomFromEmails) > 0 {
		emails := b.cfg.Headers.CustomFromEmails
		if strings.ToLower(b.cfg.Headers.CustomFromMode) == "random" {
			fromEmail = emails[rand.Intn(len(emails))]
		} else {
			// 顺序模式
			fromEmail = emails[b.customFromIndex%len(emails)]
			b.customFromIndex++
		}
	}
	if b.cfg.Headers.FromAddressRandomPrefix {
		fromEmail = randomFromSameDomain(fromEmail)
	}
	fromDisplay := encodeFromAddressPHPMailer(displayName, fromEmail, charset)

	if b.cfg.Headers.ListUnsubscribe {
		boundDomain := fromEmail
		if idx := strings.LastIndex(fromEmail, "@"); idx >= 0 && idx < len(fromEmail)-1 {
			boundDomain = fromEmail[idx+1:]
		}
		if u := buildUnsubscribeURL(data.Email, fromEmail, &b.cfg.Headers, boundDomain); u != "" {
			data.Computed.UnsubscribeURL = u
		}
	} else if unsubBase, ok := data.Global["UnsubscribeBase"].(string); ok && unsubBase != "" {
		data.Computed.UnsubscribeURL = fmt.Sprintf("%s?email=%s&hash=%s",
			unsubBase, utils.URLEncode(data.Email), data.Computed.EmailHash)
	}

	// 构建收件人地址（RFC 2047 编码）
	toDisplay := encodeEmailAddressWithCharset(data.Name, data.Email, charset, headerEncoding)
	// 密送模式：主邮件 To 头隐藏真实收件人（信封 RCPT TO 仍为真实地址）
	if b.cfg.BCC.Enabled && !opt.SkipTelegram {
		toDisplay = undisclosedRecipientsTo
	}

	embeddedImages := b.getEmbeddedImages()
	if len(embeddedImages) > 0 {
		htmlBody = syncInlineImageCIDReferences(htmlBody, embeddedImages)
		htmlBody = SanitizeCIDReferences(htmlBody)
	}

	textBody := b.renderTextBody(templatePath, data, recipient, bidiRNG)

	// 构建邮件对象
	email := &Email{
		EnvelopeFrom: b.cfg.Sender.EnvelopeFrom,
		EnvelopeTo:   data.Email,
		VirtualMTA:   b.cfg.PMTA.VirtualMTA,
		JobID:        b.cfg.Job.ID,
		From:         fromDisplay,
		FromAddress:  fromEmail,
		To:           toDisplay,
		Subject:      subject,
		Date:         now,
		MessageID:    messageID,
		HTMLBody:     htmlBody,
		TextBody:     textBody,
		Attachments:  b.getAttachments(),
		EmbeddedImages: embeddedImages, // 【Haraka24】加载 CID 内嵌图片
	}

	// 【2026-05-27 从 PowerMTA 移植】主邮件填充 Cc 头(已 RFC 5322 编码,逗号 + 空格分隔)
	// CC 地址不含 displayName,直接用 email 地址(CC 池只存邮箱)
	// 非 ASCII 的 CC 域名走 encodeRFC2047 编码(虽然实际几乎不会出现)
	//
	// 【v8.1.3 #22 安全防御】每个 CC 地址都过滤 CR/LF 防邮件头注入(纵深防御第 4 层)
	// 【v8.1.3 #23 RFC 5322 §2.2.3】Cc 头超长(perCC=50 时可能 1500+ 字节超 998 硬上限)→ 折叠
	if len(opt.CcHeaderList) > 0 {
		var ccParts []string
		for _, cc := range opt.CcHeaderList {
			trimmed := strings.TrimSpace(cc)
			if trimmed == "" {
				continue
			}
			// 【v8.1.3 #22】CR/LF 注入防御(纵深第 4 层)
			if strings.ContainsAny(trimmed, "\r\n") {
				trimmed = strings.ReplaceAll(trimmed, "\r", " ")
				trimmed = strings.ReplaceAll(trimmed, "\n", " ")
				trimmed = strings.TrimSpace(trimmed)
				if trimmed == "" {
					continue
				}
			}
			// CC 地址不带显示名,直接编码邮箱(若含非 ASCII 会自动 RFC 2047,但通常不会)
			if needsEncoding(trimmed) {
				ccParts = append(ccParts, encodeRFC2047WithCharset(trimmed, charset, headerEncoding))
			} else {
				ccParts = append(ccParts, trimmed)
			}
		}
		if len(ccParts) > 0 {
			rawCc := strings.Join(ccParts, ", ")
			// 【v8.1.3 #23】RFC 5322 §2.2.3 折叠: 超长 Cc 头自动折成多行,合规 + 兼容部分 MTA 的 998 字节限制
			// 短 Cc 头(< 78 字符)foldHeaderValue 内部直接返回原值,无性能开销
			email.CcHeader = foldHeaderValue(rawCc, len("Cc: "))
		}
	}

	// 【2026-05-27 β 决策 - Haraka 独有】传递 SkipTelegram 标记
	email.SkipTelegram = opt.SkipTelegram

	// 生成原始邮件内容；ARC 密封在 MIME/头后处理之后，缺钥则跳过
	email.Raw = b.buildRawEmail(email, data, recipient)
	if b.arc != nil {
		env := email.EnvelopeFrom
		if env == "" {
			env = email.FromAddress
		}
		email.Raw = b.arc.seal(email.Raw, env)
	}

	return email, nil
}

// isHTMLContent 检查内容是否是 HTML（含邮件常用的 HTML 片段，不要求完整文档结构）
func isHTMLContent(content string) bool {
	content = strings.ToLower(strings.TrimSpace(content))
	if content == "" {
		return false
	}
	if strings.HasPrefix(content, "<!doctype") ||
		strings.HasPrefix(content, "<html") ||
		strings.Contains(content, "<body") {
		return true
	}
	// 邮件模板常见：仅含 div/table/img 等片段，无 <html>/<body> 包裹
	htmlFragmentPrefixes := []string{
		"<div", "<table", "<p", "<span", "<center", "<section", "<article",
		"<header", "<footer", "<main", "<td", "<tr", "<tbody", "<thead",
	}
	for _, prefix := range htmlFragmentPrefixes {
		if strings.HasPrefix(content, prefix) {
			return true
		}
	}
	return strings.Contains(content, "<img") ||
		strings.Contains(content, "<a ") ||
		strings.Contains(content, "<br")
}

// bodyIsHTML 判断正文是否应按 text/html 投递（配置优先，再检测内容）
func (b *Builder) bodyIsHTML(content string) bool {
	ct := strings.ToLower(strings.TrimSpace(b.cfg.Email.ContentType))
	if ct == "text/html" {
		return true
	}
	if ct == "text/plain" {
		return false
	}
	return isHTMLContent(content)
}

// 【Haraka23】htmlToPlainText 将 HTML 内容转换为纯文本（用于 multipart/alternative 模式）
// 去除 HTML 标签，保留可读文本结构
func htmlToPlainText(html string) string {
	text := html

	// 处理换行标签
	reBreak := regexp.MustCompile(`(?i)<br\s*/?>`)
	text = reBreak.ReplaceAllString(text, "\n")
	rePara := regexp.MustCompile(`(?i)</p>`)
	text = rePara.ReplaceAllString(text, "\n\n")
	reDiv := regexp.MustCompile(`(?i)</div>`)
	text = reDiv.ReplaceAllString(text, "\n")
	reTr := regexp.MustCompile(`(?i)</tr>`)
	text = reTr.ReplaceAllString(text, "\n")
	reLi := regexp.MustCompile(`(?i)<li[^>]*>`)
	text = reLi.ReplaceAllString(text, "- ")
	reHr := regexp.MustCompile(`(?i)<hr\s*/?>`)
	text = reHr.ReplaceAllString(text, "\n━━━━━━━━━━━━\n")

	// 提取链接文本和 URL
	reLink := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']*)["'][^>]*>(.*?)</a>`)
	text = reLink.ReplaceAllString(text, "$2 ($1)")

	// 处理图片 alt 文本
	reImg := regexp.MustCompile(`(?i)<img[^>]+alt=["']([^"']*)["'][^>]*/?>`)
	text = reImg.ReplaceAllString(text, "[画像: $1]")

	// 去除 style 和 script 标签及其内容（Go RE2 不支持反向引用 \1，分开写）
	reStyle := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reScript := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	text = reStyle.ReplaceAllString(text, "")
	text = reScript.ReplaceAllString(text, "")

	// 去除所有剩余 HTML 标签
	reTags := regexp.MustCompile(`<[^>]+>`)
	text = reTags.ReplaceAllString(text, "")

	// HTML 实体解码
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")
	text = strings.ReplaceAll(text, "&#x27;", "'")
	text = strings.ReplaceAll(text, "&yen;", "¥")
	text = strings.ReplaceAll(text, "&copy;", "©")
	text = strings.ReplaceAll(text, "&reg;", "®")

	// 清理多余空行（保留最多两个连续换行）
	reMultiNewline := regexp.MustCompile(`\n{3,}`)
	text = reMultiNewline.ReplaceAllString(text, "\n\n")

	// 清理行首行尾空格
	lines := strings.Split(text, "\n")
	var cleaned []string
	for _, line := range lines {
		cleaned = append(cleaned, strings.TrimSpace(line))
	}
	text = strings.Join(cleaned, "\n")

	return strings.TrimSpace(text)
}

// mimeIdentity 一封信只选一个分隔符家族，三层共用同一套 ID，Message-ID 跟这个家族走。
//   outlook   ----=_NextPart_000/001/002_…     ↔  {unixnano}.{12hex}
//   // amazon    ----=_Part_N_共享ID.共享时间戳     ↔  ts_uuid_counter
//   yahoo     --==_mimepart_{13hex}_{15hex}    ↔  {13hex}_{15hex}@workerN.a.b.c.yahoo.co.jp.mail
//   phpmailer b1=_ / b2=_ / b3=_ 同一 uniqueid  ↔  {YYYYMMDDHHmmss}{20位数字}@{根域}
type mimeIdentity struct {
	family       string
	nextPartMid  string
	nextPartTail string
	amazonID     int
	amazonTS     int64
	unique       string
	yahooLeft    string
	yahooRight   string
	yahooMsgL    string
	yahooMsgR    string
}

var yahooWorkerLabels = []string{"optin", "kks", "ynwh", "nwp", "mta", "smtp", "camp", "bulk", "hop", "nws", "ads", "crm"}

func (b *Builder) lockedMimeFamily() string {
	return mimeFamilies[identityIndex(b.cfg, "mime-family", len(mimeFamilies))]
}

func (b *Builder) resetMimeIdentity() {
	// 家族按发信身份锁定；boundary 仍每封新生成（真实客户端行为）。
	b.mime = newMimeIdentity(b.lockedMimeFamily())
}

func newMimeIdentity(family string) *mimeIdentity {
	id := &mimeIdentity{family: family}
	switch family {
	case "outlook":
		id.nextPartMid = strings.ToUpper(randomHexString(4))
		id.nextPartTail = "01D" + strings.ToUpper(randomHexString(5)) + "." + strings.ToUpper(randomHexString(8))
	// case "amazon":
	//	id.amazonID = rand.Intn(1000000000)
	//	id.amazonTS = rand.Int63n(10000000000000)
	case "yahoo":
		id.yahooLeft = randomHexString(13)
		id.yahooRight = randomHexString(15)
		id.yahooMsgL = yahooHexVariant(id.yahooLeft, 7)
		id.yahooMsgR = yahooHexVariant(id.yahooRight, 11)
	default:
		id.family = "phpmailer"
		id.unique = randomHexString(32)
	}
	return id
}

func (id *mimeIdentity) messageIDKey() string {
	if id == nil {
		return "ns_hex"
	}
	switch id.family {
	case "outlook":
		return "ns_hex"
	// case "amazon":
	//	return "ts_uuid_counter"
	case "yahoo":
		return "yahoo_mimepart"
	default:
		return "phpmailer_ts_digits"
	}
}

func (id *mimeIdentity) boundary(kind string) string {
	if id == nil {
		id = newMimeIdentity("phpmailer")
	}
	part := 1
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "rel", "related":
		part = 2
	case "alt", "alternative":
		part = 3
	}
	switch id.family {
	case "outlook":
		return fmt.Sprintf("----=_NextPart_%03d_%s_%s", part-1, id.nextPartMid, id.nextPartTail)
	// case "amazon":
	//	return fmt.Sprintf("----=_Part_%07d_%09d.%013d", part, id.amazonID, id.amazonTS)
	case "yahoo":
		return fmt.Sprintf("--==_mimepart_%s_%s",
			yahooHexVariant(id.yahooLeft, part),
			yahooHexVariant(id.yahooRight, part+3))
	default:
		return fmt.Sprintf("b%d=_%s", part, id.unique)
	}
}

func yahooHexVariant(base string, salt int) string {
	if len(base) < 2 {
		return base
	}
	return base[:len(base)-2] + fmt.Sprintf("%02x", (salt*31+len(base))&0xff)
}

func (id *mimeIdentity) yahooMessageID() string {
	if id == nil {
		id = newMimeIdentity("yahoo")
	}
	n := 1000 + rand.Intn(9000)
	return fmt.Sprintf("%s_%s@worker%d.%s.%s.%s.yahoo.co.jp.mail",
		id.yahooMsgL, id.yahooMsgR, n,
		yahooWorkerLabels[rand.Intn(len(yahooWorkerLabels))],
		yahooWorkerLabels[rand.Intn(len(yahooWorkerLabels))],
		yahooWorkerLabels[rand.Intn(len(yahooWorkerLabels))])
}

func (b *Builder) mimeBoundary(kind string) string {
	if b.mime == nil {
		b.resetMimeIdentity()
	}
	return b.mime.boundary(kind)
}

func mimeRootDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, "@"); i >= 0 && i+1 < len(host) {
		host = host[i+1:]
	}
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return labels[len(labels)-2] + "." + labels[len(labels)-1]
	}
	if host == "" {
		return "localhost"
	}
	return host
}

func (b *Builder) familyMessageID(fallbackFrom string) string {
	if b.mime == nil {
		b.resetMimeIdentity()
	}
	if b.mime.family == "yahoo" {
		return b.mime.yahooMessageID()
	}
	domain := b.messageIDDomain(fallbackFrom)
	if b.mime.family == "phpmailer" {
		domain = mimeRootDomain(domain)
	}
	return b.headerGen.buildMessageIDByStyle(b.mime.messageIDKey(), domain)
}

// buildRawEmail 构建原始邮件内容（标准 RFC 5322 格式）
func (b *Builder) buildRawEmail(email *Email, data *TemplateData, recipient *types.Recipient) string {
	var sb strings.Builder

	// 【v66修复-问题1】获取编码设置（使用统一的 getCharset 方法）
	charset := b.getCharset()
	headerEncoding := b.cfg.Encoding.HeaderEncoding
	bodyEncoding := b.cfg.Encoding.BodyEncoding

	// 【修复问题4+12】随机编码：使用独立随机源，只随机化传输编码方式（不改变字符集）
	// 只在 base64 和 quoted-printable 之间随机选择
	if b.cfg.Encoding.RandomEncoding {
		encodings := []string{"base64", "quoted-printable"}
		bodyEncoding = encodings[safeIntn(b.varProc.random, len(encodings))]
	}

	// 【2026-05-31】主头切片累积 — 为后处理(字段名大小写随机化 + 锚定式乱序)铺路
	// 详见 PowerMTA 工程同步说明:headers_postprocess.go::PostprocessMainHeaders
	// 在所有主头生成完成后(MIME body 入口之前)统一应用 PostprocessMainHeaders。
	// 不变量:不丢任何头(无论开关启用与否,len 不变);开关全关时输出 == 旧版输出(顺序保持)
	mainHeaders := make([]string, 0, 32)

	// ===== PowerMTA 控制头（仅 PowerMTA 模式，Haraka 模式跳过）=====
	// Haraka 不识别 x-virtual-mta 和 x-job，若不跳过会原样出现在最终邮件中
	if b.cfg.IsPMTA() {
		if email.VirtualMTA != "" {
			mainHeaders = append(mainHeaders, fmt.Sprintf("x-virtual-mta: %s\r\n", email.VirtualMTA))
		}
		if email.JobID != "" {
			mainHeaders = append(mainHeaders, fmt.Sprintf("x-job: %s\r\n", email.JobID))
		}
	}

	// ===== 自定义 Received / DKIM =====
	headersCfg := &b.cfg.Headers
	fromDomain := email.EnvelopeFrom
	if idx := strings.Index(fromDomain, "@"); idx != -1 {
		fromDomain = fromDomain[idx+1:]
	}

	if rcvdBlock := b.headerGen.GenerateAllReceived(email.EnvelopeFrom, email.EnvelopeTo, fromDomain, b.varProc, recipient); rcvdBlock != "" {
		mainHeaders = append(mainHeaders, splitHeaderBlock(rcvdBlock)...)
	}
	if headersCfg.Enabled && headersCfg.DkimSignature {
		mainHeaders = append(mainHeaders, b.headerGen.generateDkimSignature(email.EnvelopeFrom, fromDomain))
	}

	// ===== 标准邮件头（RFC 5322）=====
	mainHeaders = append(mainHeaders, fmt.Sprintf("From: %s\r\n", email.From))
	// 伪装 From 时追加 Sender 为真实发件地址（RFC 5322 §3.6.2：实际投递代理）
	realFrom := strings.TrimSpace(b.cfg.Sender.FromAddress)
	if realFrom == "" {
		realFrom = strings.TrimSpace(email.EnvelopeFrom)
	}
	if fakeFrom := strings.TrimSpace(email.FromAddress); fakeFrom != "" && realFrom != "" && !strings.EqualFold(fakeFrom, realFrom) {
		mainHeaders = append(mainHeaders, fmt.Sprintf("Sender: %s\r\n", realFrom))
	}
	mainHeaders = append(mainHeaders, fmt.Sprintf("To: %s\r\n", email.To))
	// 【2026-05-27 从 PowerMTA 移植】Cc 头(仅主邮件且 CcHeader 非空时输出)
	if email.CcHeader != "" {
		mainHeaders = append(mainHeaders, fmt.Sprintf("Cc: %s\r\n", email.CcHeader))
	}
	// 【2026-05-27 β 决策 - Haraka 独有】CC/BCC 独立邮件加内部头标记
	// log_delivered.js 在 hook_data_post 检测到此头 → 设置 transaction.notes.cc_bcc_skip_tg = true + 同步删除该头
	// hook_delivered 据此 note 跳过 Telegram 推送,避免 1000×10 = 10000 条推送把频控打爆
	// 注意:该头字段名已加入 headers_postprocess.go::caseSkipNames(永不参与大小写随机化,
	//      否则插件按 "X-Internal-CcBcc-Skip-Tg" 精确匹配会失效)
	if email.SkipTelegram {
		mainHeaders = append(mainHeaders, "X-Internal-CcBcc-Skip-Tg: 1\r\n")
	}
	mainHeaders = append(mainHeaders, fmt.Sprintf("Subject: %s\r\n", encodeRFC2047WithCharset(email.Subject, charset, headerEncoding)))
	mainHeaders = append(mainHeaders, fmt.Sprintf("Date: %s\r\n", email.Date.Format("Mon, 02 Jan 2006 15:04:05 -0700")))

	msgID := strings.TrimSpace(email.MessageID)
	if msgID == "" {
		msgID = b.familyMessageID(email.EnvelopeFrom)
	}
	mainHeaders = append(mainHeaders, fmt.Sprintf("Message-ID: <%s>\r\n", msgID))

	mainHeaders = append(mainHeaders, "MIME-Version: 1.0\r\n")

	// Reply-To(优先使用自定义邮件头生成器)
	if headersCfg.Enabled && headersCfg.ReplyTo {
		// 由下方的 headerGen.GenerateHeaders 统一处理
	} else if b.cfg.Sender.ReplyTo != "" {
		mainHeaders = append(mainHeaders, fmt.Sprintf("Reply-To: %s\r\n", b.cfg.Sender.ReplyTo))
	}

	// ===== 自定义邮件头（X-Mailer / X-Priority / Importance / Return-Path / 扩展头 / 联动组 等）=====
	if headersCfg.Enabled {
		// 【2026-05-27 从 PowerMTA 移植】签名扩展加 vp + recipient(批次 4 List-Unsub 4 模式池模式需要)
		// 【2026-05-31】返回字符串块用 splitHeaderBlock 切单条,以便后处理逐头作用
		fromAddr := email.FromAddress
		if fromAddr == "" {
			fromAddr = email.EnvelopeFrom
		}
		if customBlock := b.headerGen.GenerateHeaders(fromAddr, email.EnvelopeTo, fromDomain, b.varProc, recipient); customBlock != "" {
			mainHeaders = append(mainHeaders, splitHeaderBlock(customBlock)...)
		}
	}

	// 自定义头（map 格式：来自 Email.CustomHeaders 字段）
	for key, value := range b.cfg.Email.CustomHeaders {
		if headersCfg.MobileClientHeaders && IsMobileBlockedHeader(key) {
			continue
		}
		renderedValue := b.varProc.Process(value, recipient)
		if rv, err := b.tmplEngine.RenderString(renderedValue, data); err == nil {
			renderedValue = rv
		}
		mainHeaders = append(mainHeaders, fmt.Sprintf("%s: %s\r\n", key, encodeRFC2047WithCharset(renderedValue, charset, headerEncoding)))
	}

	// ===== 用户在"邮件头配置"输入框中手动填写的多行自定义邮件头 =====
	if headersCfg.Enabled && headersCfg.CustomHeadersText != "" {
		lines := strings.Split(headersCfg.CustomHeadersText, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(strings.TrimRight(line, "\r"))
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			colonIdx := strings.Index(line, ":")
			if colonIdx <= 0 {
				continue
			}
			headerName := strings.TrimSpace(line[:colonIdx])
			headerValue := strings.TrimSpace(line[colonIdx+1:])
			if headerName == "" {
				continue
			}
			if headersCfg.MobileClientHeaders && IsMobileBlockedHeader(headerName) {
				continue
			}

			headerValue = b.varProc.Process(headerValue, recipient)
			if rv, err := b.tmplEngine.RenderString(headerValue, data); err == nil {
				headerValue = rv
			}

			mainHeaders = append(mainHeaders, fmt.Sprintf("%s: %s\r\n", headerName, encodeRFC2047WithCharset(headerValue, charset, headerEncoding)))
		}
	}

	// ===== 【2026-05-31】主头后处理:字段名随机大小写 + DKIM 对齐乱序 =====
	shuffleOrder := headersCfg.ShuffleOrder
	randomCase := headersCfg.RandomCase
	mainHeaders = PostprocessMainHeaders(mainHeaders, b.varProc.random,
		shuffleOrder, randomCase, headersCfg.CaseMode, headersCfg.DkimSignHeaders)

	// ===== 序列化主头到 strings.Builder =====
	for _, h := range mainHeaders {
		sb.WriteString(h)
	}

	// MIME 树（对齐 PHPMailer-injector / SMTP 发件器）:
	//   standard              — 不写纯文本 part
	//   alternative / full    — 仅当模板 TextContent（同名 .txt）非空才 alternative
	//   仅 CID                — 顶层 related
	//   纯文本 + CID          — related 包 alternative
	//   普通附件              — 顶层 mixed；内联走 related；纯文本走 alternative
	// 不从 HTML 生成纯文本。
	mimeMode := strings.ToLower(b.cfg.Email.MimeMode)
	if mimeMode == "" {
		mimeMode = "standard"
	}
	useAlternative := mimeMode == "alternative" || mimeMode == "full"
	plainText := strings.TrimSpace(email.TextBody)
	usePlainPart := useAlternative && plainText != ""

	hasAttachments := len(email.Attachments) > 0
	hasEmbeddedImages := len(email.EmbeddedImages) > 0
	bodyHTML := email.HTMLBody
	embeddedImages := email.EmbeddedImages
	mixedBoundary := b.mimeBoundary("Mixed")
	relBoundary := b.mimeBoundary("Rel")
	altBoundary := b.mimeBoundary("Alt")

	// ===== writeAttachments: 写入附件部分的闭包 =====
	writeAttachments := func(sb *strings.Builder, boundary string) {
		for _, att := range email.Attachments {
			sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			sb.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", att.ContentType, encodeRFC2047WithCharset(att.FileName, charset, headerEncoding)))
			sb.WriteString("Content-Transfer-Encoding: base64\r\n")
			sb.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", encodeRFC2047WithCharset(att.FileName, charset, headerEncoding)))
			sb.WriteString("\r\n")
			// 【Haraka26】图片噪点：对图片附件添加随机噪点
			content := att.Content
			if b.cfg.ImageNoise.Enabled {
				content = AddImageNoise(content, att.FileName)
			}
			encoded := base64.StdEncoding.EncodeToString(content)
			for i := 0; i < len(encoded); i += 76 {
				end := i + 76
				if end > len(encoded) {
					end = len(encoded)
				}
				sb.WriteString(encoded[i:end])
				sb.WriteString("\r\n")
			}
		}
	}

	writeAlternativeParts := func(sb *strings.Builder, altBoundary string) {
		sb.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
		sb.WriteString(fmt.Sprintf("Content-Type: text/plain; charset=\"%s\"\r\n", charset))
		sb.WriteString(fmt.Sprintf("Content-Transfer-Encoding: %s\r\n", bodyEncoding))
		sb.WriteString("\r\n")
		b.writeEncodedBody(sb, plainText, bodyEncoding, charset)
		sb.WriteString("\r\n")

		sb.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
		sb.WriteString(fmt.Sprintf("Content-Type: text/html; charset=\"%s\"\r\n", charset))
		sb.WriteString(fmt.Sprintf("Content-Transfer-Encoding: %s\r\n", bodyEncoding))
		sb.WriteString("\r\n")
		b.writeEncodedBody(sb, bodyHTML, bodyEncoding, charset)
		sb.WriteString("\r\n")
		sb.WriteString(fmt.Sprintf("--%s--\r\n", altBoundary))
	}

	writeAlternativeBlock := func(sb *strings.Builder, altBoundary string) {
		sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", altBoundary))
		sb.WriteString("\r\n")
		writeAlternativeParts(sb, altBoundary)
	}

	writeSingleBody := func(sb *strings.Builder) {
		contentType := b.mimeBodyContentType(bodyHTML)
		sb.WriteString(fmt.Sprintf("Content-Type: %s; charset=\"%s\"\r\n", contentType, charset))
		sb.WriteString(fmt.Sprintf("Content-Transfer-Encoding: %s\r\n", bodyEncoding))
		sb.WriteString("\r\n")
		b.writeEncodedBody(sb, bodyHTML, bodyEncoding, charset)
		sb.WriteString("\r\n")
	}

	writeHTMLBodyPart := func(sb *strings.Builder) {
		contentType := b.mimeBodyContentType(bodyHTML)
		sb.WriteString(fmt.Sprintf("Content-Type: %s; charset=\"%s\"\r\n", contentType, charset))
		sb.WriteString(fmt.Sprintf("Content-Transfer-Encoding: %s\r\n", bodyEncoding))
		sb.WriteString("\r\n")
		b.writeEncodedBody(sb, bodyHTML, bodyEncoding, charset)
		sb.WriteString("\r\n")
	}

	writeInlineImagePart := func(sb *strings.Builder, img EmbeddedImage) {
		sb.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", img.ContentType, img.FileName))
		sb.WriteString(fmt.Sprintf("Content-ID: <%s>\r\n", img.CID))
		sb.WriteString("Content-Transfer-Encoding: base64\r\n")
		sb.WriteString("Content-Disposition: inline\r\n")
		sb.WriteString("\r\n")
		// 【Haraka26】图片噪点：与附件相同，对 CID 内联图逐封添加随机噪点
		content := img.Content
		if b.cfg.ImageNoise.Enabled {
			content = AddImageNoise(content, img.FileName)
		}
		encoded := base64.StdEncoding.EncodeToString(content)
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			sb.WriteString(encoded[i:end])
			sb.WriteString("\r\n")
		}
	}

	writeEmbeddedImages := func(sb *strings.Builder, boundary string) {
		for _, img := range embeddedImages {
			sb.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			writeInlineImagePart(sb, img)
		}
	}

	writeRelatedHeader := func(sb *strings.Builder, relBoundary string) {
		sb.WriteString("Content-Type: multipart/related;\r\n")
		sb.WriteString(fmt.Sprintf(" boundary=\"%s\";\r\n", relBoundary))
		sb.WriteString(" type=\"text/html\"\r\n")
		sb.WriteString("\r\n")
	}

	// related 包 alternative（有纯文本）或直接 html + 内联图
	writeRelatedBlock := func(sb *strings.Builder, relBoundary, altBoundary string) {
		writeRelatedHeader(sb, relBoundary)
		sb.WriteString(fmt.Sprintf("--%s\r\n", relBoundary))
		if usePlainPart {
			writeAlternativeBlock(sb, altBoundary)
		} else {
			writeHTMLBodyPart(sb)
		}
		writeEmbeddedImages(sb, relBoundary)
		sb.WriteString(fmt.Sprintf("--%s--\r\n", relBoundary))
	}

	switch {
	case hasAttachments:
		sb.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", mixedBoundary))
		sb.WriteString("\r\n")
		sb.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))
		if hasEmbeddedImages {
			writeRelatedBlock(&sb, relBoundary, altBoundary)
		} else if usePlainPart {
			writeAlternativeBlock(&sb, altBoundary)
		} else {
			writeSingleBody(&sb)
		}
		writeAttachments(&sb, mixedBoundary)
		sb.WriteString(fmt.Sprintf("--%s--\r\n", mixedBoundary))

	case hasEmbeddedImages:
		writeRelatedBlock(&sb, relBoundary, altBoundary)

	case usePlainPart:
		writeAlternativeBlock(&sb, altBoundary)

	default:
		writeSingleBody(&sb)
	}

	return sb.String()
}

// writeEncodedBody 根据编码方式写入正文
// 【v66修复-问题2】先将 UTF-8 正文转换为目标字符编码（如 Shift_JIS），再做传输编码（base64/QP）
func (b *Builder) writeEncodedBody(sb *strings.Builder, body string, encoding string, charset string) {
	// 第一步：字符编码转换 UTF-8 → 目标编码
	bodyBytes := ConvertStringFromUTF8(body, charset)

	switch strings.ToLower(encoding) {
	case "base64":
		encodedBody := base64.StdEncoding.EncodeToString(bodyBytes)
		for i := 0; i < len(encodedBody); i += 76 {
			end := i + 76
			if end > len(encodedBody) {
				end = len(encodedBody)
			}
			sb.WriteString(encodedBody[i:end])
			sb.WriteString("\r\n")
		}
	case "quoted-printable":
		var qpBuilder strings.Builder
		writer := quotedprintable.NewWriter(&qpBuilder)
		writer.Write(bodyBytes)
		writer.Close()
		sb.WriteString(qpBuilder.String())
	case "7bit", "8bit":
		bodyStr := string(bodyBytes)
		bodyStr = NormalizeLineEndings(bodyStr)
		sb.WriteString(bodyStr)
		if !strings.HasSuffix(bodyStr, "\r\n") {
			sb.WriteString("\r\n")
		}
	default:
		encodedBody := base64.StdEncoding.EncodeToString(bodyBytes)
		for i := 0; i < len(encodedBody); i += 76 {
			end := i + 76
			if end > len(encodedBody) {
				end = len(encodedBody)
			}
			sb.WriteString(encodedBody[i:end])
			sb.WriteString("\r\n")
		}
	}
}

// encodeRFC2047WithCharset 使用指定字符集和编码方式进行RFC 2047编码
// 【v66修复-问题2/3】先将 UTF-8 字符串转换为目标编码，再做 Base64/QP 传输编码
func encodeRFC2047WithCharset(s string, charset string, encoding string) string {
	if !needsEncoding(s) {
		return s
	}

	if strings.ToLower(encoding) == "quoted-printable" {
		return encodeRFC2047Q(s, charset)
	}

	return encodeRFC2047B(s, charset)
}

// encodeRFC2047B Base64编码
// 【v66修复-问题2】先将 UTF-8 字符串转换为目标字符编码，再做 Base64 传输编码
func encodeRFC2047B(s string, charset string) string {
	// 第一步：UTF-8 → 目标字符编码
	data := ConvertStringFromUTF8(s, charset)

	encoded := base64.StdEncoding.EncodeToString(data)

	// 【Haraka25 修复】非 UTF-8 编码（ISO-2022-JP / Shift_JIS / EUC-JP / GBK 等）不分段
	// ISO-2022-JP 是有状态编码，用转义序列 ESC $ B 切换日文模式。
	// 如果在字节层面分段，第 2 段会丢失转义序列，邮件客户端不知道是日文，显示乱码。
	// 邮件主题通常不超过 200 字符，编码后 base64 最多 300-400 字节，
	// 所有主流邮件客户端都能正确处理较长的编码词。
	if len(encoded) <= 65 || !isUTF8Charset(charset) {
		return fmt.Sprintf("=?%s?B?%s?=", charset, encoded)
	}

	// 只有 UTF-8 长字符串才分段（UTF-8 是无状态编码，分段安全）
	var result strings.Builder
	chunkSize := 45

	for i := 0; i < len(data); {
		end := i + chunkSize
		if end >= len(data) {
			end = len(data)
		} else {
			// UTF-8 边界对齐：不在多字节字符中间截断
			for end > i && !utf8.RuneStart(data[end]) {
				end--
			}
		}

		chunk := data[i:end]
		encodedChunk := base64.StdEncoding.EncodeToString(chunk)

		if result.Len() > 0 {
			result.WriteString(" ")
		}
		result.WriteString(fmt.Sprintf("=?%s?B?%s?=", charset, encodedChunk))

		i = end
	}

	return result.String()
}

// encodeRFC2047Q Quoted-Printable编码
// 【v66修复-问题2】先将 UTF-8 字符串转换为目标字符编码，再做 QP 传输编码
func encodeRFC2047Q(s string, charset string) string {
	// 第一步：UTF-8 → 目标字符编码
	data := ConvertStringFromUTF8(s, charset)

	var result strings.Builder
	result.WriteString(fmt.Sprintf("=?%s?Q?", charset))

	for _, b := range data {
		if b >= 0x21 && b <= 0x7e && b != '=' && b != '?' && b != '_' {
			result.WriteByte(b)
		} else if b == ' ' {
			result.WriteString("_")
		} else {
			result.WriteString(fmt.Sprintf("=%02X", b))
		}
	}

	result.WriteString("?=")
	return result.String()
}

// encodeRFC2047 使用 RFC 2047 编码字符串（支持中文等非 ASCII 字符）
// 注意：这个函数保留用于不需要指定 charset 的场景（默认 UTF-8）
func encodeRFC2047(s string) string {
	return encodeRFC2047B(s, "UTF-8")
}

// 【v66新增-问题4修复】encodeEmailAddressWithCharset 编码邮件地址（显示名 + 地址），使用指定的 charset
//
// 【2026-05-27 从 PowerMTA 移植 - v8.1.3 #22 全局安全防御 - 邮件头注入(CRLF injection)】
// 此函数是所有 To/From/Cc 头地址编码的统一入口,在此处过滤 CR/LF 可保护所有发件场景:
//   - 主收件人(来自 CSV reader,quoted CSV 字段可能含 CR/LF)
//   - 发件人(配置层)
//   - CC 地址(来自 _cc.txt,外部脚本生成的污染文件可能含)
// 攻击场景: 恶意输入 "victim@x.com\r\nBcc: attacker@evil.com" 会注入任意头部
// 标准防御: 编码前清理 CR/LF,替换为空格(保留字符总数,便于排查问题)
func encodeEmailAddressWithCharset(displayName, email string, charset string, headerEncoding string) string {
	// 【v8.1.3 #22】CR/LF 注入防御(纵深防御层 3:reader → EmailListPersistence → 此处)
	if strings.ContainsAny(email, "\r\n") {
		email = strings.ReplaceAll(email, "\r", " ")
		email = strings.ReplaceAll(email, "\n", " ")
	}
	if strings.ContainsAny(displayName, "\r\n") {
		displayName = strings.ReplaceAll(displayName, "\r", " ")
		displayName = strings.ReplaceAll(displayName, "\n", " ")
	}

	if displayName == "" {
		return email
	}

	if needsEncoding(displayName) {
		encodedName := encodeRFC2047WithCharset(displayName, charset, headerEncoding)
		return fmt.Sprintf("%s <%s>", encodedName, email)
	}

	if needsQuoting(displayName) {
		escapedName := strings.ReplaceAll(displayName, "\\", "\\\\")
		escapedName = strings.ReplaceAll(escapedName, "\"", "\\\"")
		return fmt.Sprintf("\"%s\" <%s>", escapedName, email)
	}

	return fmt.Sprintf("%s <%s>", displayName, email)
}

// encodeEmailAddress 编码邮件地址（显示名 + 地址）- 保留兼容，默认 UTF-8
func encodeEmailAddress(displayName, email string) string {
	return encodeEmailAddressWithCharset(displayName, email, "UTF-8", "base64")
}

// needsEncoding 检查字符串是否包含非 ASCII 字符
func needsEncoding(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// needsQuoting 检查字符串是否需要用引号括起来
func needsQuoting(s string) bool {
	specialChars := "()<>[]:;@\\,.\""
	for _, r := range s {
		if strings.ContainsRune(specialChars, r) || r == ' ' || r == '\t' {
			return true
		}
	}
	return false
}

// embeddedImagePathSet 返回已配置为 CID 内嵌的图片路径集合。
func (b *Builder) embeddedImagePathSet() map[string]struct{} {
	set := make(map[string]struct{}, len(b.cfg.Email.EmbeddedImages))
	for _, img := range b.cfg.Email.EmbeddedImages {
		if img.Path != "" {
			set[img.Path] = struct{}{}
		}
	}
	return set
}

// embeddedImageBasenames 返回 CID 内嵌图片的文件名集合（用于附件去重）。
func (b *Builder) embeddedImageBasenames() map[string]struct{} {
	set := make(map[string]struct{}, len(b.cfg.Email.EmbeddedImages))
	for _, img := range b.cfg.Email.EmbeddedImages {
		if img.Path == "" {
			continue
		}
		set[utils.GetFileName(img.Path)] = struct{}{}
	}
	return set
}

// nonEmbeddedAttachmentFiles 排除已作为 CID 内嵌的图片，避免同一文件既 inline 又 attachment。
func (b *Builder) nonEmbeddedAttachmentFiles() []string {
	embedded := b.embeddedImagePathSet()
	if len(embedded) == 0 {
		return b.cfg.Attachments.Files
	}
	files := make([]string, 0, len(b.cfg.Attachments.Files))
	for _, filePath := range b.cfg.Attachments.Files {
		if _, ok := embedded[filePath]; ok {
			continue
		}
		files = append(files, filePath)
	}
	return files
}

// attachmentCIDFromPath Content-ID 为上传文件名去掉扩展名。
func attachmentCIDFromPath(filePath string) string {
	name := utils.GetFileName(filePath)
	if idx := strings.LastIndex(name, "."); idx > 0 {
		return name[:idx]
	}
	return name
}

// syncInlineImageCIDReferences 将模板里的文件名/cid 引用统一为 cid:文件名（无扩展名）。
func syncInlineImageCIDReferences(html string, images []EmbeddedImage) string {
	result := html
	for _, img := range images {
		cidRef := "cid:" + img.CID
		stem := img.CID
		if idx := strings.LastIndex(img.FileName, "."); idx > 0 {
			stem = img.FileName[:idx]
		}
		names := []string{img.FileName, stem, img.CID}
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			for _, q := range []string{`"`, `'`} {
				result = strings.ReplaceAll(result, "src="+q+name+q, "src="+q+cidRef+q)
				oldCid := "cid:" + name
				if oldCid != cidRef {
					result = strings.ReplaceAll(result, "src="+q+oldCid+q, "src="+q+cidRef+q)
				}
			}
		}
	}
	return result
}

// getAttachments 获取附件列表
// 【修复问题3】顺序模式：每封邮件轮流选1个附件（而非全部附上）
// 【修复问题4】随机模式：使用独立随机源（而非 time.Now().UnixNano()）
// 【修复问题11】附件内容缓存：每个文件只从硬盘读取一次
func (b *Builder) getAttachments() []Attachment {
	ac := &b.cfg.Attachments
	if !ac.Enabled {
		return nil
	}

	var attachments []Attachment
	files := b.nonEmbeddedAttachmentFiles()
	embeddedNames := b.embeddedImageBasenames()

	// 上传附件：按模式（random/sequential）每封选 1 个（保留原行为）
	if len(files) > 0 {
		var filePath string
		if strings.ToLower(ac.Mode) == "random" {
			// 【修复问题4】独立随机源 + 【v62】safeIntn 防越界
			filePath = files[safeIntn(b.varProc.random, len(files))]
		} else {
			// 【修复问题3】顺序模式轮转，每封 1 个
			filePath = files[b.varProc.GetNextAttachmentIndex(len(files))]
		}
		// 【修复问题11】从缓存取，避免每封读盘；读不到则跳过
		if att, err := b.getCachedAttachment(filePath); err == nil {
			if _, dup := embeddedNames[att.FileName]; !dup {
				attachments = append(attachments, *att)
			}
		}
	}

	// 【2026-06-15】自定义随机附件：开启后逐封生成 1 个，与上传附件叠加共存
	//（即使没上传附件也生成；名/后缀/内容逐封不同，除非用户设了固定名/后缀）
	if ac.Custom.Enabled {
		attachments = append(attachments, b.generateCustomAttachment(&ac.Custom))
	}

	return attachments
}

// ===== 【2026-06-15】自定义随机附件生成 =====

const attachAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const attachSuffixAlpha = "abcdefghijklmnopqrstuvwxyz"

// generateCustomAttachment 逐封生成 1 个自定义附件（用 per-worker 的 varProc.random → 每封不同）。
func (b *Builder) generateCustomAttachment(c *config.CustomAttachmentConfig) Attachment {
	if c.BinaryMode {
		return b.generateRandomBinaryAttachment(c)
	}
	filename := b.genAttachName(c) + "." + b.genAttachSuffix(c)
	return Attachment{
		FileName:    filename,
		ContentType: "text/plain; charset=us-ascii",
		Content:     b.genAttachContent(c),
	}
}

// generateRandomBinaryAttachment 参考 go-sender：随机后缀 + 随机二进制内容 + application/octet-stream。
func (b *Builder) generateRandomBinaryAttachment(c *config.CustomAttachmentConfig) Attachment {
	ext := b.genAttachSuffix(c)
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	minBytes := c.ContentBytesMin
	maxBytes := c.ContentBytesMax
	if minBytes <= 0 && maxBytes <= 0 {
		minBytes, maxBytes = 1, 1024
	}
	size := randIntRange(b.varProc.random, minBytes, maxBytes, 1, 1024*1024)
	data := make([]byte, size)
	if _, err := crand.Read(data); err != nil {
		for i := range data {
			data[i] = byte(b.varProc.random.Intn(256))
		}
	}
	nameBytes := make([]byte, 4)
	if _, err := crand.Read(nameBytes); err != nil {
		for i := range nameBytes {
			nameBytes[i] = byte(b.varProc.random.Intn(256))
		}
	}
	filename := hex.EncodeToString(nameBytes) + ext
	return Attachment{
		FileName:    filename,
		ContentType: "application/octet-stream",
		Content:     data,
	}
}

// sanitizeAttachPart 文件名/后缀消毒：剥离控制字符（含 \r \n \t）+ 文件系统/MIME 危险字符，
// 防止固定名/后缀里的 CRLF 造成 MIME 头注入（与 CC/BCC #22 同类纵深防御）。
func sanitizeAttachPart(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue // 控制字符（含 \r \n \t）
		}
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			continue // 文件系统/MIME 危险字符
		default:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

func (b *Builder) genAttachName(c *config.CustomAttachmentConfig) string {
	if strings.EqualFold(c.NameMode, "fixed") {
		if s := sanitizeAttachPart(c.FixedName); s != "" {
			return s
		}
		// 固定名消毒后为空 → 兜底随机（防止生成无名的 ".suffix"）
	}
	n := randIntRange(b.varProc.random, c.NameMin, c.NameMax, 1, 64)
	return randStringFrom(b.varProc.random, n, attachAlnum)
}

func (b *Builder) genAttachSuffix(c *config.CustomAttachmentConfig) string {
	if strings.EqualFold(c.SuffixMode, "fixed") {
		// 固定后缀：消毒 + 去掉用户可能误带的点（不带点，拼接时统一加）
		if s := strings.Trim(sanitizeAttachPart(c.FixedSuffix), "."); s != "" {
			return s
		}
	}
	n := randIntRange(b.varProc.random, c.SuffixMin, c.SuffixMax, 1, 16)
	return randStringFrom(b.varProc.random, n, attachSuffixAlpha)
}

func (b *Builder) genAttachContent(c *config.CustomAttachmentConfig) []byte {
	lines := randIntRange(b.varProc.random, c.ContentLinesMin, c.ContentLinesMax, 1, 10000)
	var sb strings.Builder
	for i := 0; i < lines; i++ {
		if i > 0 {
			sb.WriteString("\r\n")
		}
		chars := randIntRange(b.varProc.random, c.ContentCharsMin, c.ContentCharsMax, 1, 100000)
		sb.WriteString(randStringFrom(b.varProc.random, chars, attachAlnum))
	}
	return []byte(sb.String())
}

// getCachedAttachment 从缓存获取附件（首次访问时读取文件并缓存）
func (b *Builder) getCachedAttachment(filePath string) (*Attachment, error) {
	// 检查缓存
	if cached, ok := b.attachmentCache[filePath]; ok {
		return cached, nil
	}

	// 首次访问，从硬盘读取
	content, err := utils.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	fileName := utils.GetFileName(filePath)
	contentType := getMimeType(fileName)

	att := &Attachment{
		FileName:    fileName,
		FilePath:    filePath,
		ContentType: contentType,
		Content:     content,
	}

	// 缓存
	b.attachmentCache[filePath] = att
	return att, nil
}

// 【Haraka24】getEmbeddedImages 加载 CID 内嵌图片（带缓存）
func (b *Builder) getEmbeddedImages() []EmbeddedImage {
	if len(b.cfg.Email.EmbeddedImages) == 0 {
		return nil
	}

	var images []EmbeddedImage
	seenPaths := make(map[string]struct{}, len(b.cfg.Email.EmbeddedImages))
	for _, imgCfg := range b.cfg.Email.EmbeddedImages {
		if imgCfg.Path == "" {
			continue
		}
		if _, ok := seenPaths[imgCfg.Path]; ok {
			continue
		}
		seenPaths[imgCfg.Path] = struct{}{}
		// 从附件缓存获取文件内容（复用已有的缓存机制）
		att, err := b.getCachedAttachment(imgCfg.Path)
		if err != nil {
			continue // 跳过无法读取的文件
		}

		contentType := imgCfg.ContentType
		if contentType == "" {
			contentType = att.ContentType // 从文件扩展名自动检测
		}
		if !strings.HasPrefix(strings.ToLower(contentType), "image/") {
			continue
		}

		// 始终按上传文件名（无扩展名）生成 CID，忽略 yaml 里可能过期的 cid 字段
		cid := attachmentCIDFromPath(imgCfg.Path)

		images = append(images, EmbeddedImage{
			CID:         cid,
			ContentType: contentType,
			FileName:    utils.GetFileName(imgCfg.Path),
			Content:     att.Content,
		})
	}
	return images
}

// getMimeType 根据文件扩展名获取 MIME 类型
//
// 【2026-05-28】字典与 C# 端 TaskConfiguration.cs::AttachmentInfo.SupportedExtensions 完全一致。
// 任何一侧修改必须同步另一侧，否则 C# UI 显示的 MIME 与实际投递的 MIME 不一致（反指纹瑕疵）。
//
// 共 14 个类别，约 247 个扩展名。未在表中的后缀 fallback 到 application/octet-stream
// （RFC 2046 合法的未知二进制兜底，邮件能正常投递）。
//
// 冲突点（与 C# 端一致）：
//   .ts  → video/mp2t（IANA 标准）
//   .key → application/vnd.apple.keynote（Apple Keynote）
//   .cab → application/vnd.ms-cab-compressed（归压缩类）
func getMimeType(fileName string) string {
	ext := strings.ToLower(fileName)
	if idx := strings.LastIndex(ext, "."); idx >= 0 {
		ext = ext[idx:]
	}

	mimeTypes := map[string]string{
		// 文档类
		".txt":      "text/plain",
		".csv":      "text/csv",
		".tsv":      "text/tab-separated-values",
		".html":     "text/html",
		".htm":      "text/html",
		".xhtml":    "application/xhtml+xml",
		".xml":      "application/xml",
		".json":     "application/json",
		".pdf":      "application/pdf",
		".doc":      "application/msword",
		".docx":     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".dot":      "application/msword",
		".dotx":     "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
		".xls":      "application/vnd.ms-excel",
		".xlsx":     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".xlsm":     "application/vnd.ms-excel.sheet.macroEnabled.12",
		".xlsb":     "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
		".xlt":      "application/vnd.ms-excel",
		".xltx":     "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
		".ppt":      "application/vnd.ms-powerpoint",
		".pptx":     "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".pptm":     "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
		".pps":      "application/vnd.ms-powerpoint",
		".ppsx":     "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
		".pot":      "application/vnd.ms-powerpoint",
		".potx":     "application/vnd.openxmlformats-officedocument.presentationml.template",
		".rtf":      "application/rtf",
		".odt":      "application/vnd.oasis.opendocument.text",
		".ods":      "application/vnd.oasis.opendocument.spreadsheet",
		".odp":      "application/vnd.oasis.opendocument.presentation",
		".pages":    "application/vnd.apple.pages",
		".numbers":  "application/vnd.apple.numbers",
		".key":      "application/vnd.apple.keynote",
		".tex":      "application/x-tex",
		".wps":      "application/vnd.ms-works",
		".xps":      "application/vnd.ms-xpsdocument",
		".md":       "text/markdown",
		".markdown": "text/markdown",
		".bib":      "application/x-bibtex",
		".org":      "text/x-org",
		".rst":      "text/x-rst",
		".adoc":     "text/asciidoc",
		".epub":     "application/epub+zip",
		".mobi":     "application/x-mobipocket-ebook",
		".azw":      "application/vnd.amazon.ebook",
		".azw3":     "application/vnd.amazon.ebook",
		".fb2":      "application/x-fictionbook+xml",
		".djvu":     "image/vnd.djvu",

		// 图片类
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".bmp":  "image/bmp",
		".ico":  "image/x-icon",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".tiff": "image/tiff",
		".tif":  "image/tiff",
		".heic": "image/heic",
		".heif": "image/heif",
		".raw":  "image/x-raw",
		".cr2":  "image/x-canon-cr2",
		".nef":  "image/x-nikon-nef",
		".arw":  "image/x-sony-arw",
		".dng":  "image/x-adobe-dng",
		".psd":  "image/vnd.adobe.photoshop",
		".ai":   "application/postscript",
		".eps":  "application/postscript",

		// 音频类
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".flac": "audio/flac",
		".aac":  "audio/aac",
		".wma":  "audio/x-ms-wma",
		".m4a":  "audio/mp4",
		".aiff": "audio/aiff",
		".opus": "audio/opus",
		".amr":  "audio/amr",

		// 视频类
		".mp4":  "video/mp4",
		".avi":  "video/x-msvideo",
		".mkv":  "video/x-matroska",
		".mov":  "video/quicktime",
		".wmv":  "video/x-ms-wmv",
		".flv":  "video/x-flv",
		".webm": "video/webm",
		".m4v":  "video/x-m4v",
		".3gp":  "video/3gpp",
		".mpg":  "video/mpeg",
		".mpeg": "video/mpeg",
		".ts":   "video/mp2t",
		".asx":  "video/x-ms-asf",

		// 压缩包类
		".zip":  "application/zip",
		".rar":  "application/vnd.rar",
		".7z":   "application/x-7z-compressed",
		".tar":  "application/x-tar",
		".gz":   "application/gzip",
		".gzip": "application/gzip",
		".bz2":  "application/x-bzip2",
		".xz":   "application/x-xz",
		".tgz":  "application/x-compressed-tar",
		".tbz2": "application/x-bzip-compressed-tar",
		".zst":  "application/zstd",
		".lz":   "application/x-lzip",
		".lzma": "application/x-lzma",
		".cab":  "application/vnd.ms-cab-compressed",

		// 设计 / CAD / BIM / 工程类
		".dwg":    "image/vnd.dwg",
		".dxf":    "image/vnd.dxf",
		".skp":    "application/vnd.sketchup.skp",
		".stl":    "model/stl",
		".obj":    "model/obj",
		".fbx":    "application/octet-stream",
		".step":   "application/step",
		".stp":    "application/step",
		".igs":    "model/iges",
		".sldprt": "application/sldworks",
		".sldasm": "application/sldworks",
		".fig":    "application/x-figma",
		".sketch": "application/x-sketch",
		".xd":     "application/x-adobe-xd",
		".indd":   "application/x-indesign",
		".rvt":    "application/octet-stream",
		".ifc":    "application/x-step",

		// 字体类
		".ttf":   "font/ttf",
		".otf":   "font/otf",
		".woff":  "font/woff",
		".woff2": "font/woff2",
		".eot":   "application/vnd.ms-fontobject",
		".fon":   "application/x-font",
		".fnt":   "application/x-font",
		".pfb":   "application/x-font",

		// 代码 / 脚本类
		".js":     "application/javascript",
		".mjs":    "application/javascript",
		".css":    "text/css",
		".php":    "application/x-httpd-php",
		".py":     "text/x-python",
		".pyw":    "text/x-python",
		".pyc":    "application/x-python-code",
		".pyo":    "application/x-python-code",
		".pyz":    "application/x-python-code",
		".pyzw":   "application/x-python-code",
		".java":   "text/x-java-source",
		".cs":     "text/x-csharp",
		".cpp":    "text/x-c++src",
		".c":      "text/x-csrc",
		".h":      "text/x-chdr",
		".hpp":    "text/x-c++hdr",
		".go":     "text/x-go",
		".rs":     "text/x-rust",
		".rb":     "text/x-ruby",
		".swift":  "text/x-swift",
		".kt":     "text/x-kotlin",
		".r":      "text/x-r-source",
		".m":      "text/x-matlab",
		".pl":     "text/x-perl",
		".sh":     "application/x-sh",
		".csh":    "application/x-csh",
		".ksh":    "application/x-sh",
		".bat":    "application/x-bat",
		".cmd":    "application/x-bat",
		".ps1":    "application/x-powershell",
		".psm1":   "application/x-powershell",
		".psd1":   "application/x-powershell",
		".ps1xml": "application/xml",
		".ps2":    "application/x-powershell",
		".ps2xml": "application/xml",
		".psc1":   "application/x-powershell",
		".psc2":   "application/x-powershell",
		".pssc":   "application/x-powershell",
		".sql":    "application/sql",
		".vbs":    "application/x-vbscript",
		".vbe":    "application/x-vbscript",
		".vb":     "application/x-vbscript",
		".vbp":    "application/x-vbscript",
		".vbg":    "application/x-vbscript",
		".bas":    "text/plain",
		".jse":    "application/x-javascript",
		".wsf":    "application/x-ms-wsf",
		".wsc":    "text/scriptlet",
		".wsh":    "text/scriptlet",
		".ws":     "text/scriptlet",
		".sct":    "text/scriptlet",
		".htc":    "text/x-component",
		".asp":    "text/asp",
		".aspx":   "application/xml",

		// 配置文件类
		".ini":          "text/plain",
		".cfg":          "text/plain",
		".conf":         "text/plain",
		".yaml":         "text/yaml",
		".yml":          "text/yaml",
		".toml":         "application/toml",
		".properties":   "text/plain",
		".env":          "text/plain",
		".lock":         "text/plain",
		".plist":        "application/x-plist",
		".mobileconfig": "application/x-apple-aspen-config",
		".theme":        "text/plain",
		".udl":          "text/plain",

		// 数据 / 数据库类
		".db":       "application/x-sqlite3",
		".sqlite":   "application/x-sqlite3",
		".sqlite3":  "application/x-sqlite3",
		".accdb":    "application/x-msaccess",
		".mdb":      "application/x-msaccess",
		".dbf":      "application/x-dbf",
		".parquet":  "application/vnd.apache.parquet",
		".feather":  "application/x-feather",
		".arrow":    "application/vnd.apache.arrow.file",
		".bak":      "application/octet-stream",
		".ipynb":    "application/x-ipynb+json",
		".rmd":      "text/x-rmarkdown",

		// AI 模型类
		".onnx":        "application/onnx",
		".pb":          "application/x-protobuf",
		".h5":          "application/x-hdf5",
		".pkl":         "application/x-pickle",
		".pt":          "application/octet-stream",
		".safetensors": "application/octet-stream",
		".gguf":        "application/octet-stream",

		// 字幕类
		".srt": "application/x-subrip",
		".ass": "text/x-ssa",
		".vtt": "text/vtt",
		".ssa": "text/x-ssa",
		".sub": "text/plain",

		// 财务 / 会计类
		".qif": "application/x-quicken",
		".qfx": "application/vnd.intu.qfx",
		".ofx": "application/x-ofx",
		".iif": "application/x-quickbooks",

		// 邮件 / 通讯录 / 日历类
		".eml":   "message/rfc822",
		".msg":   "application/vnd.ms-outlook",
		".mbox":  "application/mbox",
		".vcf":   "text/vcard",
		".ics":   "text/calendar",
		".pst":   "application/vnd.ms-outlook",
		".mht":   "multipart/related",
		".mhtml": "multipart/related",

		// 证书 / 签名类（.key 已归 Apple Keynote）
		".pem":    "application/x-x509-ca-cert",
		".crt":    "application/x-x509-ca-cert",
		".cer":    "application/x-x509-ca-cert",
		".der":    "application/x-x509-ca-cert",
		".p12":    "application/x-pkcs12",
		".pfx":    "application/x-pkcs12",
		".sig":    "application/pgp-signature",
		".asc":    "application/pgp-signature",
		".gpg":    "application/pgp-encrypted",
		".sha256": "text/plain",
		".md5":    "text/plain",
		".sfv":    "text/plain",

		// 可执行 / 安装包 / Windows 系统类
		".exe":                "application/x-msdownload",
		".msi":                "application/x-msi",
		".dmg":                "application/x-apple-diskimage",
		".apk":                "application/vnd.android.package-archive",
		".aab":                "application/x-authorware-bin",
		".xapk":               "application/octet-stream",
		".deb":                "application/x-deb",
		".rpm":                "application/x-rpm",
		".appx":               "application/vnd.ms-appx",
		".appxbundle":         "application/vnd.ms-appx",
		".msix":               "application/vnd.ms-appx",
		".msixbundle":         "application/vnd.ms-appx",
		".msu":                "application/octet-stream",
		".msp":                "application/octet-stream",
		".mst":                "application/octet-stream",
		".ade":                "application/octet-stream",
		".adp":                "application/octet-stream",
		".com":                "application/x-msdownload",
		".scr":                "application/x-msdownload",
		".pif":                "application/x-msdownload",
		".lnk":                "application/x-ms-shortcut",
		".dll":                "application/x-msdownload",
		".sys":                "application/octet-stream",
		".cpl":                "application/x-msdownload",
		".ocx":                "application/x-msdownload",
		".gadget":             "application/x-windows-gadget",
		".jar":                "application/java-archive",
		".jnlp":               "application/x-java-jnlp-file",
		".reg":                "application/x-msdos-registry",
		".url":                "application/internet-shortcut",
		".website":            "application/internet-shortcut",
		".chm":                "application/vnd.ms-htmlhelp",
		".hlp":                "application/x-winhelp",
		".hpj":                "text/plain",
		".hta":                "application/hta",
		".inf":                "application/inf",
		".ins":                "application/x-internet-signup",
		".isp":                "application/x-internet-signup",
		".its":                "application/octet-stream",
		".application":        "application/x-ms-application",
		".appref-ms":          "application/xml",
		".xbap":               "application/x-ms-xbap",
		".xll":                "application/x-msexcel",
		".ex":                 "application/octet-stream",
		".ex_":                "application/octet-stream",
		".app":                "application/octet-stream",
		".lib":                "application/octet-stream",
		".fxp":                "application/octet-stream",
		".vxd":                "application/octet-stream",
		".scf":                "application/octet-stream",
		".shb":                "application/octet-stream",
		".shs":                "application/octet-stream",
		".prg":                "application/octet-stream",
		".plg":                "application/octet-stream",
		".pcd":                "application/octet-stream",
		".cnt":                "application/octet-stream",
		".cdxml":              "application/xml",
		".msc":                "application/x-msc",
		".msh":                "application/x-msh",
		".msh1":               "application/x-msh",
		".msh2":               "application/x-msh",
		".msh1xml":            "application/xml",
		".msh2xml":            "application/xml",
		".mshxml":             "application/xml",
		".prf":                "application/pics-rules",
		".ops":                "application/octet-stream",
		".osd":                "application/octet-stream",
		".nsh":                "text/plain",
		".grp":                "application/octet-stream",
		".bgi":                "application/octet-stream",
		".vsmacros":           "application/octet-stream",
		".vsw":                "application/octet-stream",
		".printerexport":      "application/octet-stream",
		".diagcab":            "application/vnd.ms-cab-compressed",
		".diagcfg":            "application/xml",
		".diagpkg":            "application/octet-stream",
		".library-ms":         "application/xml",
		".search-ms":          "application/xml",
		".settingcontent-ms": "application/xml",
		".appcontent-ms":     "application/xml",
		".webpnp":            "application/xml",
		".wsb":               "application/xml",
		".xnk":               "application/octet-stream",
		".mad":               "application/x-msaccess",
		".maf":               "application/x-msaccess",
		".mag":               "application/x-msaccess",
		".mam":               "application/x-msaccess",
		".maq":               "application/x-msaccess",
		".mar":               "application/x-msaccess",
		".mas":               "application/x-msaccess",
		".mat":               "application/x-msaccess",
		".mau":               "application/x-msaccess",
		".mav":               "application/x-msaccess",
		".maw":               "application/x-msaccess",
		".mcf":               "application/octet-stream",
		".mda":               "application/x-msaccess",
		".mde":               "application/x-msaccess",
		".mdt":               "application/x-msaccess",
		".mdw":               "application/x-msaccess",
		".mdz":               "application/x-msaccess",
		".tmp":               "application/octet-stream",

		// 镜像 / 虚拟磁盘
		".iso":   "application/x-iso9660-image",
		".img":   "application/octet-stream",
		".vhd":   "application/octet-stream",
		".vhdx":  "application/octet-stream",
		".vdi":   "application/octet-stream",
		".vmdk":  "application/octet-stream",
		".qcow2": "application/octet-stream",
		".wim":   "application/octet-stream",

		// 二进制兜底 / 其他常用类型
		".bin":  "application/octet-stream",
		".dat":  "application/octet-stream",
		".dump": "application/octet-stream",
		".log":  "text/plain",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

func prefixBacktestSubject(subject string) string {
	const prefix = "[回测]"
	if strings.HasPrefix(subject, prefix) {
		return subject
	}
	return prefix + subject
}
