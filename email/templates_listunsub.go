package email

// =============================================================================
// 【2026-05-27 从 PowerMTA 移植】50 个 List-Unsubscribe 模板模板（4 模式各自池的内置基础）
//
// 设计：
//   - 每个模板含变量占位符，运行时由 VariableProcessor 渲染
//   - {FROM_DOMAIN} 自动适配每台 Haraka 服务器（multi-tenant 友好）
//   - 长 URL（JWT 类）会被 RFC 5322 §2.2.3 折叠器自动断行
//
// 池被三种 ListUnsubMode 共用：
//   - real：真实退订模式（需配合 HTTP server 启动）
//   - custom：自定义模板（用户填的优先；池作为"自动生成"基础数据）
//   - random：随机风格池
//   default 模式不读这个池，直接用 <mailto:unsubscribe-{hex}@{domain}>
//
// 类别分布（50 条）：
//   - SendGrid 风格           5  (idx 0-4)
//   - Mailchimp 风格          4  (idx 5-8)
//   - Salesforce MC           3  (idx 9-11)
//   - Constant Contact        3  (idx 12-14)
//   - HubSpot                 3  (idx 15-17)
//   - Mailgun                 3  (idx 18-20)
//   - Amazon SES              3  (idx 21-23)
//   - Marketo                 3  (idx 24-26)
//   - Klaviyo                 3  (idx 27-29)
//   - IBM Watson / Pardot     3  (idx 30-32)
//   - 日本邮件商 vpass 风     3  (idx 33-35)
//   - 日本邮件商 biccamera 风 2  (idx 36-37)
//   - 通用 mailto + HTTPS     5  (idx 38-42)
//   - 通用 HTTPS only         4  (idx 43-46)
//   - 通用 mailto only        3  (idx 47-49)
//
// 总：5+4+3+3+3+3+3+3+3+3+3+2+5+4+3 = 50 ✓
//
// 约定：
//   - 每个模板必须以 "<" 开头、">" 结尾（RFC 2369 / RFC 8058 要求）
//   - 模板单行，渲染后由 foldHeaderValue 折叠（如果过长）
//   - 不含 "List-Unsubscribe: " 前缀（调用方拼接）
// =============================================================================

// listUnsubTemplatePool 50 个 List-Unsubscribe 模板
var listUnsubTemplatePool = []string{
	// ===== SendGrid 风格（5 个）=====
	"<https://u{ID_QUEUE:7}.ct.sendgrid.net/wf/unsubscribe?upn={JWT_TOKEN}>",
	"<https://u{ID_QUEUE:7}.ct.sendgrid.net/wf/unsubscribe?upn={JWT_TOKEN}>, <mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://email.{FROM_DOMAIN}/wf/unsubscribe?upn={JWT_TOKEN}>",
	"<mailto:unsubscribe@{FROM_DOMAIN}?subject=unsubscribe-{ID_HEX:16}>, <https://email.{FROM_DOMAIN}/wf/unsubscribe?upn={JWT_TOKEN}>",
	"<https://sendgrid.{FROM_DOMAIN}/asm/unsubscribe?u={ID_HEX:32}>",

	// ===== Mailchimp 风格（4 个）=====
	"<http://{FROM_DOMAIN}/unsubscribe?u={ID_HEX:32}&id={ID_HEX:10}>",
	"<http://{FROM_DOMAIN}/unsubscribe?u={ID_HEX:32}&id={ID_HEX:10}>, <mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://{FROM_DOMAIN}/mc/unsubscribe?u={ID_HEX:32}&id={ID_HEX:10}&e={ID_HEX:16}>",
	"<mailto:unsubscribe-mc.list-{ID_HEX:16}.{ID_HEX:16}@{FROM_DOMAIN}>",

	// ===== Salesforce Marketing Cloud / ExactTarget（3 个）=====
	"<https://cl.{FROM_DOMAIN}/subscription_center.aspx?qs={ID_HEX:64}>",
	"<https://cl.{FROM_DOMAIN}/subscription_center.aspx?qs={ID_HEX:64}>, <mailto:leave-{ID_BOUNCE_TOKEN}@{FROM_DOMAIN}>",
	"<https://email.{FROM_DOMAIN}/subscription_center?jwt={JWT_TOKEN}>",

	// ===== Constant Contact（3 个）=====
	"<https://visitor.r20.{FROM_DOMAIN}/manage/optout?v={JWT_TOKEN}>",
	"<https://visitor.r20.{FROM_DOMAIN}/manage/optout?v={JWT_TOKEN}>, <mailto:optout-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://r20.{FROM_DOMAIN}/d.jsp?llr={ID_HEX:16}&p=oo&m={ID_HEX:32}>",

	// ===== HubSpot（3 个）=====
	"<https://app.{FROM_DOMAIN}/email-unsubscribe?d={ID_HEX:64}>",
	"<https://app.{FROM_DOMAIN}/email-unsubscribe?d={ID_HEX:64}>, <mailto:unsubscribe-{ID_HEX:16}@reply.{FROM_DOMAIN}>",
	"<https://t.hsms{ID_QUEUE:2}.{FROM_DOMAIN}/c/unsubscribe?h={JWT_TOKEN}>",

	// ===== Mailgun（3 个）=====
	"<https://email.{FROM_DOMAIN}/u/eh/{ID_HEX:64}>",
	"<https://email.{FROM_DOMAIN}/u/eh/{ID_HEX:64}>, <mailto:unsubscribe-{ID_HEX:32}@{FROM_DOMAIN}>",
	"<mailto:unsubscribe+{ID_HEX:32}@mg.{FROM_DOMAIN}>, <https://email.{FROM_DOMAIN}/u/{ID_HEX:64}>",

	// ===== Amazon SES（3 个）=====
	"<https://{FROM_DOMAIN}/r/?id={JWT_TOKEN}&utype=u>",
	"<mailto:{ID_HEX:32}@unsubscribe.{FROM_DOMAIN}>",
	"<mailto:{ID_HEX:32}@unsubscribe.{FROM_DOMAIN}>, <https://{FROM_DOMAIN}/r/?id={JWT_TOKEN}&utype=u>",

	// ===== Marketo（3 个）=====
	"<https://email.{FROM_DOMAIN}/un.aspx?id={ID_HEX:16}&u={JWT_TOKEN}>",
	"<https://email.{FROM_DOMAIN}/un.aspx?id={ID_HEX:16}&u={JWT_TOKEN}>, <mailto:reply-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://go.{FROM_DOMAIN}/un.aspx?bid={ID_HEX:24}&cid={ID_HEX:16}>",

	// ===== Klaviyo（3 个）=====
	"<https://manage.kmail-lists.com/subscriptions/{ID_HEX:24}/list/{ID_HEX:10}>",
	"<https://manage.kmail-lists.com/subscriptions/{ID_HEX:24}/list/{ID_HEX:10}>, <mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://email.{FROM_DOMAIN}/email/unsubscribe?h={JWT_TOKEN}&p={ID_HEX:16}>",

	// ===== IBM Watson Campaign / Pardot（3 个）=====
	"<https://maillist.{FROM_DOMAIN}/u/{ID_HEX:32}-{ID_HEX:16}-{ID_HEX:16}-{ID_HEX:8}>",
	"<https://go.pardot.{FROM_DOMAIN}/e/{ID_HEX:32}/{ID_HEX:16}/{ID_HEX:24}>",
	"<https://email.{FROM_DOMAIN}/op.aspx?u={JWT_TOKEN}&token={ID_HEX:48}>",

	// ===== 日本邮件商 vpass / smbc 风格（3 个）=====
	"<https://{FROM_DOMAIN}/contact/mail-stop?id={ID_HEX:32}>, <mailto:leave-{ID_BOUNCE_TOKEN}@bounce.{FROM_DOMAIN}>",
	"<https://www.{FROM_DOMAIN}/cgi-bin/mail_stop?u={ID_HEX:24}&t={ID_HEX:16}>",
	"<mailto:unsubscribe-{ID_HEX:16}@bounce.contact.{FROM_DOMAIN}>",

	// ===== 日本邮件商 biccamera / ml 风格（2 个）=====
	"<https://www.{FROM_DOMAIN}/bin/mail_unsubscribe?bid={ID_HEX:16}&cid={ID_HEX:8}>",
	"<mailto:leave-{ID_BOUNCE_TOKEN}@bounce.ml.{FROM_DOMAIN}>, <https://ml.{FROM_DOMAIN}/u/{ID_HEX:32}>",

	// ===== 通用 mailto + HTTPS 复合（5 个）=====
	"<mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>, <https://{FROM_DOMAIN}/unsubscribe/{ID_HEX:48}>",
	"<mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>, <https://{FROM_DOMAIN}/mail-unsubscribe/{ID_HEX:64}>",
	"<https://{FROM_DOMAIN}/u/{ID_HEX:32}>, <mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<https://{FROM_DOMAIN}/subscription_center?jwt={JWT_TOKEN}>, <mailto:leave-{ID_BOUNCE_TOKEN}@{FROM_DOMAIN}>",
	"<mailto:unsub-{ID_HEX:32}@{FROM_DOMAIN}>, <https://{FROM_DOMAIN}/opt-out?token={JWT_TOKEN}>",

	// ===== 通用 HTTPS only（4 个）=====
	"<https://{FROM_DOMAIN}/mail-unsubscribe/{ID_HEX:64}>",
	"<https://{FROM_DOMAIN}/unsubscribe?u={ID_HEX:32}&h={ID_HEX:16}>",
	"<https://{FROM_DOMAIN}/list/unsubscribe?id={ID_HEX:24}>",
	"<https://{FROM_DOMAIN}/opt-out/{ID_HEX:32}>",

	// ===== 通用 mailto only（3 个）=====
	"<mailto:unsubscribe-{ID_HEX:16}@{FROM_DOMAIN}>",
	"<mailto:remove-{ID_HEX:24}@{FROM_DOMAIN}>",
	"<mailto:list-unsubscribe-{ID_HEX:32}@{FROM_DOMAIN}>",
}

// listUnsubTemplatePoolSize 池大小（启动时一次性计算）
var listUnsubTemplatePoolSize = len(listUnsubTemplatePool)
