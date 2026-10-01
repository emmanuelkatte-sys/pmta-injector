// Package config 定义 YAML 配置结构与加载逻辑。
//
// Config 聚合发件人、PMTA/SMTP、性能、模板、邮件头、CC/BCC、
// 退订服务器等全部运行时参数；由 C# 管理端生成或手工编辑。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	App         AppConfig         `yaml:"app"`
	MtaType     string            `yaml:"mta_type"` // "pmta" 或 "haraka"，控制邮件头行为
	Sender      SenderConfig      `yaml:"sender"`
	PMTA        PMTAConfig        `yaml:"pmta"`
	SMTP        SMTPConfig        `yaml:"smtp"`
	Performance PerformanceConfig `yaml:"performance"`
	Email       EmailConfig       `yaml:"email"`
	Attachments AttachmentsConfig `yaml:"attachments"`
	Recipients  RecipientsConfig  `yaml:"recipients"`
	Job         JobConfig         `yaml:"job"`
	Output      OutputConfig      `yaml:"output"`
	Logging     LoggingConfig     `yaml:"logging"`
	Template    TemplateConfig    `yaml:"template"`
	Encoding    EncodingConfig    `yaml:"encoding"`
	Variables   VariablesConfig   `yaml:"variables"`
	Headers     HeadersConfig     `yaml:"headers"`
	ZeroWidth   ZeroWidthConfig   `yaml:"zero_width"`    // 【Haraka26】零宽字符
	ReverseBidi ReverseBidiConfig `yaml:"reverse_bidi"`
	ImageNoise  ImageNoiseConfig  `yaml:"image_noise"`   // 【Haraka26】图片噪点
	HtmlMutator HtmlMutatorConfig `yaml:"html_mutator"`  // HTML 模板结构变异

	// 【2026-05-27 从 PowerMTA 移植】CC/BCC 三组对称设计
	Recipient   RecipientControlConfig `yaml:"recipient,omitempty"` // 收件人功能启用开关
	CC          CCConfig               `yaml:"cc,omitempty"`        // 抄送配置(独立邮件路径)
	BCC         BCCConfig              `yaml:"bcc,omitempty"`       // 密送配置(独立邮件路径)

	// 【2026-05-27 批次 4 从 PowerMTA 移植】退订 HTTP 服务器（仅 serve 子命令读取，send 子命令忽略）
	UnsubscribeServer UnsubscribeServerConfig `yaml:"unsubscribe_server,omitempty"`

	Backtest BacktestConfig `yaml:"backtest,omitempty"`
	Arc      ArcConfig      `yaml:"arc,omitempty"`
	ReceivedChain ReceivedChainConfig `yaml:"received_chain,omitempty"`

	DryRun      bool              `yaml:"-"`
}

// ArcConfig RFC 8617 ARC 密封（github.com/rest-mail/go-arc），复用 DKIM 私钥。
type ArcConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Domain         string `yaml:"domain"`
	Selector       string `yaml:"selector"`
	PrivateKeyPath string `yaml:"private_key_path"`
	PrivateKeyPEM  string `yaml:"private_key_pem,omitempty"`
}

type ReceivedChainConfig struct {
	Enabled          bool   `yaml:"enabled"`
	ChainType        string `yaml:"chain_type"`
	IPMode           string `yaml:"ip_mode"`
	IPPool           string `yaml:"ip_pool"`
	Hops             int    `yaml:"hops"`
	MTAFlavor        string `yaml:"mta_flavor"`
	DomainStyle      string `yaml:"domain_style"`
	CustomTemplate   string `yaml:"custom_template"`
	StripAuthResults bool   `yaml:"strip_auth_results"`
	StripReceived    bool   `yaml:"strip_received"`
	StripClientIP    bool   `yaml:"strip_client_ip"`
}

type BacktestConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Frequency int    `yaml:"frequency"`
	Email     string `yaml:"email"`
}

func (c *Config) BacktestActive() bool {
	if c == nil || !c.Backtest.Enabled || c.Backtest.Frequency < 1 {
		return false
	}
	email := strings.TrimSpace(c.Backtest.Email)
	return email != "" && strings.Contains(email, "@")
}

func (c *Config) ExpectedBacktestCount(mainCount int64) int64 {
	if !c.BacktestActive() || mainCount < int64(c.Backtest.Frequency) {
		return 0
	}
	return mainCount / int64(c.Backtest.Frequency)
}

// 【2026-05-27 从 PowerMTA 移植】CC/BCC 三组对称的配置类型
//
// RecipientControlConfig: 收件人功能启用开关
//   - Enabled=true(默认): 正常处理 recipients.csv 中每个 Email,主邮件投递 + 触发 CC/BCC 独立邮件循环
//   - Enabled=false: 跳过 Email 为空的合成主收件人(C# 端在收件人禁用场景下生成 1 行空 Email CSV 占位),
//     但仍触发 CC/BCC 独立邮件循环(由 CC/BCC 池本身驱动)
//
// CCConfig: 抄送配置(独立邮件路径)
//   - Enabled=true 且 FilePath 非空时,Go 端从 FilePath 加载抄送地址池
//   - 主邮件: To 头 = 收件人,Cc 头 = 本封分配的 PerEmail 个抄送地址(让收件人能看到抄送列表)
//   - 抄送独立邮件: 每个抄送地址单独生成 1 封独立 raw 邮件(独立 Message-ID/boundary/时间戳),
//     这封邮件的 To 头 = 该 CC 地址本身(收件方看不到主收件人或其他 CC,反指纹安全)
//   - PerEmail 默认 1,clamp 到 [1, 100](防止用户手改 yaml 设巨大值导致 Cc 头超 RFC 998 硬上限)
//
// BCCConfig: 密送配置(纯独立邮件路径,不在主邮件头出现)
//   - 同 CCConfig,但主邮件不写 Bcc 头(永远不写),每个 BCC 单独发独立邮件
//   - 这样所有 BCC 收件人都看不到主收件人/其他 BCC(反指纹最强)
type RecipientControlConfig struct {
	Enabled bool `yaml:"enabled"`
}

type CCConfig struct {
	Enabled  bool   `yaml:"enabled"`
	FilePath string `yaml:"file_path"` // 远端 cc.txt 绝对路径
	PerEmail int    `yaml:"per_email"` // 每封主邮件对应的 CC 数(消费完即停)
}

type BCCConfig struct {
	Enabled  bool   `yaml:"enabled"`
	FilePath string `yaml:"file_path"`
	PerEmail int    `yaml:"per_email"`
}

// 【2026-05-27 批次 4 从 PowerMTA 移植】UnsubscribeServerConfig HTTP 退订服务器配置
// 仅当 Headers.ListUnsubMode = "real" 时由 cmd/serve.go 启动
// 监听 80（301 → HTTPS）+ 443（TLS）；证书由 acme.sh 通配符证书提供
// 服务器在每台 Haraka 服务器独立运行 systemd 守护进程 pmta-injector-unsub.service
//
// 【Haraka 适配】CertFile/KeyFile 路径必须由 C# 端在 GenerateUnsubYaml 时写入
// Haraka 端实际路径: /root/haraka/config/certificate/fullchain_{domain}.pem  /  privkey_{domain}.pem
// （与 PowerMTA 工程的 /etc/pmta/certs/... 不同，绝不能硬编码）
//
// C2 决策：tls.Config.GetCertificate 每次握手回调重读证书文件，证书续期自动生效，无需 reload
// C3 决策：HTML 实例签名（启动时一次随机，进程生命周期不变）+ X-Robots-Tag noindex 防搜索引擎索引
type UnsubscribeServerConfig struct {
	Enabled     bool   `yaml:"enabled,omitempty"`
	ListenHTTP  string `yaml:"listen_http,omitempty"`  // 默认 ":80"，301 重定向到 HTTPS
	ListenHTTPS string `yaml:"listen_https,omitempty"` // 默认 ":443"
	CertFile    string `yaml:"cert_file,omitempty"`    // /root/haraka/config/certificate/fullchain_{domain}.pem
	KeyFile     string `yaml:"key_file,omitempty"`     // /root/haraka/config/certificate/privkey_{domain}.pem
	Domain      string `yaml:"domain,omitempty"`       // 服务器主域名（HTML 标题展示 + Host 校验反扫描用）
}

type AppConfig struct {
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	LogLevel string `yaml:"log_level"`
	LogFile  string `yaml:"log_file"`
}

type SenderConfig struct {
	Mode                   string   `yaml:"mode"`
	FromAddress            string   `yaml:"from_address"`
	FromName               string   `yaml:"from_name"`
	EnvelopeFrom           string   `yaml:"envelope_from"`
	ReplyTo                string   `yaml:"reply_to"`
	SenderMode             string   `yaml:"sender_mode"`
	SenderAddress          string   `yaml:"sender_address"`
	RecipientDisplayMode   string   `yaml:"recipient_display_mode"`
	RecipientHonorific     string   `yaml:"recipient_honorific"`
	RecipientCustomPhrases []string `yaml:"recipient_custom_phrases"`
	DisplayNames           []string `yaml:"display_names"`
	DisplayNameMode        string   `yaml:"display_name_mode"`
	// 【2026-06-15】显示名字节反转隐藏(RLO 反指纹)：true 时对显示名做"字节反转 + RLO 回正"，
	// 收件人看正常、扫描器看反序。仅 UTF-8 生效（控制符无法编码进 Shift_JIS 等）。
	DisplayNameBidiReverse bool `yaml:"display_name_bidi_reverse"`
}

type PMTAConfig struct {
	VirtualMTA string `yaml:"virtual_mta"`
	PickupDir  string `yaml:"pickup_dir"`
	TempDir    string `yaml:"temp_dir"`
	FileMode   uint32 `yaml:"file_mode"`
	DirMode    uint32 `yaml:"dir_mode"`
}

type SMTPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	UseAuth    bool   `yaml:"use_auth"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	UseTLS     bool   `yaml:"use_tls"`
	SkipVerify bool   `yaml:"skip_verify"`
	Timeout    int    `yaml:"timeout"`
	MaxConn    int    `yaml:"max_conn"`
}

type PerformanceConfig struct {
	Workers          int `yaml:"workers"`
	RateLimit        int `yaml:"rate_limit"`
	BatchSize        int `yaml:"batch_size"`
	ChannelBuffer    int `yaml:"channel_buffer"`
	MemoryWarningMB  int `yaml:"memory_warning_mb"`
	ProgressInterval int `yaml:"progress_interval"`
	MinInterval      int `yaml:"min_interval"`
	MaxInterval      int `yaml:"max_interval"`
	// legacy keys from older GUI-generated yaml
	IntervalMinMs int `yaml:"interval_min_ms,omitempty"`
	IntervalMaxMs int `yaml:"interval_max_ms,omitempty"`
	BatchPause    int `yaml:"batch_pause"`
	RetryCount    int `yaml:"retry_count"`
	RetryInterval int `yaml:"retry_interval"`
}

// NormalizedIntervals returns min/max send delay in ms (legacy yaml keys fallback).
func (p PerformanceConfig) NormalizedIntervals() PerformanceConfig {
	out := p
	if out.MinInterval <= 0 && out.IntervalMinMs > 0 {
		out.MinInterval = out.IntervalMinMs
	}
	if out.MaxInterval <= 0 && out.IntervalMaxMs > 0 {
		out.MaxInterval = out.IntervalMaxMs
	}
	if out.MinInterval > 0 && out.MaxInterval > 0 && out.MinInterval > out.MaxInterval {
		out.MinInterval, out.MaxInterval = out.MaxInterval, out.MinInterval
	}
	return out
}

type EmailConfig struct {
	Subject          string               `yaml:"subject"`
	Subjects         []string             `yaml:"subjects"`
	SubjectMode      string               `yaml:"subject_mode"`
	// 【2026-06-15】主题字节反转隐藏(RLO 反指纹)：同 display_name_bidi_reverse，仅 UTF-8 生效。
	SubjectBidiReverse bool               `yaml:"subject_bidi_reverse"`
	TemplatePath       string            `yaml:"template_path"`
	TemplatePaths      []string          `yaml:"template_paths"`
	TemplateKeywords   map[string]string `yaml:"template_keywords,omitempty"`
	TemplateMode       string            `yaml:"template_mode"`
	ConvertTxtToHtml bool                 `yaml:"convert_txt_to_html"`
	Charset          string               `yaml:"charset"`
	ContentType      string               `yaml:"content_type"`
	IncludeTextPart  bool                 `yaml:"include_text_part"`
	MimeMode         string               `yaml:"mime_mode"` // "standard" | "alternative" | "full"
	CidInboxMode     string               `yaml:"cid_inbox_mode,omitempty"` // "legacy"(plain label,高进箱) | "html"(渲染HTML)
	CustomHeaders    map[string]string    `yaml:"custom_headers"`
	EmbeddedImages   []EmbeddedImageConfig `yaml:"embedded_images"` // 【Haraka24】CID 内嵌图片
}

// 【Haraka24】CID 内嵌图片配置
type EmbeddedImageConfig struct {
	CID         string `yaml:"cid"`          // Content-ID 标识（对应 HTML 里的 cid:xxx）
	Path        string `yaml:"path"`         // 图片文件路径
	ContentType string `yaml:"content_type"` // MIME 类型（image/png, image/jpeg 等）
}

type AttachmentsConfig struct {
	Enabled bool     `yaml:"enabled"`
	Mode    string   `yaml:"mode"`
	Files   []string `yaml:"files"`
	// 【2026-06-15】自定义随机附件（测试 + 纯反指纹）：开启后逐封生成 1 个随机/固定 名+后缀+内容 的附件，
	// 与上传附件叠加共存（即使没上传附件也生成）。字段与 C# AppConfig / GenerateConfigYaml 契约对齐。
	Custom CustomAttachmentConfig `yaml:"custom"`
}

// CustomAttachmentConfig 自定义随机附件参数
type CustomAttachmentConfig struct {
	Enabled         bool   `yaml:"enabled"`
	BinaryMode      bool   `yaml:"binary_mode"` // true = 随机二进制（go-sender 风格）
	NameMode        string `yaml:"name_mode"`   // "random" | "fixed"
	NameMin         int    `yaml:"name_min"`
	NameMax         int    `yaml:"name_max"`
	FixedName       string `yaml:"fixed_name"`
	SuffixMode      string `yaml:"suffix_mode"` // "random" | "fixed"
	SuffixMin       int    `yaml:"suffix_min"`
	SuffixMax       int    `yaml:"suffix_max"`
	FixedSuffix     string `yaml:"fixed_suffix"`
	ContentBytesMin int    `yaml:"content_bytes_min"`
	ContentBytesMax int    `yaml:"content_bytes_max"`
	ContentLinesMin int    `yaml:"content_lines_min"`
	ContentLinesMax int    `yaml:"content_lines_max"`
	ContentCharsMin int    `yaml:"content_chars_min"`
	ContentCharsMax int    `yaml:"content_chars_max"`
}

type RecipientsConfig struct {
	FilePath         string    `yaml:"file_path"`
	Format           string    `yaml:"format"`
	SkipLines        int       `yaml:"skip_lines"`
	CSV              CSVConfig `yaml:"csv"`
	RemoveDuplicates bool      `yaml:"remove_duplicates"`
	FilterInvalid    bool      `yaml:"filter_invalid"`
}

type CSVConfig struct {
	Delimiter    string            `yaml:"delimiter"`
	HasHeader    bool              `yaml:"has_header"`
	FieldMapping map[string]string `yaml:"field_mapping"`
}

type JobConfig struct {
	ID              string `yaml:"id"`
	IDPrefix        string `yaml:"id_prefix"`
	IncludeInHeader bool   `yaml:"include_in_header"`
}

type OutputConfig struct {
	ProgressInterval int    `yaml:"progress_interval"`
	ShowProgressBar  bool   `yaml:"show_progress_bar"`
	ProgressFile     string `yaml:"progress_file"`
	ResultFile       string `yaml:"result_file"`
	ErrorFile        string `yaml:"error_file"`
	SaveLog          bool   `yaml:"save_log"`
	SaveFailedEmails bool   `yaml:"save_failed_emails"`
	LogDirectory     string `yaml:"log_directory"`
}

// LoggingConfig GUI「日志设置」：sendMail 写入 logging: 节，与 output 分离。
type LoggingConfig struct {
	SaveLog    bool   `yaml:"save_log"`
	SaveFailed bool   `yaml:"save_failed"`
	Directory  string `yaml:"directory"`
}

func (c *Config) normalizeLogging() {
	if c.Logging.SaveLog || c.Logging.SaveFailed || c.Logging.Directory != "" {
		return
	}
	if c.Output.SaveLog || c.Output.SaveFailedEmails || c.Output.LogDirectory != "" {
		c.Logging.SaveLog = c.Output.SaveLog
		c.Logging.SaveFailed = c.Output.SaveFailedEmails
		c.Logging.Directory = c.Output.LogDirectory
	}
}

func (c *Config) LogDirectoryPath() string {
	dir := strings.TrimSpace(c.Logging.Directory)
	if dir == "" {
		dir = "logs"
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	if base := strings.TrimSpace(c.Output.ProgressFile); base != "" {
		return filepath.Join(filepath.Dir(base), dir)
	}
	if base := strings.TrimSpace(c.Output.ResultFile); base != "" {
		return filepath.Join(filepath.Dir(base), dir)
	}
	return dir
}

type TemplateConfig struct {
	GlobalVariables map[string]interface{} `yaml:"global_variables"`
}

type EncodingConfig struct {
	Charset        string `yaml:"charset"`
	HeaderEncoding string `yaml:"header_encoding"`
	BodyEncoding   string `yaml:"body_encoding"`
	RandomEncoding bool   `yaml:"random_encoding"`
}

type VariablesConfig struct {
	AmountMin           float64           `yaml:"amount_min"`
	AmountMax           float64           `yaml:"amount_max"`
	AmountDecimals      int               `yaml:"amount_decimals"`
	AmountUseSeparator  bool              `yaml:"amount_use_separator"`
	CustomVariableFiles map[string]string            `yaml:"custom_variable_files"`
	CustomVariableModes map[string]string            `yaml:"custom_variable_modes,omitempty"` // name -> sequential | random
}

type HeadersConfig struct {
	Enabled               bool   `yaml:"enabled"`
	MobileClientHeaders   bool   `yaml:"mobile_client_headers,omitempty"` // 手机单跳 Received + 客户端 Message-ID；可与假 DKIM 并存
	Received              bool   `yaml:"received"`
	ReceivedDeterministic bool `yaml:"received_deterministic,omitempty"` // true=固定 2-hop + TLS1_2，消除 ~50% 随机波动
	DkimSignature     bool   `yaml:"dkim_signature"`
	XMailer           bool   `yaml:"x_mailer"`
	XPriority         bool   `yaml:"x_priority"`
	XPriorityValue    string `yaml:"x_priority_value"`
	Importance        bool   `yaml:"importance"`
	ImportanceValue   string `yaml:"importance_value"`
	MessageID         bool   `yaml:"message_id"`
	MessageIDDomainMode string `yaml:"message_id_domain_mode,omitempty"` // "subdomain" | "main"
	MessageIDMainDomain string `yaml:"message_id_main_domain,omitempty"`
	MessageIDFullDomain string `yaml:"message_id_full_domain,omitempty"`
	ReplyTo           bool   `yaml:"reply_to"`
	ReplyToMode       string `yaml:"reply_to_mode"`
	ReturnPath        bool   `yaml:"return_path"`
	ReturnPathMode    string `yaml:"return_path_mode"`
	AcceptLanguage    bool   `yaml:"accept_language"`
	AcceptLangValue   string `yaml:"accept_language_value"`
	ContentLanguage   bool   `yaml:"content_language"`
	ContentLangValue  string `yaml:"content_language_value"`
	CustomHeadersText string `yaml:"custom_headers_text"`
	// 【Haraka26】自定义 From 邮箱地址
	CustomFromEnabled bool     `yaml:"custom_from_enabled"`
	CustomFromMode    string   `yaml:"custom_from_mode"`    // "sequential" | "random"
	CustomFromEmails  []string `yaml:"custom_from_emails"`
	// 每封邮件随机 local-part，保留当前 From 域名（SMTP 认证仍用 sender.from_address）
	FromAddressRandomPrefix bool `yaml:"from_address_random_prefix"`
	// User-Agent（桌面客户端模拟；按 client_profile 池轮换）
	UserAgent bool `yaml:"user_agent,omitempty"`
	// ClientProfile 子域绑定的客户端指纹：outlook / apple / thunderbird / gmail / becky / emclient
	ClientProfile string `yaml:"client_profile,omitempty"`
	// 【Haraka26】显示名支持 \r\n（将字面量 \r\n 替换为真正的回车换行字节）
	DisplayNameNewline bool `yaml:"display_name_newline,omitempty"`

	SenderMode             string   `yaml:"sender_mode"`
	SenderAddress          string   `yaml:"sender_address"`
	RcvdChainEnable        bool     `yaml:"rcvd_chain_enable"`
	RcvdChainType          string   `yaml:"rcvd_chain_type"`
	RecipientDisplayMode   string   `yaml:"recipient_display_mode"`
	RecipientHonorific     string   `yaml:"recipient_honorific"`
	RecipientCustomPhrases []string `yaml:"recipient_custom_phrases"`

	// =====================================================================
	// 【扩展邮件头 2026-05-13】P0/P1/P2/P3 共 28 个邮件头 + 随机使用控制
	// P0 组（4 项）：送达率刚需，勾选了总是加，不参与随机
	// P1/P2/P3 组（24 项）：反指纹高真实感，可独立加或加入随机池
	// 联动组：XTMASGroup / XSFMCGroup —— 单开关控制多个头，保证扫描痕迹一致性
	// =====================================================================

	// P0 送达率刚需
	ListUnsubscribe     bool `yaml:"list_unsubscribe"`
	ListUnsubscribePost bool `yaml:"list_unsubscribe_post"`
	// 【Haraka26 / go-sender 对齐】List-Unsubscribe URL 配置（仅写邮件头，不插 HTML 正文）
	UnsubscribeHost            string `yaml:"unsubscribe_host,omitempty"`
	UnsubscribePath            string `yaml:"unsubscribe_path,omitempty"`
	UnsubscribeKey             string `yaml:"unsubscribe_key,omitempty"` // AES-GCM seed；有值时 URL 为 base/token 形式
	UnsubscribeUseDecimal      bool   `yaml:"unsubscribe_use_decimal"`   // true=List-Unsubscribe Q 编码（GUI「转十进制」）
	UnsubscribeQueryParam      string `yaml:"unsubscribe_query_param,omitempty"`
	UnsubscribeMailtoDomain    string `yaml:"unsubscribe_mailto_domain,omitempty"`
	UnsubscribeHeaderFoldWidth int    `yaml:"unsubscribe_header_fold_width,omitempty"`
	FeedbackID          bool `yaml:"feedback_id"`
	Precedence          bool `yaml:"precedence"`

	// P1 反指纹高真实感
	ErrorsTo       bool `yaml:"errors_to"`
	Sender         bool `yaml:"sender"`
	Organization   bool `yaml:"organization"`
	XOriginatingIP bool `yaml:"x_originating_ip"`
	AutoSubmitted  bool `yaml:"auto_submitted"`
	Comments       bool `yaml:"comments"`
	Keywords       bool `yaml:"keywords"`
	XReportAbuse   bool `yaml:"x_report_abuse"`
	XCSAComplaints bool `yaml:"x_csa_complaints"`

	// P2 Outlook 风格
	XMSMailPriority       bool `yaml:"x_msmail_priority"`
	ThreadIndex           bool `yaml:"thread_index"`
	ThreadTopic           bool `yaml:"thread_topic"`
	XAutoResponseSuppress bool `yaml:"x_auto_response_suppress"`

	// P2 行为标识
	ReturnReceiptTo           bool `yaml:"return_receipt_to"`
	DispositionNotificationTo bool `yaml:"disposition_notification_to"`
	XEntityRefID              bool `yaml:"x_entity_ref_id"`

	// P3 营销活动
	XCampaignID bool `yaml:"x_campaign_id"`
	XMailerLID  bool `yaml:"x_mailer_lid"`
	CampaignID  bool `yaml:"campaign_id"`

	// P3 联动组（一个开关 → 多个头）
	XTMASGroup bool `yaml:"x_tm_as_group"` // 启用 X-TM-AS-* 系列 6 个头（v2 扩展，原 3 头）
	XSFMCGroup bool `yaml:"x_sfmc_group"`  // 启用 X-SFMC-Stack + x-job

	// 【2026-05-21 从 PowerMTA 移植】4 组企业网关联动头（企业级反垃圾产品，IP 段不敏感）
	XBarracudaGroup  bool `yaml:"x_barracuda_group"`  // Barracuda 6 头联动
	XProofpointGroup bool `yaml:"x_proofpoint_group"` // Proofpoint 4 头联动
	XMimecastGroup   bool `yaml:"x_mimecast_group"`   // Mimecast 4 头联动
	XSymantecGroup   bool `yaml:"x_symantec_group"`   // Symantec MessageLabs 4 头联动

	// 【扩展邮件头 v2 2026-05-14】方案 B 5 个新独立头
	ListID               bool `yaml:"list_id"`                // P0 新增（与 List-Unsubscribe 配套）
	XOriginatingEmail    bool `yaml:"x_originating_email"`    // P1 新增（与 X-Originating-IP 配套）
	XMimeOLE             bool `yaml:"x_mime_ole"`             // P2 Outlook 新增
	XMailerVersion       bool `yaml:"x_mailer_version"`       // P2 Outlook 新增（与 X-Mailer 配套）
	XOriginalArrivalTime bool `yaml:"x_original_arrival_time"` // P2 Outlook 新增（与 X-MimeOLE 配套）

	// 【ESP Received 2026-05-21 从 PowerMTA 移植】5 个特定 ESP 风格 Received 头（独立开关，不进随机池）
	// 多个并存时按固定顺序拼接：三井 → docomo → au → softbank → 雅虎 → 原 Received（时间递减 1-30 秒）
	ReceivedYahoo       bool   `yaml:"received_yahoo"`         // Received（雅虎）：mtaXXX.{kks|kth|ssk}.gm.yahoo.co.jp 风格
	ReceivedYahooIPMode string `yaml:"received_yahoo_ip_mode"` // "yahoo"=CIDR 池 / "random"=全球公网随机（排 9 段非公网）
	ReceivedAu          bool   `yaml:"received_au"`            // Received（au）：mta-snd-eNN.au.com 风格
	ReceivedSoftbank    bool   `yaml:"received_softbank"`      // Received（软银）：ebmkyNNNsc / dimkyNNNsc / 172.16-31 私网 IP（真实特征）
	ReceivedDocomo      bool   `yaml:"received_docomo"`        // Received（docomo）：mailN.docomo-bill.ne.jp + Postfix 风格 + (JST)
	ReceivedMitsui      bool   `yaml:"received_mitsui"`        // Received（三井）：from mail.vpass.ne.jp by mail.smbc.co.jp（几乎全固定）

	// 【2026-05-27 从 PowerMTA 移植】Received（随机）模板池：50 内置 + 用户自定义
	// Go 端每封邮件按 ReceivedRandomMode（sequential | random）从池里挑一行，再走变量替换 + 折叠
	// 插入位置：雅虎 → Received（随机）→ 原 Received（时间链继续递减 1-30 秒）
	// 模板里的 {VAR} 由 email/variables_ext.go 的 53 个扩展变量解析（RFC 2822 时间/ID/IP/域名/TLS/JWT）
	ReceivedRandomEnabled   bool     `yaml:"received_random_enabled,omitempty"`
	ReceivedRandomMode      string   `yaml:"received_random_mode,omitempty"` // "sequential" | "random"
	ReceivedRandomTemplates []string `yaml:"received_random_templates,omitempty"`

	// 【2026-05-27 批次 4 从 PowerMTA 移植】List-Unsubscribe 4 模式
	//   default = <mailto:unsubscribe-{16hex}@{domain}>（老行为，无 HTTP server）
	//   real    = 从用户真实模板池里抽 + 自动加 List-Unsubscribe-Post（One-Click） + 启动 HTTP server 守护
	//   custom  = 从用户自定义模板池里抽
	//   random  = 从用户随机模板池里抽
	// 真实/自定义/随机 三种各自独立的模板池 + 顺序/随机模式
	// 真实模式下自动加 List-Unsubscribe-Post（C6 决策）
	ListUnsubMode            string   `yaml:"list_unsub_mode,omitempty"` // "default" | "real" | "custom" | "random"
	ListUnsubRealTemplates   []string `yaml:"list_unsub_real_templates,omitempty"`
	ListUnsubRealMode        string   `yaml:"list_unsub_real_mode,omitempty"` // "sequential" | "random"
	ListUnsubCustomTemplates []string `yaml:"list_unsub_custom_templates,omitempty"`
	ListUnsubCustomMode      string   `yaml:"list_unsub_custom_mode,omitempty"`
	ListUnsubRandomTemplates []string `yaml:"list_unsub_random_templates,omitempty"`
	ListUnsubRandomMode      string   `yaml:"list_unsub_random_mode,omitempty"`

	// 【2026-05-31 从 PowerMTA 同步】字段名随机大小写 + 邮件头排序乱序
	//   RandomCase   : 启用每个邮件头字段名逐字符 50/50 随机大小写
	//   ShuffleOrder : 启用温和锚定式乱序(锚定 Received/DKIM/MIME/From/To/Cc/Subject/Date/Message-ID/
	//                  List-Unsubscribe + Post / x-virtual-mta + x-job 不动,其它头 Fisher-Yates 洗牌)
	//   CaseMode     : 预留 D2 切换点。空="random"(全随机式)
	// 实施:email/headers_postprocess.go
	// 跳过名单:DKIM-Signature / x-virtual-mta / x-job
	RandomCase   bool   `yaml:"random_case,omitempty"`
	ShuffleOrder bool   `yaml:"shuffle_order,omitempty"`
	// DkimSignHeaders Haraka DKIM 预设签名字段（小写），乱序时保持此顺序块不变以对齐 DKIM
	DkimSignHeaders []string `yaml:"dkim_sign_headers,omitempty"`
	CaseMode     string `yaml:"case_mode,omitempty"`

	// 【2026-06-15】Message-ID 风格选择器（去重后 25 种 + "随机Message-ID"）
	//   MessageIDRandomAll : true=从全部风格随机抽（默认"随机Message-ID"）；false=仅从 MessageIDStyles 勾选项随机；空选回退全随机
	//   MessageIDStyles    : 勾选的风格 key（与 C# MessageIdStyleForm 字节一致；仅 RandomAll=false 时生效）
	//   仅当 headers.Enabled && headers.MessageID 都为 true 时才走自定义 Message-ID（见 builder.go）
	MessageIDRandomAll bool     `yaml:"message_id_random_all"`
	MessageIDStyles    []string `yaml:"message_id_styles,omitempty"`

	// 随机使用邮件头
	RandomEnabled bool `yaml:"random_enabled"`
	RandomMin     int  `yaml:"random_min"` // 范围下限，[1, 10]
	RandomMax     int  `yaml:"random_max"` // 范围上限，[1, 10]

	// 【HELO 池 2026-05-21 从 PowerMTA 移植，Haraka 端用插件实现】
	HeloPoolEnabled bool     `yaml:"helo_pool_enabled"` // 启用 HELO 域名池多域轮换
	HeloDomains     []string `yaml:"helo_domains"`      // HELO 域名列表（每条一行，原样保留）
}

// 【Haraka26】零宽字符配置
type ZeroWidthConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Subject         bool   `yaml:"subject"`
	DisplayName     bool   `yaml:"display_name"`
	TemplateContent bool   `yaml:"template_content"`
	Keywords        string `yaml:"keywords,omitempty"`
}

type ReverseBidiConfig struct {
	Subject         bool `yaml:"subject"`
	DisplayName     bool `yaml:"display_name"`
	TemplateContent bool `yaml:"template_content"`
}

// 【Haraka26】图片噪点配置
type ImageNoiseConfig struct {
	Enabled bool `yaml:"enabled"`
}

// HtmlMutatorConfig HTML 模板 DOM/CSS 指纹变异（每收件人一次）
type HtmlMutatorConfig struct {
	Enabled        bool `yaml:"enabled"`
	CssJitter      bool `yaml:"css_jitter"`
	InjectAttrs    bool `yaml:"inject_attrs"`
	TagSwap        bool `yaml:"tag_swap"`
	PreserveTables bool `yaml:"preserve_tables"`
}

// IsPMTA 判断是否为 PowerMTA 模式
func (c *Config) IsPMTA() bool {
	return c.MtaType == "" || c.MtaType == "pmta"
}

// IsHaraka 判断是否为 Haraka 模式
func (c *Config) IsHaraka() bool {
	return c.MtaType == "haraka"
}

// SMTPNeedAuth Haraka 587 必须 AUTH；YAML 关掉 use_auth 也强制开。
func (c *Config) SMTPNeedAuth() bool {
	if c == nil {
		return false
	}
	if c.SMTP.UseAuth {
		return true
	}
	return c.IsHaraka()
}

func (c *Config) SMTPAuthUser() string {
	if c == nil {
		return ""
	}
	if u := strings.TrimSpace(c.SMTP.Username); u != "" {
		return u
	}
	return strings.TrimSpace(c.Sender.FromAddress)
}

func Default() *Config {
	return &Config{
		App: AppConfig{
			Name: "pmta-injector", Version: "2.0.0",
			LogLevel: "info", LogFile: "/var/log/pmta-injector/app.log",
		},
		MtaType: "pmta",
		Sender: SenderConfig{
			Mode: "auto", FromAddress: "noreply@example.com", FromName: "Example Company",
			DisplayNames: []string{}, DisplayNameMode: "random",
		},
		PMTA: PMTAConfig{
			VirtualMTA: "pmta-vmta1", PickupDir: "/var/spool/pmta/pickup",
			TempDir: "/var/spool/pmta/tmp", FileMode: 0644, DirMode: 0755,
		},
		SMTP: SMTPConfig{
			Enabled: true, Host: "127.0.0.1", Port: 25,
			UseAuth: false, UseTLS: false, SkipVerify: true, Timeout: 30, MaxConn: 50,
		},
		Performance: PerformanceConfig{
			Workers: runtime.NumCPU() * 10, BatchSize: 1000, ChannelBuffer: 10000,
			MemoryWarningMB: 500, ProgressInterval: 1, MaxInterval: 100,
			BatchPause: 5, RetryCount: 3, RetryInterval: 1000,
		},
		Email: EmailConfig{
			Subject: "Welcome", Subjects: []string{}, SubjectMode: "random",
			TemplatePaths: []string{}, TemplateMode: "random", ConvertTxtToHtml: true,
			Charset: "UTF-8", ContentType: "text/html", MimeMode: "standard", CustomHeaders: make(map[string]string),
		},
		Attachments: AttachmentsConfig{Mode: "sequential", Files: []string{}},
		Recipients: RecipientsConfig{
			Format: "auto", RemoveDuplicates: true, FilterInvalid: true,
			CSV: CSVConfig{Delimiter: ",", HasHeader: true, FieldMapping: map[string]string{}},
		},
		Job:      JobConfig{IDPrefix: "job", IncludeInHeader: true},
		Output: OutputConfig{
			ProgressInterval: 1, ShowProgressBar: true,
			ProgressFile: "/tmp/progress.json", ResultFile: "/tmp/result.json",
			ErrorFile: "/tmp/errors.log", SaveLog: true, SaveFailedEmails: true,
			LogDirectory: "/var/log/pmta-injector",
		},
		Template: TemplateConfig{GlobalVariables: make(map[string]interface{})},
		Encoding: EncodingConfig{Charset: "UTF-8", HeaderEncoding: "base64", BodyEncoding: "base64"},
		Variables: VariablesConfig{
			AmountMin: 10000, AmountMax: 100000, AmountUseSeparator: true,
			CustomVariableFiles: make(map[string]string),
		},
		Headers: HeadersConfig{
			XPriorityValue: "random", ImportanceValue: "random",
			ReplyToMode: "from_address", ReturnPathMode: "from_address",
			AcceptLangValue: "random", ContentLangValue: "random",
		},
		// 【2026-05-27 从 PowerMTA 移植】CC/BCC 三组对称默认值
		// Recipient.Enabled 默认 true 保持向后兼容(老 config.yaml 无此字段时正常发主邮件)
		// CC/BCC 默认禁用,PerEmail 兜底 1(避免 yaml 缺字段时 0 导致 takeBatch 死循环)
		Recipient: RecipientControlConfig{Enabled: true},
		CC:        CCConfig{Enabled: false, PerEmail: 1},
		BCC:       BCCConfig{Enabled: false, PerEmail: 1},
	}
}

func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	if cfg.Sender.EnvelopeFrom == "" {
		cfg.Sender.EnvelopeFrom = cfg.Sender.FromAddress
	}
	if cfg.Performance.Workers <= 0 {
		cfg.Performance.Workers = runtime.NumCPU() * 10
	}
	cfg.Performance = cfg.Performance.NormalizedIntervals()
	cfg.normalizeLogging()
	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	return nil
}
