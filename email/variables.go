package email

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/types"
)

// ===== 【修复问题6】预编译所有正则表达式 =====
// regexp.Regexp 本身是并发安全的，可以在所有协程间共享
var (
	// 随机变量正则
	reRandom       = regexp.MustCompile(`(?i)\{RANDOM(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomLower  = regexp.MustCompile(`(?i)\{RANDOM_LOWER(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomUpper  = regexp.MustCompile(`(?i)\{RANDOM_UPPER(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomNum    = regexp.MustCompile(`(?i)\{RANDOM_NUM(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomLowerN = regexp.MustCompile(`(?i)\{RANDOM_LOWER_NUM(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomUpperN = regexp.MustCompile(`(?i)\{RANDOM_UPPER_NUM(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomHex    = regexp.MustCompile(`(?i)\{RANDOM_HEX(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomCN     = regexp.MustCompile(`(?i)\{RANDOM_CN(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomJP     = regexp.MustCompile(`(?i)\{RANDOM_JP(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomHira   = regexp.MustCompile(`(?i)\{RANDOM_HIRA(?::(\d+)(?:-(\d+))?)?\}`)
	reRandomKata   = regexp.MustCompile(`(?i)\{RANDOM_KATA(?::(\d+)(?:-(\d+))?)?\}`)

	// 金额变量正则
	reAmount    = regexp.MustCompile(`(?i)\{AMOUNT\}`)
	reAmountR   = regexp.MustCompile(`(?i)\{AMOUNT:(\d+)-(\d+)(?::(\d+))?\}`)
	reAmountJP  = regexp.MustCompile(`(?i)\{AMOUNT_JP:(\d+)-(\d+)\}`)
	reAmountCN  = regexp.MustCompile(`(?i)\{AMOUNT_CN:(\d+)-(\d+)(?::(\d+))?\}`)
	reAmountUSD = regexp.MustCompile(`(?i)\{AMOUNT_USD:(\d+)-(\d+)(?::(\d+))?\}`)

	// IP变量正则
	reRandomIP   = regexp.MustCompile(`(?i)\{RANDOM_IP\}`)
	reRandomIPCN = regexp.MustCompile(`(?i)\{RANDOM_IP_CN\}`)
	reRandomIPJP = regexp.MustCompile(`(?i)\{RANDOM_IP_JP\}`)
	reRandomIPUS = regexp.MustCompile(`(?i)\{RANDOM_IP_US\}`)

	// UUID/哈希正则
	reUUID      = regexp.MustCompile(`(?i)\{UUID\}`)
	reUUIDShort = regexp.MustCompile(`(?i)\{UUID_SHORT\}`)
	reMD5       = regexp.MustCompile(`(?i)\{MD5:([^}]+)\}`)
	reMD5Short  = regexp.MustCompile(`(?i)\{MD5_SHORT:([^}]+)\}`)

	// 自定义变量正则
	reCustomVar = regexp.MustCompile(`(?i)\{CUSTOM:(\w+)(?::(random|seq))?\}`)

	// 条件变量正则
	reConditional = regexp.MustCompile(`(?i)\{IF:(\w+)=([^:]+):([^:]*):([^}]*)\}`)
)

// randomVarDef 预编译正则+生成函数的配对
type randomVarDef struct {
	re    *regexp.Regexp
	genFn func(vp *VariableProcessor, length int) string
}

// 随机变量定义表（启动时初始化一次）
var randomVarDefs = []randomVarDef{
	{reRandom, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "alphanumeric") }},
	{reRandomLower, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "lower") }},
	{reRandomUpper, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "upper") }},
	{reRandomNum, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "numeric") }},
	{reRandomLowerN, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "lower_num") }},
	{reRandomUpperN, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "upper_num") }},
	{reRandomHex, func(vp *VariableProcessor, l int) string { return vp.generateRandom(l, "hex") }},
	{reRandomCN, func(vp *VariableProcessor, l int) string { return vp.generateRandomChinese(l) }},
	{reRandomJP, func(vp *VariableProcessor, l int) string { return vp.generateRandomJapanese(l, true, true) }},
	{reRandomHira, func(vp *VariableProcessor, l int) string { return vp.generateRandomJapanese(l, true, false) }},
	{reRandomKata, func(vp *VariableProcessor, l int) string { return vp.generateRandomJapanese(l, false, true) }},
}

// VariableProcessor 变量处理器
type VariableProcessor struct {
	cfg              *config.Config
	customVars       map[string][]string
	customVarModes   map[string]string
	customVarIndex   map[string]int
	templateIndex    int
	subjectIndex     int
	displayNameIndex int
	attachmentIndex  int // 【修复问题3】附件顺序索引
	random           *rand.Rand
}

// NewVariableProcessor 创建新的变量处理器
// 【v62修复】使用 crypto/rand 生成安全种子 + workerID 偏移，彻底避免并发种子碰撞
func NewVariableProcessor(cfg *config.Config, workerID int) *VariableProcessor {
	vp := &VariableProcessor{
		cfg:            cfg,
		customVars:     make(map[string][]string),
		customVarModes: make(map[string]string),
		customVarIndex: make(map[string]int),
		random:         rand.New(rand.NewSource(cryptoSeed(workerID))),
	}

	// 加载自定义变量文件
	vp.loadCustomVariables()

	return vp
}

// loadCustomVariables 加载自定义变量文件
func (vp *VariableProcessor) loadCustomVariables() {
	for name, filePath := range vp.cfg.Variables.CustomVariableFiles {
		values, err := readLinesFromFile(filePath)
		if err != nil {
			fmt.Printf("Warning: Failed to load custom variable %s: %v\n", name, err)
			continue
		}
		key := strings.ToLower(name)
		vp.customVars[key] = values
		vp.customVarIndex[key] = 0
	}
	for name, mode := range vp.cfg.Variables.CustomVariableModes {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		m := strings.ToLower(strings.TrimSpace(mode))
		if m == "seq" || m == "sequential" {
			vp.customVarModes[key] = "sequential"
		} else {
			vp.customVarModes[key] = "random"
		}
	}
}

// readLinesFromFile 从文件读取所有非空行
func readLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// Process 处理所有变量替换
func (vp *VariableProcessor) Process(content string, recipient *types.Recipient) string {
	if content == "" {
		return content
	}

	// 1. 处理时间变量
	content = vp.processTimeVariables(content)

	// 2. 处理收件人变量
	content = vp.processRecipientVariables(content, recipient)

	// 3. 处理发件人变量
	content = vp.processSenderVariables(content)

	// 4. 处理随机变量
	content = vp.processRandomVariables(content)

	// 5. 处理金额变量
	content = vp.processAmountVariables(content)

	// 6. 处理IP变量
	content = vp.processIPVariables(content)

	// 7. 处理UUID/哈希变量
	content = vp.processUuidHashVariables(content)

	// 8. 处理自定义变量
	content = vp.processCustomVariables(content, recipient)

	// 9. 处理条件变量
	content = vp.processConditionalVariables(content, recipient)

	// 10. 【2026-05-27 从 PowerMTA 移植】处理 53 个扩展变量（A 时间 13 / B ID 8 / C IP 10 / D 域名 15 / E 协议 6 / F JWT 1）
	// 实现在 variables_ext.go，被 Received 随机模板和 List-Unsubscribe 4 模式池模式调用
	content = vp.processExtendedVariables(content)

	return content
}

// processTimeVariables 处理时间变量
func (vp *VariableProcessor) processTimeVariables(content string) string {
	now := time.Now()

	replacements := map[string]string{
		"{DATE_TIME}":  now.Format("2006-01-02 15:04:05"),
		"{DATE}":       now.Format("2006-01-02"),
		"{TIME}":       now.Format("15:04:05"),
		"{YEAR}":       now.Format("2006"),
		"{MONTH}":      now.Format("01"),
		"{DAY}":        now.Format("02"),
		"{HOUR}":       now.Format("15"),
		"{MINUTE}":     now.Format("04"),
		"{SECOND}":     now.Format("05"),
		"{TIMESTAMP}":  strconv.FormatInt(now.Unix(), 10),
		"{DATE_JP}":    now.Format("2006年01月02日"),
		"{DATE_CN}":    fmt.Sprintf("%d年%d月%d日", now.Year(), now.Month(), now.Day()),
		"{WEEKDAY}":    getWeekdayCN(now.Weekday()),
		"{WEEKDAY_EN}": now.Weekday().String(),
	}

	for k, v := range replacements {
		content = strings.ReplaceAll(content, k, v)
		content = strings.ReplaceAll(content, strings.ToLower(k), v)
	}

	return content
}

func getWeekdayCN(w time.Weekday) string {
	names := []string{"星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六"}
	return names[w]
}

// processRecipientVariables 处理收件人变量
func (vp *VariableProcessor) processRecipientVariables(content string, r *types.Recipient) string {
	email := r.Email
	parts := strings.Split(email, "@")
	user := parts[0]
	domain := ""
	if len(parts) > 1 {
		domain = parts[1]
	}

	replacements := map[string]string{
		"{TO_EMAIL}":      email,
		"{TO_USER}":       user,
		"{TO_DOMAIN}":     domain,
		"{TO_NAME}":       r.Name,
		"{TO_FIRST}":      r.FirstName,
		"{TO_LAST}":       r.LastName,
		"{TO_USER_UPPER}": strings.ToUpper(user),
		"{TO_USER_LOWER}": strings.ToLower(user),
		"{TO_USER_CAP}":   capitalizeFirst(user),
		"{TO_NAME_UPPER}": strings.ToUpper(r.Name),
		"{TO_NAME_LOWER}": strings.ToLower(r.Name),
	}

	for k, v := range replacements {
		content = strings.ReplaceAll(content, k, v)
		content = strings.ReplaceAll(content, strings.ToLower(k), v)
	}

	// 处理收件人自定义字段（来自CSV的额外列）
	if r.CustomFields != nil && len(r.CustomFields) > 0 {
		for key, value := range r.CustomFields {
			if strings.TrimSpace(value) == "" {
				continue
			}
			owned := strings.ToLower(key)
			if _, exists := vp.customVars[owned]; exists && vp.customVarModes[owned] != "sequential" {
				continue
			}
			patterns := []string{
				fmt.Sprintf("{CUSTOM:%s:seq}", key),
				fmt.Sprintf("{CUSTOM:%s:random}", key),
				fmt.Sprintf("{CUSTOM:%s:seq}", strings.ToUpper(key)),
				fmt.Sprintf("{CUSTOM:%s:random}", strings.ToUpper(key)),
				fmt.Sprintf("{CUSTOM:%s:seq}", strings.ToLower(key)),
				fmt.Sprintf("{CUSTOM:%s:random}", strings.ToLower(key)),
				fmt.Sprintf("{%s}", key),
				fmt.Sprintf("{%s}", strings.ToUpper(key)),
				fmt.Sprintf("{%s}", strings.ToLower(key)),
				fmt.Sprintf("{CUSTOM:%s}", key),
				fmt.Sprintf("{CUSTOM:%s}", strings.ToUpper(key)),
				fmt.Sprintf("{CUSTOM:%s}", strings.ToLower(key)),
				fmt.Sprintf("{TO_%s}", strings.ToUpper(key)),
				fmt.Sprintf("{to_%s}", strings.ToLower(key)),
			}

			for _, pattern := range patterns {
				if strings.Contains(content, pattern) {
					content = strings.ReplaceAll(content, pattern, value)
				}
			}
		}
	}

	return content
}

// capitalizeFirst 首字母大写
// 【修复问题5】使用 utf8.DecodeRuneInString 正确处理多字节字符（日文/中文等）
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return strings.ToUpper(string(r)) + strings.ToLower(s[size:])
}

// processSenderVariables 处理发件人变量
func (vp *VariableProcessor) processSenderVariables(content string) string {
	fromAddr := vp.cfg.Sender.FromAddress
	parts := strings.Split(fromAddr, "@")
	user := parts[0]
	domain := ""
	if len(parts) > 1 {
		domain = parts[1]
	}

	replacements := map[string]string{
		"{FROM_EMAIL}":  fromAddr,
		"{FROM_USER}":   user,
		"{FROM_DOMAIN}": domain,
		"{FROM_NAME}":   vp.cfg.Sender.FromName,
	}

	for k, v := range replacements {
		content = strings.ReplaceAll(content, k, v)
		content = strings.ReplaceAll(content, strings.ToLower(k), v)
	}

	return content
}

// parseRandomLength 从正则匹配结果中解析长度参数
func parseRandomLength(re *regexp.Regexp, match string, random *rand.Rand) int {
	length := 8 // 默认长度
	submatches := re.FindStringSubmatch(match)
	if len(submatches) > 1 && submatches[1] != "" {
		min, _ := strconv.Atoi(submatches[1])
		if len(submatches) > 2 && submatches[2] != "" {
			max, _ := strconv.Atoi(submatches[2])
			if max > min {
				length = min + safeIntn(random, max-min+1)
			} else {
				length = min
			}
		} else {
			length = min
		}
	}
	if length <= 0 {
		length = 1
	}
	return length
}

// processRandomVariables 处理随机变量
func (vp *VariableProcessor) processRandomVariables(content string) string {
	for _, def := range randomVarDefs {
		def := def // 闭包安全
		content = def.re.ReplaceAllStringFunc(content, func(match string) string {
			length := parseRandomLength(def.re, match, vp.random)
			return def.genFn(vp, length)
		})
	}
	return content
}

func (vp *VariableProcessor) generateRandom(length int, randType string) string {
	var chars string
	switch randType {
	case "lower":
		chars = "abcdefghijklmnopqrstuvwxyz"
	case "upper":
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "numeric":
		chars = "0123456789"
	case "alphanumeric":
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case "lower_num":
		chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	case "upper_num":
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case "hex":
		chars = "0123456789abcdef"
	default:
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	result := make([]byte, length)
	for i := range result {
		result[i] = chars[safeIntn(vp.random, len(chars))]
	}
	return string(result)
}

func (vp *VariableProcessor) generateRandomChinese(length int) string {
	result := make([]rune, length)
	for i := range result {
		result[i] = rune(0x4E00 + safeIntn(vp.random, 0x9FFF-0x4E00+1))
	}
	return string(result)
}

func (vp *VariableProcessor) generateRandomJapanese(length int, hiragana, katakana bool) string {
	result := make([]rune, length)
	for i := range result {
		if hiragana && katakana {
			if safeIntn(vp.random, 2) == 0 {
				result[i] = rune(0x3040 + safeIntn(vp.random, 0x309F-0x3040+1))
			} else {
				result[i] = rune(0x30A0 + safeIntn(vp.random, 0x30FF-0x30A0+1))
			}
		} else if hiragana {
			result[i] = rune(0x3040 + safeIntn(vp.random, 0x309F-0x3040+1))
		} else {
			result[i] = rune(0x30A0 + safeIntn(vp.random, 0x30FF-0x30A0+1))
		}
	}
	return string(result)
}

// processAmountVariables 处理金额变量
func (vp *VariableProcessor) processAmountVariables(content string) string {
	cfg := vp.cfg.Variables

	content = reAmount.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateAmount(cfg.AmountMin, cfg.AmountMax, cfg.AmountDecimals, cfg.AmountUseSeparator, "")
	})

	content = reAmountR.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reAmountR.FindStringSubmatch(match)
		min, _ := strconv.ParseFloat(submatches[1], 64)
		max, _ := strconv.ParseFloat(submatches[2], 64)
		decimals := cfg.AmountDecimals
		if len(submatches) > 3 && submatches[3] != "" {
			decimals, _ = strconv.Atoi(submatches[3])
		}
		return vp.generateAmount(min, max, decimals, cfg.AmountUseSeparator, "")
	})

	content = reAmountJP.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reAmountJP.FindStringSubmatch(match)
		min, _ := strconv.ParseFloat(submatches[1], 64)
		max, _ := strconv.ParseFloat(submatches[2], 64)
		return vp.generateAmount(min, max, 0, true, "¥")
	})

	content = reAmountCN.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reAmountCN.FindStringSubmatch(match)
		min, _ := strconv.ParseFloat(submatches[1], 64)
		max, _ := strconv.ParseFloat(submatches[2], 64)
		decimals := 2
		if len(submatches) > 3 && submatches[3] != "" {
			decimals, _ = strconv.Atoi(submatches[3])
		}
		return vp.generateAmount(min, max, decimals, true, "￥")
	})

	content = reAmountUSD.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reAmountUSD.FindStringSubmatch(match)
		min, _ := strconv.ParseFloat(submatches[1], 64)
		max, _ := strconv.ParseFloat(submatches[2], 64)
		decimals := 2
		if len(submatches) > 3 && submatches[3] != "" {
			decimals, _ = strconv.Atoi(submatches[3])
		}
		return vp.generateAmount(min, max, decimals, true, "$")
	})

	return content
}

func (vp *VariableProcessor) generateAmount(min, max float64, decimals int, useSeparator bool, prefix string) string {
	amount := min + vp.random.Float64()*(max-min)

	var formatted string
	if decimals > 0 {
		formatted = fmt.Sprintf("%.*f", decimals, amount)
	} else {
		formatted = fmt.Sprintf("%.0f", amount)
	}

	if useSeparator {
		formatted = addThousandSeparator(formatted)
	}

	return prefix + formatted
}

func addThousandSeparator(s string) string {
	parts := strings.Split(s, ".")
	intPart := parts[0]

	var result []byte
	for i, c := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}

	if len(parts) > 1 {
		return string(result) + "." + parts[1]
	}
	return string(result)
}

// processIPVariables 处理IP变量
func (vp *VariableProcessor) processIPVariables(content string) string {
	content = reRandomIP.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateRandomIP([][]int{{1, 9}, {11, 126}, {128, 169}, {171, 191}, {193, 223}})
	})
	content = reRandomIPCN.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateRandomIP([][]int{{116, 117}, {119, 120}, {121, 122}, {222, 223}})
	})
	content = reRandomIPJP.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateRandomIP([][]int{{133, 134}, {150, 151}, {157, 158}, {202, 203}})
	})
	content = reRandomIPUS.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateRandomIP([][]int{{64, 65}, {66, 67}, {69, 70}, {98, 99}})
	})
	return content
}

func (vp *VariableProcessor) generateRandomIP(ranges [][]int) string {
	r := ranges[safeIntn(vp.random, len(ranges))]
	first := r[0] + safeIntn(vp.random, r[1]-r[0]+1)
	return fmt.Sprintf("%d.%d.%d.%d", first, safeIntn(vp.random, 256), safeIntn(vp.random, 256), 1+safeIntn(vp.random, 254))
}

// processUuidHashVariables 处理UUID和哈希变量
func (vp *VariableProcessor) processUuidHashVariables(content string) string {
	content = reUUID.ReplaceAllStringFunc(content, func(match string) string {
		return vp.generateUUID()
	})
	content = reUUIDShort.ReplaceAllStringFunc(content, func(match string) string {
		return strings.ReplaceAll(vp.generateUUID(), "-", "")
	})
	content = reMD5.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reMD5.FindStringSubmatch(match)
		if len(submatches) > 1 {
			hash := md5.Sum([]byte(submatches[1]))
			return hex.EncodeToString(hash[:])
		}
		return match
	})
	content = reMD5Short.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reMD5Short.FindStringSubmatch(match)
		if len(submatches) > 1 {
			hash := md5.Sum([]byte(submatches[1]))
			return hex.EncodeToString(hash[:])[:8]
		}
		return match
	})
	return content
}

func (vp *VariableProcessor) generateUUID() string {
	b := make([]byte, 16)
	vp.random.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// processCustomVariables 处理自定义变量
func (vp *VariableProcessor) processCustomVariables(content string, recipient *types.Recipient) string {
	return reCustomVar.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reCustomVar.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		varName := strings.ToLower(submatches[1])
		mode := ""
		if len(submatches) > 2 && submatches[2] != "" {
			mode = strings.ToLower(submatches[2])
		}
		if mode == "" {
			if def := vp.customVarModes[varName]; def == "sequential" {
				mode = "seq"
			} else {
				mode = "random"
			}
		}

		values, ok := vp.customVars[varName]
		if !ok || len(values) == 0 {
			return ""
		}

		if mode == "seq" {
			idx := 0
			if recipient != nil && recipient.Index > 0 {
				idx = recipient.Index - 1
			} else {
				idx = vp.customVarIndex[varName]
				vp.customVarIndex[varName] = idx + 1
			}
			return values[idx%len(values)]
		}

		return values[safeIntn(vp.random, len(values))]
	})
}

// processConditionalVariables 处理条件变量
func (vp *VariableProcessor) processConditionalVariables(content string, r *types.Recipient) string {
	email := r.Email
	parts := strings.Split(email, "@")
	user := parts[0]
	domain := ""
	if len(parts) > 1 {
		domain = parts[1]
	}

	content = reConditional.ReplaceAllStringFunc(content, func(match string) string {
		submatches := reConditional.FindStringSubmatch(match)
		if len(submatches) < 5 {
			return match
		}

		field := strings.ToUpper(submatches[1])
		compareValue := submatches[2]
		trueValue := submatches[3]
		falseValue := submatches[4]

		var actualValue string
		switch field {
		case "TO_DOMAIN":
			actualValue = domain
		case "TO_USER":
			actualValue = user
		case "TO_EMAIL":
			actualValue = email
		case "TO_NAME":
			actualValue = r.Name
		}

		if strings.EqualFold(actualValue, compareValue) {
			return trueValue
		}
		return falseValue
	})

	return content
}

// GetNextTemplate 获取下一个模板
func (vp *VariableProcessor) GetNextTemplate() string {
	paths := vp.cfg.Email.TemplatePaths
	if len(paths) == 0 {
		return vp.cfg.Email.TemplatePath
	}

	if vp.cfg.Email.TemplateMode == "sequential" {
		path := paths[vp.templateIndex%len(paths)]
		vp.templateIndex++
		return path
	}

	return paths[safeIntn(vp.random, len(paths))]
}

// GetNextSubject 获取下一个主题
func (vp *VariableProcessor) GetNextSubject() string {
	subjects := vp.cfg.Email.Subjects
	if len(subjects) == 0 {
		return vp.cfg.Email.Subject
	}

	if vp.cfg.Email.SubjectMode == "sequential" {
		subject := subjects[vp.subjectIndex%len(subjects)]
		vp.subjectIndex++
		return subject
	}

	return subjects[safeIntn(vp.random, len(subjects))]
}

// GetNextDisplayName 获取下一个显示名
func (vp *VariableProcessor) GetNextDisplayName() string {
	names := vp.cfg.Sender.DisplayNames
	if len(names) == 0 {
		return vp.cfg.Sender.FromName
	}

	if vp.cfg.Sender.DisplayNameMode == "sequential" {
		name := names[vp.displayNameIndex%len(names)]
		vp.displayNameIndex++
		return name
	}

	return names[safeIntn(vp.random, len(names))]
}

// GetNextAttachmentIndex 获取下一个附件索引
// 【修复问题3】附件顺序模式支持轮转
func (vp *VariableProcessor) GetNextAttachmentIndex(total int) int {
	if total <= 0 {
		return 0
	}
	idx := vp.attachmentIndex % total
	vp.attachmentIndex++
	return idx
}

// TextToHTML 将纯文本转换为HTML（保留换行，链接可点击）
func TextToHTML(text string, charset string) string {
	if text == "" {
		return text
	}

	// 在HTML转义之前先检测URL
	urlRe := regexp.MustCompile(`https?://[^\s<>"'` + "`" + `]+`)

	var result strings.Builder
	lastIndex := 0

	for _, loc := range urlRe.FindAllStringIndex(text, -1) {
		if loc[0] > lastIndex {
			result.WriteString(html.EscapeString(text[lastIndex:loc[0]]))
		}
		rawURL := text[loc[0]:loc[1]]
		escapedURL := html.EscapeString(rawURL)
		result.WriteString(fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, escapedURL, escapedURL))
		lastIndex = loc[1]
	}

	if lastIndex < len(text) {
		result.WriteString(html.EscapeString(text[lastIndex:]))
	}

	processedText := result.String()

	processedText = strings.ReplaceAll(processedText, "\r\n", "<br>\n")
	processedText = strings.ReplaceAll(processedText, "\n", "<br>\n")

	// 【v66修复】使用配置的 charset，不再硬编码 UTF-8
	if charset == "" {
		charset = "UTF-8"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="%s">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
%s
</body>
</html>`, charset, processedText)
}

// NormalizeLineEndings 统一换行符为CRLF
func NormalizeLineEndings(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	return text
}
