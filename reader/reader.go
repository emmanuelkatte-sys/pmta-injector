// Package reader 流式读取收件人数据文件（CSV / JSON / 纯文本邮箱列表）。
//
// 支持跳过行数（断点续发）、字段映射、去重与格式校验。
// ReadEmailList 专用于 CC/BCC 地址池的一次性加载。
package reader

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"__MODULE_PLACEHOLDER__/config"
)

// Recipient 收件人
type Recipient struct {
	Email        string
	Name         string
	FirstName    string
	LastName     string
	CustomFields map[string]string
	LineNumber   int
	IsBacktest   bool
}

// 【2026-05-27 从 PowerMTA 移植】ReadEmailList 流式读 cc.txt / bcc.txt
//
// 用途:
//   - dispatcher.Run 在启动时一次性加载 CC/BCC 子池(各服务器子池已由 C# 切好,通常 ≤ 100 万条)
//   - 配合 dispatcher.takeCCBatch/takeBCCBatch 通过 atomic.AddInt64 原子分配索引消费
//
// 安全防御(纵深第 2 层,见 builder.go::encodeEmailAddressWithCharset 注释):
//   - 过滤行内 CR/LF(防御外部脚本生成的污染文件,经典 SMTP 邮件头注入漏洞)
//   - 过滤 UTF-8 BOM(EmailListPersistence 已处理,这里再防一层)
//   - 跳过完全空白行
//   - 大文件保护(scanner 缓冲扩到 1MB,防止单行过长 panic)
//
// 返回: 邮箱地址列表(已 trim + 过滤), 错误(文件不存在/读取失败等)
func ReadEmailList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开邮箱列表失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 扩大缓冲区(默认 64KB,扩到 1MB)避免单行过长 panic
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	emails := make([]string, 0, 1024)
	isFirstLine := true
	const utf8BOM = "\xEF\xBB\xBF"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// 【v8.1.3 #22】过滤行内 CR/LF 防邮件头注入
		// scanner.Scan() 按 \n 分行,行内可能含 \r(纯 \r 行尾或混合行尾的污染文件)
		if strings.ContainsAny(line, "\r\n") {
			line = strings.ReplaceAll(line, "\r", " ")
			line = strings.ReplaceAll(line, "\n", " ")
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
		}
		// 【v8.1.3 #24】首行 UTF-8 BOM 过滤(C# 端已处理,这里纵深防御)
		if isFirstLine {
			line = strings.TrimPrefix(line, utf8BOM)
			line = strings.TrimSpace(line)
			isFirstLine = false
			if line == "" {
				continue
			}
		}
		emails = append(emails, line)
	}
	if err := scanner.Err(); err != nil {
		return emails, fmt.Errorf("读取邮箱列表失败: %w", err)
	}
	return emails, nil
}

// Reader 收件人读取器接口
type Reader interface {
	Read() (*Recipient, error)
	Count() (int64, error)
	Close() error
}

// New 创建读取器
func New(filePath string, cfg *config.Config) (Reader, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	format := cfg.Recipients.Format

	if format == "" {
		// 根据扩展名自动判断
		switch ext {
		case ".csv":
			format = "csv"
		case ".json":
			format = "json"
		case ".txt":
			format = "txt"
		default:
			format = "csv"
		}
	}

	switch format {
	case "csv":
		return NewCSVReader(filePath, cfg)
	case "json":
		return NewJSONReader(filePath, cfg)
	case "txt":
		return NewTXTReader(filePath)
	default:
		return nil, fmt.Errorf("不支持的文件格式: %s", format)
	}
}

// CSVReader CSV 读取器
type CSVReader struct {
	file         *os.File
	reader       *csv.Reader
	headers      []string
	headerIndex  map[string]int
	fieldMapping map[string]string
	lineNumber   int
}

// NewCSVReader 创建 CSV 读取器
func NewCSVReader(filePath string, cfg *config.Config) (*CSVReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}

	reader := csv.NewReader(file)
	
	// 设置分隔符
	if cfg.Recipients.CSV.Delimiter != "" && len(cfg.Recipients.CSV.Delimiter) > 0 {
		reader.Comma = rune(cfg.Recipients.CSV.Delimiter[0])
	}

	// 允许字段数量不一致
	reader.FieldsPerRecord = -1

	r := &CSVReader{
		file:         file,
		reader:       reader,
		headerIndex:  make(map[string]int),
		fieldMapping: cfg.Recipients.CSV.FieldMapping,
	}

	// 读取标题行
	if cfg.Recipients.CSV.HasHeader {
		headers, err := reader.Read()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("读取CSV标题行失败: %w", err)
		}
		r.headers = headers
		for i, h := range headers {
			r.headerIndex[strings.ToLower(strings.TrimSpace(h))] = i
		}
		r.lineNumber = 1
	}

	return r, nil
}

// Read 读取一行
func (r *CSVReader) Read() (*Recipient, error) {
	record, err := r.reader.Read()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	r.lineNumber++

	recipient := &Recipient{
		CustomFields: make(map[string]string),
		LineNumber:   r.lineNumber,
	}

	// 如果有标题行，使用字段名映射
	if len(r.headers) > 0 {
		for i, value := range record {
			if i >= len(r.headers) {
				break
			}
			fieldName := strings.ToLower(strings.TrimSpace(r.headers[i]))
			value = strings.TrimSpace(value)

			// 检查是否有自定义映射
			if mappedName, ok := r.fieldMapping[fieldName]; ok {
				fieldName = strings.ToLower(mappedName)
			}

			switch fieldName {
			case "email", "e-mail", "mail", "emailaddress", "email_address":
				recipient.Email = value
			case "name", "fullname", "full_name":
				recipient.Name = value
			case "firstname", "first_name", "first", "fname":
				recipient.FirstName = value
			case "lastname", "last_name", "last", "lname":
				recipient.LastName = value
			default:
				recipient.CustomFields[r.headers[i]] = value
			}
		}
	} else {
		// 没有标题行，假设第一列是邮箱
		if len(record) > 0 {
			recipient.Email = strings.TrimSpace(record[0])
		}
		if len(record) > 1 {
			recipient.Name = strings.TrimSpace(record[1])
		}
		if len(record) > 2 {
			recipient.FirstName = strings.TrimSpace(record[2])
		}
		if len(record) > 3 {
			recipient.LastName = strings.TrimSpace(record[3])
		}
		for i := 4; i < len(record); i++ {
			recipient.CustomFields[fmt.Sprintf("field%d", i-4)] = strings.TrimSpace(record[i])
		}
	}

	// 如果没有名字，尝试从 FirstName 和 LastName 组合
	if recipient.Name == "" && (recipient.FirstName != "" || recipient.LastName != "") {
		recipient.Name = strings.TrimSpace(recipient.FirstName + " " + recipient.LastName)
	}

	return recipient, nil
}

// Count 统计行数（独立统计，不影响当前读取状态）
func (r *CSVReader) Count() (int64, error) {
	// 创建新的文件句柄来统计，避免影响当前读取
	file, err := os.Open(r.file.Name())
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 设置更大的缓冲区以处理长行
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var count int64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" { // 跳过空行
			count++
		}
	}

	// 如果有标题行，减去1
	if len(r.headers) > 0 && count > 0 {
		count--
	}

	return count, scanner.Err()
}

// Close 关闭
func (r *CSVReader) Close() error {
	return r.file.Close()
}

// JSONReader JSON 读取器
type JSONReader struct {
	file       *os.File
	decoder    *json.Decoder
	lineNumber int
}

// NewJSONReader 创建 JSON 读取器
func NewJSONReader(filePath string, cfg *config.Config) (*JSONReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}

	decoder := json.NewDecoder(file)

	// 读取开始的 '['
	token, err := decoder.Token()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("解析JSON失败: %w", err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		file.Close()
		return nil, fmt.Errorf("JSON格式错误: 期望数组")
	}

	return &JSONReader{
		file:    file,
		decoder: decoder,
	}, nil
}

// Read 读取一条
func (r *JSONReader) Read() (*Recipient, error) {
	if !r.decoder.More() {
		return nil, nil
	}

	r.lineNumber++

	var data map[string]interface{}
	if err := r.decoder.Decode(&data); err != nil {
		return nil, err
	}

	recipient := &Recipient{
		CustomFields: make(map[string]string),
		LineNumber:   r.lineNumber,
	}

	for key, value := range data {
		strValue := fmt.Sprintf("%v", value)
		lowerKey := strings.ToLower(key)

		switch lowerKey {
		case "email", "e-mail", "mail":
			recipient.Email = strValue
		case "name", "fullname":
			recipient.Name = strValue
		case "firstname", "first_name":
			recipient.FirstName = strValue
		case "lastname", "last_name":
			recipient.LastName = strValue
		default:
			recipient.CustomFields[key] = strValue
		}
	}

	return recipient, nil
}

// Count 统计数量
func (r *JSONReader) Count() (int64, error) {
	// JSON 格式不方便统计，返回0
	return 0, nil
}

// Close 关闭
func (r *JSONReader) Close() error {
	return r.file.Close()
}

// TXTReader 纯文本读取器（每行一个邮箱）
type TXTReader struct {
	file       *os.File
	scanner    *bufio.Scanner
	lineNumber int
}

// NewTXTReader 创建纯文本读取器
func NewTXTReader(filePath string) (*TXTReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}

	return &TXTReader{
		file:    file,
		scanner: bufio.NewScanner(file),
	}, nil
}

// Read 读取一行
// 【修复问题8】将递归改为循环，避免大量连续空行时栈溢出
func (r *TXTReader) Read() (*Recipient, error) {
	for {
		if !r.scanner.Scan() {
			if err := r.scanner.Err(); err != nil {
				return nil, err
			}
			return nil, nil
		}

		r.lineNumber++
		email := strings.TrimSpace(r.scanner.Text())

		if email == "" {
			continue // 跳过空行，继续循环读取下一行
		}

		return &Recipient{
			Email:        email,
			CustomFields: make(map[string]string),
			LineNumber:   r.lineNumber,
		}, nil
	}
}

// Count 统计行数
func (r *TXTReader) Count() (int64, error) {
	currentPos, _ := r.file.Seek(0, io.SeekCurrent)
	r.file.Seek(0, io.SeekStart)

	scanner := bufio.NewScanner(r.file)
	var count int64
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}

	r.file.Seek(currentPos, io.SeekStart)
	return count, nil
}

// Close 关闭
func (r *TXTReader) Close() error {
	return r.file.Close()
}
