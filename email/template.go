package email

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"__MODULE_PLACEHOLDER__/utils"
)

// TemplateData 模板数据
type TemplateData struct {
	// 收件人数据
	Email     string
	Name      string
	FirstName string
	LastName  string
	Data      map[string]string // 自定义字段

	// 全局变量
	Global map[string]interface{}

	// 系统变量
	System struct {
		Date      string
		DateTime  string
		Timestamp int64
		Year      int
		UUID      string
		JobID     string
		MessageID string
		Index     int
		Honorific string
	}

	// 计算变量
	Computed struct {
		UnsubscribeURL string
		TrackingPixel  string
		Greeting       string
		EmailHash      string
	}
}

// NewTemplateData 创建模板数据
func NewTemplateData() *TemplateData {
	now := time.Now()
	return &TemplateData{
		Data:   make(map[string]string),
		Global: make(map[string]interface{}),
		System: struct {
			Date      string
			DateTime  string
			Timestamp int64
			Year      int
			UUID      string
			JobID     string
			MessageID string
			Index     int
			Honorific string
		}{
			Date:      now.Format("2006-01-02"),
			DateTime:  now.Format("2006-01-02 15:04:05"),
			Timestamp: now.Unix(),
			Year:      now.Year(),
			UUID:      utils.GenerateUUID(),
		},
	}
}

// TemplateEngine 模板引擎
type TemplateEngine struct {
	tmpl            *template.Template
	rawContent      string
	globalVariables map[string]interface{}

	// 【修复问题7】字符串模板缓存：相同字符串只解析一次
	stringCache map[string]*template.Template

	// 【修复问题13】文件模板缓存：相同文件路径只读取+解析一次
	fileCache map[string]*template.Template
}

// NewTemplateEngine 创建模板引擎
func NewTemplateEngine(templatePath string) (*TemplateEngine, error) {
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %w", err)
	}

	// 创建模板函数映射
	funcMap := createFuncMap()

	// 解析模板
	tmpl, err := template.New("email").Funcs(funcMap).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("解析模板失败: %w", err)
	}

	return &TemplateEngine{
		tmpl:            tmpl,
		rawContent:      string(content),
		globalVariables: make(map[string]interface{}),
		stringCache:     make(map[string]*template.Template),
		fileCache:       make(map[string]*template.Template),
	}, nil
}

// SetGlobalVariables 设置全局变量
func (e *TemplateEngine) SetGlobalVariables(vars map[string]interface{}) {
	e.globalVariables = vars
}

// Render 渲染主模板
func (e *TemplateEngine) Render(data *TemplateData) (string, error) {
	// 合并全局变量
	e.mergeGlobalVars(data)

	var buf bytes.Buffer
	if err := e.tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染模板失败: %w", err)
	}

	return buf.String(), nil
}

// RenderString 渲染字符串模板
// 【修复问题7】使用缓存，相同字符串只 Parse 一次
func (e *TemplateEngine) RenderString(text string, data *TemplateData) (string, error) {
	// 从缓存中查找
	tmpl, ok := e.stringCache[text]
	if !ok {
		// 首次遇到，解析并缓存
		funcMap := createFuncMap()
		var err error
		tmpl, err = template.New("string").Funcs(funcMap).Parse(text)
		if err != nil {
			return text, err
		}
		e.stringCache[text] = tmpl
	}

	// 合并全局变量
	e.mergeGlobalVars(data)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return text, err
	}

	return buf.String(), nil
}

// RenderFile 渲染指定文件的模板
// 【修复问题13】使用缓存，相同文件只读取+解析一次
func (e *TemplateEngine) RenderFile(templatePath string, data *TemplateData) (string, error) {
	// 从缓存中查找
	tmpl, ok := e.fileCache[templatePath]
	if !ok {
		// 首次遇到，读取文件并解析
		content, err := os.ReadFile(templatePath)
		if err != nil {
			return "", fmt.Errorf("读取模板文件失败: %w", err)
		}

		funcMap := createFuncMap()
		tmpl, err = template.New("file").Funcs(funcMap).Parse(string(content))
		if err != nil {
			return "", fmt.Errorf("解析模板失败: %w", err)
		}
		e.fileCache[templatePath] = tmpl
	}

	// 合并全局变量
	e.mergeGlobalVars(data)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("渲染模板失败: %w", err)
	}

	return buf.String(), nil
}

// mergeGlobalVars 合并全局变量到模板数据
func (e *TemplateEngine) mergeGlobalVars(data *TemplateData) {
	for k, v := range e.globalVariables {
		if data.Global == nil {
			data.Global = make(map[string]interface{})
		}
		data.Global[k] = v
	}
}

// createFuncMap 创建模板函数映射
func createFuncMap() template.FuncMap {
	return template.FuncMap{
		// 字符串处理
		"upper":    strings.ToUpper,
		"lower":    strings.ToLower,
		"title":    strings.Title,
		"trim":     strings.TrimSpace,
		"replace":  strings.ReplaceAll,
		"contains": strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,

		// 默认值
		"default": func(def, val interface{}) interface{} {
			if val == nil || val == "" {
				return def
			}
			return val
		},
		"or": func(vals ...interface{}) interface{} {
			for _, v := range vals {
				if v != nil && v != "" && v != 0 && v != false {
					return v
				}
			}
			return nil
		},

		// 截断
		"truncate": func(s string, length int) string {
			if len(s) <= length {
				return s
			}
			return s[:length]
		},

		// URL 编码
		"urlEncode": utils.URLEncode,
		"urlDecode": utils.URLDecode,

		// Base64 编码
		"base64Encode": utils.Base64Encode,
		"base64Decode": utils.Base64Decode,

		// 哈希
		"md5":    utils.MD5Hash,
		"sha256": utils.SHA256Hash,

		// 日期格式化
		"formatDate": func(t interface{}, layout string) string {
			switch v := t.(type) {
			case time.Time:
				return v.Format(layout)
			case string:
				if parsed, err := time.Parse(time.RFC3339, v); err == nil {
					return parsed.Format(layout)
				}
				return v
			default:
				return fmt.Sprintf("%v", t)
			}
		},
		"now": time.Now,

		// HTML 相关
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"safeCSS": func(s string) template.CSS {
			return template.CSS(s)
		},
		"safeJS": func(s string) template.JS {
			return template.JS(s)
		},
		"safeURL": func(s string) template.URL {
			return template.URL(s)
		},

		// 数学运算
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"mod": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a % b
		},

		// 条件
		"eq": func(a, b interface{}) bool { return a == b },
		"ne": func(a, b interface{}) bool { return a != b },
		"lt": func(a, b int) bool { return a < b },
		"le": func(a, b int) bool { return a <= b },
		"gt": func(a, b int) bool { return a > b },
		"ge": func(a, b int) bool { return a >= b },

		// 问候语
		"greeting": func() string {
			hour := time.Now().Hour()
			if hour < 12 {
				return "Good morning"
			} else if hour < 18 {
				return "Good afternoon"
			}
			return "Good evening"
		},

		// JSON
		"toJSON": utils.ToJSON,
	}
}
