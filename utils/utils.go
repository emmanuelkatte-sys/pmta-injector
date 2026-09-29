// Package utils 提供邮件构建与模板渲染常用的辅助函数。
//
// 涵盖 ID/Message-ID 生成、哈希、Base64/URL 编解码、
// JSON 序列化和文件存在性检查等通用工具。
package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateUUID 生成 UUID
func GenerateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GenerateShortID 生成短 ID
func GenerateShortID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateMessageID 生成邮件 Message-ID
func GenerateMessageID(domain string) string {
	timestamp := time.Now().UnixNano()
	random := GenerateShortID()
	
	// 提取域名
	if idx := strings.Index(domain, "@"); idx != -1 {
		domain = domain[idx+1:]
	}
	
	return fmt.Sprintf("%d.%s@%s", timestamp, random, domain)
}

// GenerateNaturalClientMessageID 生成 Postfix/客户端风格 Message-ID（UTC 紧凑时间 + pid + 随机 hex）。
func GenerateNaturalClientMessageID(domain string) string {
	if idx := strings.Index(domain, "@"); idx != -1 {
		domain = domain[idx+1:]
	}
	domain = strings.TrimSpace(domain)
	now := time.Now().UTC()
	millis := now.Nanosecond() / 1e6
	pid := os.Getpid()
	if pid <= 0 {
		pid = 1
	}
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		randBytes = []byte{0, 0, 0, 0}
	}
	return fmt.Sprintf("%s.%03d.%d.%s@%s",
		now.Format("20060102150405"),
		millis,
		pid,
		hex.EncodeToString(randBytes),
		domain,
	)
}

// MD5Hash 计算 MD5 哈希
func MD5Hash(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

// SHA256Hash 计算 SHA256 哈希
func SHA256Hash(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// Base64Encode Base64 编码
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64Decode Base64 解码
func Base64Decode(s string) string {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(data)
}

// URLEncode URL 编码
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// URLDecode URL 解码
func URLDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// ToJSON 转换为 JSON 字符串
func ToJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// Truncate 截断字符串
func Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

// SafeString 安全获取字符串，避免 nil
func SafeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// CoalesceString 返回第一个非空字符串
func CoalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ReadFile 读取文件内容
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// GetFileName 获取文件名（不含路径）
func GetFileName(path string) string {
	return filepath.Base(path)
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
