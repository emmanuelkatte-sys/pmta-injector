package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"__MODULE_PLACEHOLDER__/config"
)

// FileLogger 按 GUI「日志设置」写入发送日志与失败邮箱列表。
type FileLogger struct {
	sendFile   *os.File
	failedFile *os.File
	mu         sync.Mutex
}

// NewFileLogger 创建文件日志写入器；未启用时返回 (nil, nil)。
func NewFileLogger(cfg *config.Config) (*FileLogger, error) {
	if cfg == nil || (!cfg.Logging.SaveLog && !cfg.Logging.SaveFailed) {
		return nil, nil
	}

	dir := cfg.LogDirectoryPath()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	jobID := sanitizeLogName(cfg.Job.ID)
	if jobID == "" {
		jobID = "job"
	}

	fl := &FileLogger{}
	var err error

	if cfg.Logging.SaveLog {
		path := filepath.Join(dir, fmt.Sprintf("send-%s.log", jobID))
		fl.sendFile, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fl.Close()
			return nil, fmt.Errorf("打开发送日志失败: %w", err)
		}
	}
	if cfg.Logging.SaveFailed {
		path := filepath.Join(dir, fmt.Sprintf("failed-%s.txt", jobID))
		fl.failedFile, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fl.Close()
			return nil, fmt.Errorf("打开失败邮箱文件失败: %w", err)
		}
	}
	return fl, nil
}

func sanitizeLogName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "._")
}

// Record 记录单封邮件发送结果。
func (fl *FileLogger) Record(email string, line int, success bool, sendErr error) {
	if fl == nil {
		return
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()

	ts := time.Now().Format("2006-01-02 15:04:05")
	if fl.sendFile != nil {
		if success {
			fmt.Fprintf(fl.sendFile, "%s OK line=%d email=%s\n", ts, line, email)
		} else {
			errMsg := "unknown"
			if sendErr != nil {
				errMsg = sendErr.Error()
			}
			fmt.Fprintf(fl.sendFile, "%s FAIL line=%d email=%s err=%s\n", ts, line, email, errMsg)
		}
	}
	if !success && fl.failedFile != nil && strings.TrimSpace(email) != "" {
		fmt.Fprintln(fl.failedFile, strings.TrimSpace(email))
	}
}

// Close 关闭日志文件。
func (fl *FileLogger) Close() {
	if fl == nil {
		return
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if fl.sendFile != nil {
		fl.sendFile.Close()
		fl.sendFile = nil
	}
	if fl.failedFile != nil {
		fl.failedFile.Close()
		fl.failedFile = nil
	}
}
