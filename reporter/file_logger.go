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

// FileLogger 按 GUI「日志设置」写入发送日志与成功/失败邮箱列表。
type FileLogger struct {
	sendFile    *os.File
	successFile *os.File
	failedFile  *os.File
	dir         string
	mu          sync.Mutex
}

// NewFileLogger 创建文件日志写入器；确保实时记录 success.txt 和 failed.txt。
func NewFileLogger(cfg *config.Config) (*FileLogger, error) {
	if cfg == nil {
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

	fl := &FileLogger{dir: dir}
	var err error

	// 1. 发送详细日志 (send-job.log 以及统合 send.log)
	sendPath := filepath.Join(dir, fmt.Sprintf("send-%s.log", jobID))
	fl.sendFile, err = os.OpenFile(sendPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fl.Close()
		return nil, fmt.Errorf("打开发送日志失败: %w", err)
	}

	// 2. 成功邮箱记录 (success-job.txt 以及统合 success.txt)
	successPath := filepath.Join(dir, fmt.Sprintf("success-%s.txt", jobID))
	fl.successFile, err = os.OpenFile(successPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fl.Close()
		return nil, fmt.Errorf("打开成功邮箱文件失败: %w", err)
	}

	// 3. 失败邮箱记录 (failed-job.txt 以及统合 failed.txt)
	failedPath := filepath.Join(dir, fmt.Sprintf("failed-%s.txt", jobID))
	fl.failedFile, err = os.OpenFile(failedPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fl.Close()
		return nil, fmt.Errorf("打开失败邮箱文件失败: %w", err)
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

func appendSingleLine(path, line string) {
	if path == "" || line == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()
		fmt.Fprintln(f, line)
	}
}

// Record 记录单封邮件发送结果。
func (fl *FileLogger) Record(email string, line int, success bool, sendErr error) {
	if fl == nil {
		return
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()

	cleanEmail := strings.TrimSpace(email)
	ts := time.Now().Format("2006-01-02 15:04:05")

	if fl.sendFile != nil {
		if success {
			logLine := fmt.Sprintf("%s OK line=%d email=%s\n", ts, line, cleanEmail)
			fl.sendFile.WriteString(logLine)
			appendSingleLine(filepath.Join(fl.dir, "send.log"), strings.TrimRight(logLine, "\n"))
		} else {
			errMsg := "unknown"
			if sendErr != nil {
				errMsg = sendErr.Error()
			}
			logLine := fmt.Sprintf("%s FAIL line=%d email=%s err=%s\n", ts, line, cleanEmail, errMsg)
			fl.sendFile.WriteString(logLine)
			appendSingleLine(filepath.Join(fl.dir, "send.log"), strings.TrimRight(logLine, "\n"))
		}
	}

	if success && cleanEmail != "" {
		if fl.successFile != nil {
			fmt.Fprintln(fl.successFile, cleanEmail)
		}
		appendSingleLine(filepath.Join(fl.dir, "success.txt"), cleanEmail)
		appendSingleLine(filepath.Join(fl.dir, "success_emails.txt"), cleanEmail)
	} else if !success && cleanEmail != "" {
		if fl.failedFile != nil {
			fmt.Fprintln(fl.failedFile, cleanEmail)
		}
		appendSingleLine(filepath.Join(fl.dir, "failed.txt"), cleanEmail)
		appendSingleLine(filepath.Join(fl.dir, "failed_emails.txt"), cleanEmail)
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
	if fl.successFile != nil {
		fl.successFile.Close()
		fl.successFile = nil
	}
	if fl.failedFile != nil {
		fl.failedFile.Close()
		fl.failedFile = nil
	}
}
