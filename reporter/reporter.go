// Package reporter 负责将发送进度和最终结果持久化到磁盘。
//
// 进度文件采用「写临时文件 + 原子 rename」策略，避免外部进程读到半写入的 JSON。
// 典型输出：progress.json（实时）、result.json（任务结束）、errors.json（失败明细）。
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/types"
)

// Reporter 报告器
type Reporter struct {
	cfg          *config.Config
	progressFile string
	resultFile   string
	errorFile    string
	mu           sync.Mutex
}

// New 创建报告器
func New(cfg *config.Config) *Reporter {
	// 确保目录存在
	if cfg.Output.ProgressFile != "" {
		os.MkdirAll(filepath.Dir(cfg.Output.ProgressFile), 0755)
	}
	if cfg.Output.ResultFile != "" {
		os.MkdirAll(filepath.Dir(cfg.Output.ResultFile), 0755)
	}
	if cfg.Output.ErrorFile != "" {
		os.MkdirAll(filepath.Dir(cfg.Output.ErrorFile), 0755)
	}

	return &Reporter{
		cfg:          cfg,
		progressFile: cfg.Output.ProgressFile,
		resultFile:   cfg.Output.ResultFile,
		errorFile:    cfg.Output.ErrorFile,
	}
}

// UpdateProgress 更新进度
func (r *Reporter) UpdateProgress(progress *types.Progress) error {
	if r.progressFile == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化进度失败: %w", err)
	}

	// 原子写入：先写临时文件，再重命名
	tempFile := r.progressFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("写入进度文件失败: %w", err)
	}

	if err := os.Rename(tempFile, r.progressFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("移动进度文件失败: %w", err)
	}

	return nil
}

// SaveResult 保存结果
func (r *Reporter) SaveResult(result *types.Result) error {
	if r.resultFile == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 转换为可序列化的格式
	output := struct {
		JobID           string            `json:"job_id"`
		Status          string            `json:"status"`
		Total           int64             `json:"total"`
		Success         int64             `json:"success"`
		Failed          int64             `json:"failed"`
		StartTime       string            `json:"start_time"`
		EndTime         string            `json:"end_time"`
		DurationSeconds float64           `json:"duration_seconds"`
		AverageRate     float64           `json:"average_rate"`
		Errors          []types.ErrorInfo `json:"errors,omitempty"`
	}{
		JobID:           result.JobID,
		Status:          result.Status,
		Total:           result.Total,
		Success:         result.Success,
		Failed:          result.Failed,
		StartTime:       result.StartTime.Format(time.RFC3339),
		EndTime:         result.EndTime.Format(time.RFC3339),
		DurationSeconds: result.Duration.Seconds(),
		AverageRate:     result.AverageRate,
		Errors:          result.Errors,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化结果失败: %w", err)
	}

	// 原子写入
	tempFile := r.resultFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("写入结果文件失败: %w", err)
	}

	if err := os.Rename(tempFile, r.resultFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("移动结果文件失败: %w", err)
	}

	// 如果有错误，保存到错误文件
	if len(result.Errors) > 0 && r.errorFile != "" {
		r.saveErrors(result.Errors)
	}

	return nil
}

// saveErrors 保存错误到文件
func (r *Reporter) saveErrors(errors []types.ErrorInfo) error {
	file, err := os.Create(r.errorFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, e := range errors {
		fmt.Fprintf(file, "Line %d: %s - %s\n", e.Line, e.Email, e.Error)
	}

	return nil
}

// GetProgressFile 获取进度文件路径
func (r *Reporter) GetProgressFile() string {
	return r.progressFile
}

// GetResultFile 获取结果文件路径
func (r *Reporter) GetResultFile() string {
	return r.resultFile
}
