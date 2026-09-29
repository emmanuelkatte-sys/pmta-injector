// Package types 定义跨模块共享的数据结构。
//
// 包括收件人、发送结果、进度快照和错误信息等，
// 供 core、reporter 和上层 CLI 统一序列化/展示。
package types

import "time"

// Recipient 收件人数据
type Recipient struct {
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	FirstName    string            `json:"first_name"`
	LastName     string            `json:"last_name"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
	Index        int               `json:"index,omitempty"`
}

// Result 发送结果
type Result struct {
	JobID       string        `json:"job_id"`
	Status      string        `json:"status"`
	Total       int64         `json:"total"`
	Success     int64         `json:"success"`
	Failed      int64         `json:"failed"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration_seconds"`
	AverageRate float64       `json:"average_rate"`
	Errors      []ErrorInfo   `json:"errors,omitempty"`
}

// ErrorInfo 错误信息
type ErrorInfo struct {
	Email string `json:"email"`
	Error string `json:"error"`
	Line  int    `json:"line"`
}

// Progress 进度信息
type Progress struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"`
	Total      int64     `json:"total"`
	Processed  int64     `json:"processed"`
	Success    int64     `json:"success"`
	Failed     int64     `json:"failed"`
	Rate       float64   `json:"rate"`
	ETASeconds int64     `json:"eta_seconds"`
	StartTime  time.Time `json:"start_time"`
	UpdateTime time.Time `json:"update_time"`
}
