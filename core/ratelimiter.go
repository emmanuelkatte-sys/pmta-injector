package core

import (
	"context"
	"sync"
	"time"
)

// RateLimiter 令牌桶式速率限制器；rate=0 时 NewRateLimiter 返回 nil，调用方无需额外判断。
type RateLimiter struct {
	rate     int           // 每秒允许的数量
	tokens   int           // 当前令牌数
	maxBurst int           // 最大突发数
	interval time.Duration // 补充间隔
	mu       sync.Mutex
	lastTime time.Time
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		return nil
	}

	// 计算补充间隔，使用更细的粒度
	interval := time.Second / time.Duration(ratePerSecond)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}

	maxBurst := ratePerSecond / 10
	if maxBurst < 10 {
		maxBurst = 10
	}
	if maxBurst > 1000 {
		maxBurst = 1000
	}

	return &RateLimiter{
		rate:     ratePerSecond,
		tokens:   maxBurst,
		maxBurst: maxBurst,
		interval: interval,
		lastTime: time.Now(),
	}
}

// Wait 等待获取令牌
func (r *RateLimiter) Wait(ctx context.Context) {
	if r == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		r.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(r.lastTime)

		// 计算应该补充的令牌数
		newTokens := int(elapsed.Seconds() * float64(r.rate))
		if newTokens > 0 {
			r.tokens += newTokens
			if r.tokens > r.maxBurst {
				r.tokens = r.maxBurst
			}
			r.lastTime = now
		}

		if r.tokens > 0 {
			r.tokens--
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()

		// 等待一小段时间后重试
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.interval):
		}
	}
}

// Allow 非阻塞检查是否允许
func (r *RateLimiter) Allow() bool {
	if r == nil {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastTime)

	newTokens := int(elapsed.Seconds() * float64(r.rate))
	if newTokens > 0 {
		r.tokens += newTokens
		if r.tokens > r.maxBurst {
			r.tokens = r.maxBurst
		}
		r.lastTime = now
	}

	if r.tokens > 0 {
		r.tokens--
		return true
	}

	return false
}
