package core

import (
	"math/rand"
	"time"

	"__MODULE_PLACEHOLDER__/config"
)

// sendDelay returns a uniform-random pause between min/max interval (ms).
// Both zero → no delay.
func sendDelay(minMs, maxMs int, rng *rand.Rand) time.Duration {
	if minMs <= 0 && maxMs <= 0 {
		return 0
	}
	if maxMs <= 0 {
		maxMs = minMs
	}
	if minMs <= 0 {
		minMs = maxMs
	}
	if minMs > maxMs {
		minMs, maxMs = maxMs, minMs
	}
	if minMs == maxMs {
		return time.Duration(minMs) * time.Millisecond
	}
	span := maxMs - minMs + 1
	return time.Duration(minMs+rng.Intn(span)) * time.Millisecond
}

func performanceSendDelay(cfg *config.Config, rng *rand.Rand) time.Duration {
	if cfg == nil {
		return 0
	}
	p := cfg.Performance.NormalizedIntervals()
	return sendDelay(p.MinInterval, p.MaxInterval, rng)
}
