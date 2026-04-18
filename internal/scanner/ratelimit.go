package scanner

import (
	"sync"
	"sync/atomic"
	"time"
)

type AdaptiveLimiter struct {
	mu          sync.Mutex
	tokens      float64
	maxTokens   float64
	refillRate  float64 
	baseRate    float64
	lastRefill  time.Time
	lastPenalty time.Time

	// stats
	throttleCount int64
}

func NewAdaptiveLimiter(maxRPS int) *AdaptiveLimiter {
	if maxRPS <= 0 {
		return &AdaptiveLimiter{} 
	}
	rate := float64(maxRPS)
	return &AdaptiveLimiter{
		tokens:     rate,
		maxTokens:  rate,
		refillRate: rate,
		baseRate:   rate,
		lastRefill: time.Now(),
	}
}

func (l *AdaptiveLimiter) Wait() {
	if l.refillRate == 0 && l.maxTokens == 0 {
		return // unlimited
	}
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.lastRefill).Seconds()
		l.tokens += elapsed * l.refillRate
		if l.tokens > l.maxTokens {
			l.tokens = l.maxTokens
		}
		l.lastRefill = now

		if now.Sub(l.lastPenalty) > 30*time.Second && l.refillRate < l.baseRate {
			l.refillRate *= 1.1
			if l.refillRate > l.baseRate {
				l.refillRate = l.baseRate
			}
			l.lastPenalty = now
		}

		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return
		}

		need := 1 - l.tokens
		sleepSec := need / l.refillRate
		l.mu.Unlock()

		time.Sleep(time.Duration(sleepSec*1000) * time.Millisecond)
	}
}

func (l *AdaptiveLimiter) Penalize() {
	if l.maxTokens == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillRate *= 0.5
	if l.refillRate < 1 {
		l.refillRate = 1
	}
	l.lastPenalty = time.Now()
	atomic.AddInt64(&l.throttleCount, 1)
}

func (l *AdaptiveLimiter) CurrentRate() float64 {
	if l == nil || l.maxTokens == 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refillRate
}

func (l *AdaptiveLimiter) ThrottleCount() int64 {
	return atomic.LoadInt64(&l.throttleCount)
}
