package security

import (
	"fmt"
	"sync"
	"time"
)

// RateLimiter implements per-key rate limiting
type RateLimiter struct {
	mu        sync.RWMutex
	limits    map[string]*limit
	rate      int           // requests per interval
	interval  time.Duration // time interval
	burstSize int           // maximum burst size
	cleanup   time.Duration // cleanup interval for expired entries
}

// limit tracks the rate limit state for a single key
type limit struct {
	tokens    int
	lastReset time.Time
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limits:    make(map[string]*limit),
		rate:      rate,
		interval:  interval,
		burstSize: rate * 2, // Allow burst of 2x the rate
		cleanup:   interval * 10,
	}
	
	// Start cleanup goroutine
	go rl.cleanupLoop()
	
	return rl
}

// NewRateLimiterWithBurst creates a rate limiter with custom burst size
func NewRateLimiterWithBurst(rate int, interval time.Duration, burstSize int) *RateLimiter {
	rl := &RateLimiter{
		limits:    make(map[string]*limit),
		rate:      rate,
		interval:  interval,
		burstSize: burstSize,
		cleanup:   interval * 10,
	}
	
	// Start cleanup goroutine
	go rl.cleanupLoop()
	
	return rl
}

// Allow checks if a request is allowed for the given key
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.RLock()
	l, exists := rl.limits[key]
	rl.mu.RUnlock()
	
	if !exists {
		rl.mu.Lock()
		l = &limit{
			tokens:    rl.rate,
			lastReset: time.Now(),
		}
		rl.limits[key] = l
		rl.mu.Unlock()
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	now := time.Now()
	
	// Reset tokens if interval has passed
	if now.Sub(l.lastReset) >= rl.interval {
		l.tokens = rl.rate
		l.lastReset = now
	}
	
	// Check if we have tokens available
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	
	return false
}

// AllowN checks if n requests are allowed for the given key
func (rl *RateLimiter) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	
	if n > rl.burstSize {
		return false // Request exceeds maximum burst size
	}
	
	rl.mu.RLock()
	l, exists := rl.limits[key]
	rl.mu.RUnlock()
	
	if !exists {
		rl.mu.Lock()
		l = &limit{
			tokens:    rl.rate,
			lastReset: time.Now(),
		}
		rl.limits[key] = l
		rl.mu.Unlock()
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	now := time.Now()
	
	// Reset tokens if interval has passed
	if now.Sub(l.lastReset) >= rl.interval {
		l.tokens = rl.rate
		l.lastReset = now
	}
	
	// Check if we have enough tokens
	if l.tokens >= n {
		l.tokens -= n
		return true
	}
	
	return false
}

// AllowBurst checks if a request is allowed with burst capacity
func (rl *RateLimiter) AllowBurst(key string) bool {
	rl.mu.RLock()
	l, exists := rl.limits[key]
	rl.mu.RUnlock()
	
	if !exists {
		rl.mu.Lock()
		l = &limit{
			tokens:    rl.burstSize,
			lastReset: time.Now(),
		}
		rl.limits[key] = l
		rl.mu.Unlock()
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(l.lastReset)
	
	// Calculate tokens to add based on elapsed time
	tokensToAdd := int(elapsed.Seconds() / rl.interval.Seconds() * float64(rl.rate))
	if tokensToAdd > 0 {
		l.tokens += tokensToAdd
		if l.tokens > rl.burstSize {
			l.tokens = rl.burstSize
		}
		l.lastReset = now
	}
	
	// Check if we have tokens available
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	
	return false
}

// Reset resets the rate limit for a specific key
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	delete(rl.limits, key)
}

// ResetAll resets all rate limits
func (rl *RateLimiter) ResetAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.limits = make(map[string]*limit)
}

// GetRemaining returns the remaining tokens for a key
func (rl *RateLimiter) GetRemaining(key string) int {
	rl.mu.RLock()
	l, exists := rl.limits[key]
	rl.mu.RUnlock()
	
	if !exists {
		return rl.rate
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	now := time.Now()
	
	// Reset tokens if interval has passed
	if now.Sub(l.lastReset) >= rl.interval {
		l.tokens = rl.rate
		l.lastReset = now
	}
	
	return l.tokens
}

// GetResetTime returns when the rate limit will reset for a key
func (rl *RateLimiter) GetResetTime(key string) time.Time {
	rl.mu.RLock()
	l, exists := rl.limits[key]
	rl.mu.RUnlock()
	
	if !exists {
		return time.Now().Add(rl.interval)
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	return l.lastReset.Add(rl.interval)
}

// cleanupLoop periodically removes expired entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.cleanupExpired()
	}
}

// cleanupExpired removes expired entries
func (rl *RateLimiter) cleanupExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	expiry := rl.interval * 10 // Keep entries for 10x the interval
	
	for key, l := range rl.limits {
		l.mu.Lock()
		if now.Sub(l.lastReset) > expiry {
			delete(rl.limits, key)
		}
		l.mu.Unlock()
	}
}

// MultiKeyRateLimiter manages multiple rate limiters with different configurations
type MultiKeyRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
}

// NewMultiKeyRateLimiter creates a new multi-key rate limiter
func NewMultiKeyRateLimiter() *MultiKeyRateLimiter {
	return &MultiKeyRateLimiter{
		limiters: make(map[string]*RateLimiter),
	}
}

// AddLimiter adds a rate limiter for a specific API key pattern
func (m *MultiKeyRateLimiter) AddLimiter(pattern string, rate int, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.limiters[pattern] = NewRateLimiter(rate, interval)
}

// AddLimiterWithBurst adds a rate limiter with burst capacity
func (m *MultiKeyRateLimiter) AddLimiterWithBurst(pattern string, rate int, interval time.Duration, burst int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.limiters[pattern] = NewRateLimiterWithBurst(rate, interval, burst)
}

// GetLimiter returns the rate limiter for a pattern
func (m *MultiKeyRateLimiter) GetLimiter(pattern string) (*RateLimiter, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	limiter, exists := m.limiters[pattern]
	if !exists {
		return nil, fmt.Errorf("no rate limiter found for pattern: %s", pattern)
	}
	
	return limiter, nil
}

// Allow checks if a request is allowed for the given pattern and key
func (m *MultiKeyRateLimiter) Allow(pattern, key string) (bool, error) {
	limiter, err := m.GetLimiter(pattern)
	if err != nil {
		return false, err
	}
	
	return limiter.Allow(key), nil
}