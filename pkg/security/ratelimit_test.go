package security

import (
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	
	if rl.rate != 10 {
		t.Errorf("Expected rate to be 10, got %d", rl.rate)
	}
	
	if rl.interval != time.Second {
		t.Errorf("Expected interval to be 1s, got %v", rl.interval)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)
	key := "test-key"
	
	// First 3 requests should succeed
	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
	
	// 4th request should fail
	if rl.Allow(key) {
		t.Error("4th request should be denied")
	}
}

func TestRateLimiterAllowN(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	key := "test-key"
	
	// Request 5 tokens at once
	if !rl.AllowN(key, 5) {
		t.Error("Should allow 5 tokens")
	}
	
	// Request another 5 tokens
	if !rl.AllowN(key, 5) {
		t.Error("Should allow another 5 tokens")
	}
	
	// Request 1 more should fail
	if rl.AllowN(key, 1) {
		t.Error("Should not allow 11th token")
	}
	
	// Request 0 should always succeed
	if !rl.AllowN(key, 0) {
		t.Error("Should always allow 0 tokens")
	}
}

func TestRateLimiterAllowBurst(t *testing.T) {
	rl := NewRateLimiterWithBurst(10, time.Second, 20)
	key := "test-key"
	
	// Should allow up to burst size initially
	for i := 0; i < 20; i++ {
		if !rl.AllowBurst(key) {
			t.Errorf("Request %d should be allowed (within burst)", i+1)
		}
	}
	
	// 21st request should fail
	if rl.AllowBurst(key) {
		t.Error("21st request should be denied (exceeds burst)")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)
	key := "test-key"
	
	// Use up all tokens
	for i := 0; i < 3; i++ {
		rl.Allow(key)
	}
	
	// Should be denied
	if rl.Allow(key) {
		t.Error("Should be denied after exhausting tokens")
	}
	
	// Reset the key
	rl.Reset(key)
	
	// Should be allowed again
	if !rl.Allow(key) {
		t.Error("Should be allowed after reset")
	}
}

func TestRateLimiterResetAll(t *testing.T) {
	rl := NewRateLimiter(1, time.Second)
	
	// Use tokens for multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, key := range keys {
		rl.Allow(key)
		if rl.Allow(key) {
			t.Errorf("Second request for %s should be denied", key)
		}
	}
	
	// Reset all
	rl.ResetAll()
	
	// All keys should be allowed again
	for _, key := range keys {
		if !rl.Allow(key) {
			t.Errorf("Should be allowed after ResetAll for %s", key)
		}
	}
}

func TestRateLimiterGetRemaining(t *testing.T) {
	rl := NewRateLimiter(5, time.Second)
	key := "test-key"
	
	// Initially should have full rate
	if remaining := rl.GetRemaining(key); remaining != 5 {
		t.Errorf("Expected 5 remaining, got %d", remaining)
	}
	
	// Use 2 tokens
	rl.Allow(key)
	rl.Allow(key)
	
	if remaining := rl.GetRemaining(key); remaining != 3 {
		t.Errorf("Expected 3 remaining, got %d", remaining)
	}
}

func TestRateLimiterGetResetTime(t *testing.T) {
	rl := NewRateLimiter(5, time.Second)
	key := "test-key"
	
	now := time.Now()
	resetTime := rl.GetResetTime(key)
	
	// Reset time should be approximately 1 second in the future
	diff := resetTime.Sub(now)
	if diff < 900*time.Millisecond || diff > 1100*time.Millisecond {
		t.Errorf("Reset time should be ~1s in future, got %v", diff)
	}
}

func TestRateLimiterTokenRefresh(t *testing.T) {
	rl := NewRateLimiter(2, 100*time.Millisecond)
	key := "test-key"
	
	// Use all tokens
	rl.Allow(key)
	rl.Allow(key)
	
	// Should be denied
	if rl.Allow(key) {
		t.Error("Should be denied after exhausting tokens")
	}
	
	// Wait for refresh
	time.Sleep(150 * time.Millisecond)
	
	// Should be allowed again
	if !rl.Allow(key) {
		t.Error("Should be allowed after interval refresh")
	}
}

func TestRateLimiterConcurrency(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)
	key := "test-key"
	
	var wg sync.WaitGroup
	allowed := 0
	var mu sync.Mutex
	
	// Start 200 concurrent requests
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow(key) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	
	wg.Wait()
	
	// Should allow exactly 100
	if allowed != 100 {
		t.Errorf("Expected 100 allowed requests, got %d", allowed)
	}
}

func TestMultiKeyRateLimiter(t *testing.T) {
	m := NewMultiKeyRateLimiter()
	
	// Add different rate limiters
	m.AddLimiter("default", 10, time.Second)
	m.AddLimiterWithBurst("premium", 100, time.Second, 200)
	
	// Test default limiter
	allowed, err := m.Allow("default", "user1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("First request should be allowed")
	}
	
	// Test premium limiter
	allowed, err = m.Allow("premium", "user2")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Premium request should be allowed")
	}
	
	// Test non-existent limiter
	_, err = m.Allow("nonexistent", "user3")
	if err == nil {
		t.Error("Expected error for non-existent limiter")
	}
}

func TestMultiKeyRateLimiterGetLimiter(t *testing.T) {
	m := NewMultiKeyRateLimiter()
	m.AddLimiter("test", 5, time.Second)
	
	limiter, err := m.GetLimiter("test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if limiter == nil {
		t.Error("Expected limiter, got nil")
	}
	
	_, err = m.GetLimiter("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent limiter")
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	rl := NewRateLimiter(1000000, time.Second) // High rate to avoid limiting
	key := "bench-key"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(key)
	}
}

func BenchmarkRateLimiterConcurrent(b *testing.B) {
	rl := NewRateLimiter(1000000, time.Second) // High rate to avoid limiting
	key := "bench-key"
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(key)
		}
	})
}