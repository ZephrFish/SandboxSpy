package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/models"
)

func TestNewSecurityMiddleware(t *testing.T) {
	apiKeys := map[string]string{
		"key1": "client1",
		"key2": "client2",
	}
	
	sm := NewSecurityMiddleware(apiKeys, "cf-secret", true)
	
	if sm == nil {
		t.Fatal("NewSecurityMiddleware returned nil")
	}
	
	if sm.validator == nil {
		t.Error("Validator not initialized")
	}
	
	if sm.rateLimiter == nil {
		t.Error("Rate limiter not initialized")
	}
	
	if !sm.enableAuth {
		t.Error("Expected auth to be enabled")
	}
	
	if sm.cloudfrontSecret != "cf-secret" {
		t.Error("CloudFront secret not set correctly")
	}
}

func TestValidateAPIKey(t *testing.T) {
	apiKeys := map[string]string{
		"abcdef1234567890abcdef1234567890": "client1",
	}
	
	sm := NewSecurityMiddleware(apiKeys, "", true)
	
	tests := []struct {
		name      string
		apiKey    string
		header    bool
		query     bool
		wantValid bool
		wantID    string
	}{
		{
			name:      "Valid API key in header",
			apiKey:    "abcdef1234567890abcdef1234567890",
			header:    true,
			wantValid: true,
			wantID:    "client1",
		},
		{
			name:      "Valid API key in query",
			apiKey:    "abcdef1234567890abcdef1234567890",
			query:     true,
			wantValid: true,
			wantID:    "client1",
		},
		{
			name:      "Invalid API key",
			apiKey:    "invalid-key",
			header:    true,
			wantValid: false,
		},
		{
			name:      "No API key",
			wantValid: false,
		},
		{
			name:      "Auth disabled",
			wantValid: true,
			wantID:    "anonymous",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Auth disabled" {
				sm.enableAuth = false
			} else {
				sm.enableAuth = true
			}
			
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header {
				req.Header.Set("X-API-Key", tt.apiKey)
			}
			if tt.query {
				req.URL.RawQuery = "api_key=" + tt.apiKey
			}
			
			clientID, valid := sm.ValidateAPIKey(req)
			
			if valid != tt.wantValid {
				t.Errorf("ValidateAPIKey() valid = %v, want %v", valid, tt.wantValid)
			}
			
			if tt.wantID != "" && clientID != tt.wantID {
				t.Errorf("ValidateAPIKey() clientID = %v, want %v", clientID, tt.wantID)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	apiKeys := map[string]string{
		"abcdef1234567890abcdef1234567890": "client1",
	}
	
	sm := NewSecurityMiddleware(apiKeys, "", true)
	
	handler := sm.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.Header.Get("X-Client-ID")
		w.Write([]byte("OK: " + clientID))
	})
	
	// Test with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "abcdef1234567890abcdef1234567890")
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	if !strings.Contains(w.Body.String(), "client1") {
		t.Error("Expected client ID in response")
	}
	
	// Test with invalid API key
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "invalid-short-key")
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	// Configure very restrictive rate limit - 1 request with burst of 1
	sm.rateLimiter.AddLimiterWithBurst("default", 1, time.Minute, 1)
	
	handler := sm.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	// Use same client ID for all requests
	clientID := "test-rate-limit-client"
	
	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Client-ID", clientID)
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("First request: Expected status 200, got %d", w.Code)
	}
	
	// Second request should be rate limited
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Client-ID", clientID)
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Second request: Expected status 429, got %d", w.Code)
	}
	
	// Check rate limit headers
	if w.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Error("Expected X-RateLimit-Remaining to be 0")
	}
}

func TestValidateInputMiddleware(t *testing.T) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	handler := sm.ValidateInputMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Read validated body
		var entry models.SandboxEntry
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&entry); err != nil {
			t.Errorf("Failed to decode validated body: %v", err)
		}
		w.Write([]byte("OK"))
	})
	
	// Test with valid input
	entry := models.SandboxEntry{
		Hostname:  "test.example.com",
		Username:  "testuser",
		IPAddress: "192.168.1.1",
	}
	
	body, _ := json.Marshal(entry)
	req := httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	// Test with invalid input (SQL injection attempt)
	entry = models.SandboxEntry{
		Hostname: "test'; DROP TABLE users;--",
		Username: "testuser",
	}
	
	body, _ = json.Marshal(entry)
	req = httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid input, got %d", w.Code)
	}
	
	// Test with invalid JSON
	req = httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCloudFrontMiddleware(t *testing.T) {
	sm := NewSecurityMiddleware(nil, "secret123", false)
	
	handler := sm.CloudFrontMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	// Test with valid CloudFront secret
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-CloudFront-Secret", "secret123")
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	// Test with invalid CloudFront secret
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-CloudFront-Secret", "wrong-secret")
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
	
	// Test without CloudFront secret when required
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
	
	// Test with empty CloudFront secret (disabled)
	sm.cloudfrontSecret = ""
	
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when CloudFront disabled, got %d", w.Code)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	handler := sm.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	// Test HTTP request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	// Check security headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	
	for header, expectedValue := range expectedHeaders {
		if value := w.Header().Get(header); value != expectedValue {
			t.Errorf("Expected %s header to be %s, got %s", header, expectedValue, value)
		}
	}
	
	// Check CSP header exists
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Missing Content-Security-Policy header")
	}
	
	// Test HTTPS request (should include HSTS)
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	
	handler(w, req)
	
	if hsts := w.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("Missing HSTS header for HTTPS request")
	}
}

func TestValidateSandboxEntry(t *testing.T) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	tests := []struct {
		name    string
		entry   *models.SandboxEntry
		wantErr bool
	}{
		{
			name: "Valid entry",
			entry: &models.SandboxEntry{
				Hostname:     "test.example.com",
				Username:     "testuser",
				Domain:       "WORKGROUP",
				IPAddress:    "192.168.1.1",
				MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
				Processes:    []string{"explorer.exe"},
				FilePaths:    []string{"C:\\Windows\\System32"},
				Fingerprint:  "abc123def456",
				Tags:         []string{"test", "sandbox"},
			},
			wantErr: false,
		},
		{
			name: "Invalid hostname",
			entry: &models.SandboxEntry{
				Hostname: "test'; DROP TABLE--",
			},
			wantErr: true,
		},
		{
			name: "Invalid IP address",
			entry: &models.SandboxEntry{
				Hostname:  "test.com",
				IPAddress: "999.999.999.999",
			},
			wantErr: true,
		},
		{
			name: "Invalid MAC address",
			entry: &models.SandboxEntry{
				Hostname:     "test.com",
				MACAddresses: []string{"INVALID"},
			},
			wantErr: true,
		},
		{
			name: "Path traversal attempt",
			entry: &models.SandboxEntry{
				Hostname:  "test.com",
				FilePaths: []string{"../../../etc/passwd"},
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.ValidateSandboxEntry(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSandboxEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChain(t *testing.T) {
	// Create test middlewares that add headers
	mw1 := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Test", "MW1")
			next(w, r)
		}
	}
	
	mw2 := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Test", "MW2")
			next(w, r)
		}
	}
	
	mw3 := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Test", "MW3")
			next(w, r)
		}
	}
	
	// Chain middlewares
	chained := Chain(mw1, mw2, mw3)
	
	handler := chained(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	
	handler(w, req)
	
	// Check that all middlewares were executed in order
	headers := w.Header()["X-Test"]
	if len(headers) != 3 {
		t.Fatalf("Expected 3 headers, got %d", len(headers))
	}
	
	expectedOrder := []string{"MW1", "MW2", "MW3"}
	for i, expected := range expectedOrder {
		if headers[i] != expected {
			t.Errorf("Expected header %d to be %s, got %s", i, expected, headers[i])
		}
	}
}

// Benchmark tests
func BenchmarkAuthMiddleware(b *testing.B) {
	apiKeys := map[string]string{
		"bench-key": "bench-client",
	}
	
	sm := NewSecurityMiddleware(apiKeys, "", true)
	
	handler := sm.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "bench-key")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

func BenchmarkRateLimitMiddleware(b *testing.B) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	handler := sm.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Client-ID", "bench-client")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

func BenchmarkValidateSandboxEntry(b *testing.B) {
	sm := NewSecurityMiddleware(nil, "", false)
	
	entry := &models.SandboxEntry{
		Hostname:     "test.example.com",
		Username:     "testuser",
		Domain:       "WORKGROUP",
		IPAddress:    "192.168.1.1",
		MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
		Processes:    []string{"explorer.exe", "chrome.exe"},
		FilePaths:    []string{"C:\\Windows\\System32", "C:\\Program Files"},
		Fingerprint:  "abc123def456789",
		Tags:         []string{"test", "sandbox", "vmware"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sm.ValidateSandboxEntry(entry)
	}
}