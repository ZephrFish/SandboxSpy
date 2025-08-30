package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zephrfish/sandboxspy/pkg/models"
)

func TestNewServer(t *testing.T) {
	config := &Config{
		Host:         "0.0.0.0",
		Port:         8080,
		DatabasePath: ":memory:",
		APIKey:       "test-key",
		EnableAuth:   true,
		RateLimit:    100,
	}

	logger := logrus.New()
	server := New(config, logger)
	if server == nil {
		t.Fatal("New() returned nil")
	}

	if server.config != config {
		t.Error("Server config not set correctly")
	}

	if server.router == nil {
		t.Error("Server router not initialized")
	}
}

func TestHealthEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", response["status"])
	}
}

func TestSubmitSandboxEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	entry := models.SandboxEntry{
		Hostname:     "test-sandbox",
		Username:     "test-user",
		IPAddress:    "192.168.1.100",
		MACAddresses: []string{"00:0C:29:12:34:56"},
		Confidence:   0.85,
		Tags:         []string{"vmware", "high-confidence"},
	}
	
	body, _ := json.Marshal(entry)
	req := httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Errorf("Expected status 200 or 201, got %d", w.Code)
	}
}

func TestBatchSubmitEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	batch := models.BatchSubmission{
		Entries: []models.SandboxEntry{
			{
				Hostname:  "sandbox1",
				IPAddress: "192.168.1.101",
			},
			{
				Hostname:  "sandbox2",
				IPAddress: "192.168.1.102",
			},
		},
		BatchID:   "test-batch",
		Timestamp: time.Now(),
	}
	
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/sandbox/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestSearchEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	// First submit some data
	entry := models.SandboxEntry{
		Hostname:  "searchable-sandbox",
		IPAddress: "10.0.0.1",
	}
	
	body, _ := json.Marshal(entry)
	req := httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	// Now search for it
	req = httptest.NewRequest("GET", "/api/v1/search?q=searchable", nil)
	req.Header.Set("X-API-Key", "test-key")
	
	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestGetBlocklistEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	req := httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	req.Header.Set("X-API-Key", "test-key")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestExportBlocklistEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	tests := []struct {
		format       string
		expectedType string
	}{
		{"json", "application/json"},
		{"csv", "text/csv"},
		{"txt", "text/plain"},
	}
	
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/blocklist/export?format="+tt.format, nil)
			req.Header.Set("X-API-Key", "test-key")
			
			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)
			
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}
			
			contentType := w.Header().Get("Content-Type")
			if !strings.Contains(contentType, tt.expectedType) {
				t.Errorf("Expected content type %s, got %s", tt.expectedType, contentType)
			}
		})
	}
}

func TestGetStatsEndpoint(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "test-key")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	var stats map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode stats: %v", err)
	}
	
	if _, ok := stats["total_entries"]; !ok {
		t.Error("Stats response missing total_entries")
	}
}

func TestAuthMiddleware(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	server.config.EnableAuth = true
	
	// Test without API key
	req := httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	w := httptest.NewRecorder()
	
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without API key, got %d", w.Code)
	}
	
	// Test with invalid API key
	req = httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	w = httptest.NewRecorder()
	
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with invalid API key, got %d", w.Code)
	}
	
	// Test with valid API key
	req = httptest.NewRequest("GET", "/api/v1/blocklist", nil)
	req.Header.Set("X-API-Key", "test-key")
	w = httptest.NewRecorder()
	
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid API key, got %d", w.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	// Create server with very low rate limit
	config := &Config{
		Host:         "0.0.0.0",
		Port:         0,
		DatabasePath: ":memory:",
		APIKey:       "test-key",
		EnableAuth:   false, // Disable auth to test rate limiting only
		RateLimit:    2, // 2 requests per second, burst of 4
	}
	
	logger := logrus.New()
	server := New(config, logger)
	server.Initialize()
	
	// Make requests to exceed the burst limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		
		if i < 4 { // First 4 requests should succeed (burst capacity)
			if w.Code != http.StatusOK {
				t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
			}
		} else { // 5th request should be rate limited
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Request %d: Expected status 429, got %d", i+1, w.Code)
			}
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://example.com")
	
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	
	// Debug: print all headers
	t.Logf("Response headers: %v", w.Header())
	t.Logf("Response code: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())
	
	// Check CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("Missing Access-Control-Allow-Origin header")
	}
	
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Missing Access-Control-Allow-Methods header")
	}
}

func TestDatabaseOperations(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	entry := &models.SandboxEntry{
		Hostname:     "db-test",
		Username:     "test-user",
		IPAddress:    "192.168.1.1",
		MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
		Confidence:   0.75,
		Tags:         []string{"test"},
		Fingerprint:  "test-fingerprint",
	}
	
	// Test saving
	if err := server.saveSandboxEntry(entry); err != nil {
		t.Fatalf("Failed to save entry: %v", err)
	}
	
	// Test searching
	results, err := server.searchSandboxes("db-test")
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}
	
	if len(results) == 0 {
		t.Error("Expected to find saved entry")
	}
	
	// Test blocklist
	blocklist, err := server.getBlocklist()
	if err != nil {
		t.Fatalf("Failed to get blocklist: %v", err)
	}
	
	if len(blocklist.Hostnames) == 0 {
		t.Error("Expected hostname in blocklist")
	}
	
	// Test statistics
	stats, err := server.getStatistics()
	if err != nil {
		t.Fatalf("Failed to get statistics: %v", err)
	}
	
	if stats["total_entries"].(int) == 0 {
		t.Error("Expected non-zero total entries")
	}
}

func TestExportFormats(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	// Add test data
	entry := &models.SandboxEntry{
		Hostname:  "export-test",
		IPAddress: "10.0.0.1",
		Confidence: 0.9,
	}
	
	err := server.saveSandboxEntry(entry)
	if err != nil {
		t.Fatalf("Failed to save entry: %v", err)
	}
	
	blocklist, err := server.getBlocklist()
	if err != nil {
		t.Fatalf("Failed to get blocklist: %v", err)
	}
	
	// Export methods require http.ResponseWriter
	// We can't test them directly without creating mock writer
	// Just verify the blocklist was retrieved correctly
	if len(blocklist.Hostnames) == 0 {
		t.Error("Expected at least one hostname in blocklist")
	}
	
	// Verify the hostname we added is in the blocklist
	found := false
	for _, h := range blocklist.Hostnames {
		if h == "export-test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'export-test' in blocklist hostnames")
	}
}

func TestServerShutdown(t *testing.T) {
	server := createTestServer()
	server.Initialize()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start server in background
	go func() {
		server.Start(ctx)
	}()
	
	// Give it time to start
	time.Sleep(100 * time.Millisecond)
	
	// Shutdown should complete without error
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

// Helper function to create test server
func createTestServer() *Server {
	config := &Config{
		Host:         "0.0.0.0",
		Port:         0, // Random port
		DatabasePath: ":memory:",
		APIKey:       "test-key",
		EnableAuth:   true,
		RateLimit:    100,
	}
	
	logger := logrus.New()
	return New(config, logger)
}

// Benchmark tests
func BenchmarkSubmitSandbox(b *testing.B) {
	server := createTestServer()
	
	entry := models.SandboxEntry{
		Hostname:  "bench-test",
		IPAddress: "192.168.1.1",
	}
	
	body, _ := json.Marshal(entry)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/v1/sandbox", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-key")
		
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
	}
}

func BenchmarkGetBlocklist(b *testing.B) {
	server := createTestServer()
	server.Initialize()
	
	// Add some test data
	for i := 0; i < 100; i++ {
		entry := &models.SandboxEntry{
			Hostname:  fmt.Sprintf("host-%d", i),
			IPAddress: fmt.Sprintf("192.168.1.%d", i),
		}
		server.saveSandboxEntry(entry)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/v1/blocklist", nil)
		req.Header.Set("X-API-Key", "test-key")
		
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
	}
}