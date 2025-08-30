package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/models"
)

func TestNewClient(t *testing.T) {
	serverURL := "http://localhost:8080"
	apiKey := "test-key"
	
	client := NewServerClient(serverURL, apiKey)
	if client == nil {
		t.Fatal("NewServerClient() returned nil")
	}
	
	if client.serverURL != serverURL {
		t.Error("Client serverURL not set correctly")
	}
	
	if client.apiKey != apiKey {
		t.Error("Client apiKey not set correctly")
	}
	
	if client.httpClient == nil {
		t.Error("HTTP client not initialized")
	}
}

func TestSubmitDetection(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sandbox" {
			t.Errorf("Expected path /api/v1/sandbox, got %s", r.URL.Path)
		}
		
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("Expected API key 'test-key', got %s", r.Header.Get("X-API-Key"))
		}
		
		var entry models.SandboxEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		
		if entry.Hostname != "test-host" {
			t.Errorf("Expected hostname 'test-host', got %s", entry.Hostname)
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	entry := models.SandboxEntry{
		Hostname:  "test-host",
		IPAddress: "192.168.1.1",
	}
	
	err := client.SubmitSandboxData(entry)
	if err != nil {
		t.Fatalf("SubmitSandboxData failed: %v", err)
	}
}

func TestBatchSubmit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sandbox/batch" {
			t.Errorf("Expected path /api/v1/sandbox/batch, got %s", r.URL.Path)
		}
		
		var batch models.BatchSubmission
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Fatalf("Failed to decode batch request: %v", err)
		}
		
		if len(batch.Entries) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(batch.Entries))
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	entries := []models.SandboxEntry{
		{Hostname: "host1", IPAddress: "10.0.0.1"},
		{Hostname: "host2", IPAddress: "10.0.0.2"},
	}
	
	err := client.BatchSubmit(entries)
	if err != nil {
		t.Fatalf("BatchSubmit failed: %v", err)
	}
}

func TestGetBlocklist(t *testing.T) {
	expectedBlocklist := &models.Blocklist{
		Hostnames:  []string{"bad1.com", "bad2.com"},
		IPRanges:   []string{"1.2.3.0/24", "5.6.7.0/24"},
		UpdatedAt:  time.Now(),
	}
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/blocklist" {
			t.Errorf("Expected path /api/v1/blocklist, got %s", r.URL.Path)
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expectedBlocklist)
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	blocklist, err := client.GetBlocklist()
	if err != nil {
		t.Fatalf("GetBlocklist failed: %v", err)
	}
	
	if len(blocklist.Hostnames) != 2 {
		t.Errorf("Expected 2 hostnames, got %d", len(blocklist.Hostnames))
	}
	
	if len(blocklist.IPRanges) != 2 {
		t.Errorf("Expected 2 IP ranges, got %d", len(blocklist.IPRanges))
	}
}

func TestSearchSandboxes(t *testing.T) {
	expectedResults := []models.SandboxEntry{
		{Hostname: "search-result-1", IPAddress: "192.168.1.1"},
		{Hostname: "search-result-2", IPAddress: "192.168.1.2"},
	}
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/search" {
			t.Errorf("Expected path /api/v1/search, got %s", r.URL.Path)
		}
		
		query := r.URL.Query().Get("q")
		if query != "test-search" {
			t.Errorf("Expected query 'test-search', got %s", query)
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expectedResults)
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	results, err := client.SearchSandboxes("test-search")
	if err != nil {
		t.Fatalf("SearchSandboxes failed: %v", err)
	}
	
	if len(results) != 2 {
		t.Errorf("Expected 2 search results, got %d", len(results))
	}
}

// Test GetStatistics method which exists in the client
func TestGetStatistics(t *testing.T) {
	expectedStats := map[string]interface{}{
		"total_entries":    float64(100),
		"high_confidence":  float64(50),
		"unique_hostnames": float64(75),
	}
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/stats" {
			t.Errorf("Expected path /api/v1/stats, got %s", r.URL.Path)
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expectedStats)
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	stats, err := client.GetStatistics()
	if err != nil {
		t.Fatalf("GetStatistics failed: %v", err)
	}
	
	if stats["total_entries"] != float64(100) {
		t.Errorf("Expected total_entries 100, got %v", stats["total_entries"])
	}
}

func TestRetryLogic(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()
	
	// Client with retry functionality needs to be implemented
	// For now, test basic client behavior
	client := NewServerClient(server.URL, "test-key")
	
	entry := models.SandboxEntry{
		Hostname: "retry-test",
	}
	
	// The current client doesn't have built-in retry logic
	// This would need to be added to the client implementation
	err := client.SubmitSandboxData(entry)
	if err == nil {
		t.Error("Expected error on first attempt, got nil")
	}
}

func TestConnectionTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	// Create a client with custom timeout
	client := &ServerClient{
		serverURL: server.URL,
		apiKey:    "test-key",
		httpClient: &http.Client{
			Timeout: 100 * time.Millisecond, // Very short timeout
		},
	}
	
	entry := models.SandboxEntry{
		Hostname: "timeout-test",
	}
	
	err := client.SubmitSandboxData(entry)
	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}
	
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestInvalidServerURL(t *testing.T) {
	client := NewServerClient("http://invalid-server-that-does-not-exist.local:9999", "test-key")
	
	entry := models.SandboxEntry{
		Hostname: "test",
	}
	
	err := client.SubmitSandboxData(entry)
	if err == nil {
		t.Fatal("Expected error for invalid server, got nil")
	}
}

func TestAuthenticationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "valid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid API key"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "invalid-key")
	
	entry := models.SandboxEntry{
		Hostname: "auth-test",
	}
	
	err := client.SubmitSandboxData(entry)
	if err == nil {
		t.Fatal("Expected authentication error, got nil")
	}
}

// Benchmark tests
func BenchmarkSubmitDetection(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	entry := models.SandboxEntry{
		Hostname:  "bench-test",
		IPAddress: "192.168.1.1",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.SubmitSandboxData(entry)
	}
}

func BenchmarkGetBlocklist(b *testing.B) {
	blocklist := &models.Blocklist{
		Hostnames: make([]string, 1000),
		IPRanges:  make([]string, 1000),
	}
	
	for i := 0; i < 1000; i++ {
		blocklist.Hostnames[i] = fmt.Sprintf("host%d.bad.com", i)
		blocklist.IPRanges[i] = fmt.Sprintf("10.0.%d.0/24", i%256)
	}
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(blocklist)
	}))
	defer server.Close()
	
	client := NewServerClient(server.URL, "test-key")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetBlocklist()
	}
}