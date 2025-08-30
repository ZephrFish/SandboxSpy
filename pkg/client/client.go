package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/models"
)

// ServerClient handles communication with SandboxSpy server
type ServerClient struct {
	serverURL  string
	apiKey     string
	httpClient *http.Client
}

// NewServerClient creates a new server client
func NewServerClient(serverURL, apiKey string) *ServerClient {
	return &ServerClient{
		serverURL: serverURL,
		apiKey:    apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SubmitSandboxData sends sandbox detection data to the server
func (c *ServerClient) SubmitSandboxData(entry models.SandboxEntry) error {
	url := fmt.Sprintf("%s/api/v1/sandbox", c.serverURL)
	
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// BatchSubmit sends multiple sandbox entries at once
func (c *ServerClient) BatchSubmit(entries []models.SandboxEntry) error {
	url := fmt.Sprintf("%s/api/v1/sandbox/batch", c.serverURL)
	
	batch := models.BatchSubmission{
		Entries:   entries,
		BatchID:   generateBatchID(),
		Timestamp: time.Now().UTC(),
	}
	
	jsonData, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal batch data: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create batch request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send batch request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("batch server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// GetBlocklist retrieves the current blocklist from the server
func (c *ServerClient) GetBlocklist() (*models.Blocklist, error) {
	url := fmt.Sprintf("%s/api/v1/blocklist", c.serverURL)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocklist: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var blocklist models.Blocklist
	if err := json.NewDecoder(resp.Body).Decode(&blocklist); err != nil {
		return nil, fmt.Errorf("failed to decode blocklist: %w", err)
	}
	
	return &blocklist, nil
}

// SearchSandboxes searches for sandbox entries on the server
func (c *ServerClient) SearchSandboxes(query string) ([]models.SandboxEntry, error) {
	url := fmt.Sprintf("%s/api/v1/search?q=%s", c.serverURL, query)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var entries []models.SandboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}
	
	return entries, nil
}

// AdvancedQuery performs complex queries
func (c *ServerClient) AdvancedQuery(query models.AdvancedQuery) ([]models.SandboxEntry, error) {
	url := fmt.Sprintf("%s/api/v1/query", c.serverURL)
	
	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var entries []models.SandboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode query results: %w", err)
	}
	
	return entries, nil
}

// GetStatistics retrieves server statistics
func (c *ServerClient) GetStatistics() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/stats", c.serverURL)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}
	
	return stats, nil
}

// HealthCheck checks if the server is healthy
func (c *ServerClient) HealthCheck() error {
	url := fmt.Sprintf("%s/api/v1/health", c.serverURL)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Health check doesn't require API key
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server unhealthy: status %d", resp.StatusCode)
	}
	
	var health models.HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("failed to decode health status: %w", err)
	}
	
	if health.Status != "healthy" {
		return fmt.Errorf("server status: %s", health.Status)
	}
	
	return nil
}

// ExportBlocklist exports the blocklist in a specific format
func (c *ServerClient) ExportBlocklist(format string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/blocklist/export?format=%s", c.serverURL, format)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to export blocklist: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	return data, nil
}

// GetTimeline retrieves detection timeline
func (c *ServerClient) GetTimeline(days int) ([]models.TimelineItem, error) {
	url := fmt.Sprintf("%s/api/v1/stats/timeline?days=%d", c.serverURL, days)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get timeline: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var timeline []models.TimelineItem
	if err := json.NewDecoder(resp.Body).Decode(&timeline); err != nil {
		return nil, fmt.Errorf("failed to decode timeline: %w", err)
	}
	
	return timeline, nil
}

// GetTopIndicators retrieves top indicators
func (c *ServerClient) GetTopIndicators(limit int) (*models.Statistics, error) {
	url := fmt.Sprintf("%s/api/v1/stats/top?limit=%d", c.serverURL, limit)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	c.setHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get top indicators: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var stats models.Statistics
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode indicators: %w", err)
	}
	
	return &stats, nil
}

// setHeaders sets common headers for requests
func (c *ServerClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", "SandboxSpy-Client/1.0")
}

// generateBatchID generates a unique batch ID
func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}