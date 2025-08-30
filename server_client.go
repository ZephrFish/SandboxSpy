package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// ServerClient handles communication with SandboxSpy server
type ServerClient struct {
	serverURL string
	apiKey    string
	client    *http.Client
}

// NewServerClient creates a new server client
func NewServerClient(serverURL, apiKey string) *ServerClient {
	return &ServerClient{
		serverURL: serverURL,
		apiKey:    apiKey,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SubmitSandboxData sends sandbox detection data to the server
func (sc *ServerClient) SubmitSandboxData(entry SandboxEntry) error {
	url := fmt.Sprintf("%s/api/v1/sandbox", sc.serverURL)
	
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
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
func (sc *ServerClient) BatchSubmit(entries []SandboxEntry) error {
	url := fmt.Sprintf("%s/api/v1/sandbox/batch", sc.serverURL)
	
	payload := map[string]interface{}{
		"entries": entries,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal batch data: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create batch request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
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
func (sc *ServerClient) GetBlocklist() (*Blocklist, error) {
	url := fmt.Sprintf("%s/api/v1/blocklist", sc.serverURL)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocklist: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var blocklist Blocklist
	if err := json.NewDecoder(resp.Body).Decode(&blocklist); err != nil {
		return nil, fmt.Errorf("failed to decode blocklist: %w", err)
	}
	
	return &blocklist, nil
}

// SearchSandboxes searches for sandbox entries on the server
func (sc *ServerClient) SearchSandboxes(query string) ([]SandboxEntry, error) {
	url := fmt.Sprintf("%s/api/v1/search?q=%s", sc.serverURL, query)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var entries []SandboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}
	
	return entries, nil
}

// GetStatistics retrieves server statistics
func (sc *ServerClient) GetStatistics() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/stats", sc.serverURL)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}
	
	return stats, nil
}

// HealthCheck checks if the server is healthy
func (sc *ServerClient) HealthCheck() error {
	url := fmt.Sprintf("%s/api/v1/health", sc.serverURL)
	
	resp, err := sc.client.Get(url)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server unhealthy: status %d", resp.StatusCode)
	}
	
	return nil
}

// ExportBlocklist exports the blocklist in a specific format
func (sc *ServerClient) ExportBlocklist(format string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/blocklist/export?format=%s", sc.serverURL, format)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("X-API-Key", sc.apiKey)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to export blocklist: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	return data, nil
}