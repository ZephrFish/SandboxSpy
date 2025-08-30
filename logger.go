package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// SandboxData represents the data collected from a potential sandbox
type SandboxData struct {
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	Domain        string    `json:"domain"`
	IPAddress     string    `json:"ip_address,omitempty"`
	MACAddresses  []string  `json:"mac_addresses,omitempty"`
	FilePaths     []string  `json:"file_paths,omitempty"`
	ProcessCount  int       `json:"process_count,omitempty"`
	CPUCores      int       `json:"cpu_cores,omitempty"`
	TempFileCount int       `json:"temp_file_count,omitempty"`
	UTCOffset     int       `json:"utc_offset,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Hash          string    `json:"hash"`
}

// CentralLogger handles sending sandbox data to a central logging server
type CentralLogger struct {
	endpoint   string
	apiKey     string
	client     *http.Client
	queue      []SandboxData
	mu         sync.Mutex
	maxRetries int
}

// NewCentralLogger creates a new central logger instance
func NewCentralLogger(endpoint, apiKey string) *CentralLogger {
	return &CentralLogger{
		endpoint:   endpoint,
		apiKey:     apiKey,
		client:     &http.Client{Timeout: 10 * time.Second},
		queue:      make([]SandboxData, 0),
		maxRetries: 3,
	}
}

// GenerateHash creates a unique hash for the sandbox environment
func (cl *CentralLogger) GenerateHash(data SandboxData) string {
	hasher := sha256.New()
	hashInput := fmt.Sprintf("%s-%s-%s-%v", 
		data.Hostname, 
		data.Username, 
		data.Domain,
		data.MACAddresses)
	hasher.Write([]byte(hashInput))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

// CollectSandboxData gathers all relevant sandbox information
func (cl *CentralLogger) CollectSandboxData() SandboxData {
	hostname, _ := os.Hostname()
	
	data := SandboxData{
		Hostname:  hostname,
		Username:  os.Getenv("USERNAME"),
		Domain:    os.Getenv("USERDOMAIN"),
		Timestamp: time.Now().UTC(),
	}
	
	// Collect MAC addresses
	macs := collectMACAddresses()
	if len(macs) > 0 {
		data.MACAddresses = macs
	}
	
	// Collect detected file paths
	paths := collectDetectedFilePaths()
	if len(paths) > 0 {
		data.FilePaths = paths
	}
	
	// Add system information
	data.ProcessCount = getProcessCount()
	data.CPUCores = getCPUCores()
	data.TempFileCount = getTempFileCount()
	_, offset := time.Now().Zone()
	data.UTCOffset = offset
	
	// Generate unique hash
	data.Hash = cl.GenerateHash(data)
	
	return data
}

// QueueData adds data to the queue for batch sending
func (cl *CentralLogger) QueueData(data SandboxData) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.queue = append(cl.queue, data)
}

// SendData sends a single data entry to the central server
func (cl *CentralLogger) SendData(data SandboxData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	req, err := http.NewRequest("POST", cl.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cl.apiKey)
	req.Header.Set("User-Agent", "SandboxSpy-Logger/1.0")
	
	resp, err := cl.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	return nil
}

// SendDataWithRetry sends data with retry logic
func (cl *CentralLogger) SendDataWithRetry(data SandboxData) error {
	var lastErr error
	
	for i := 0; i < cl.maxRetries; i++ {
		err := cl.SendData(data)
		if err == nil {
			return nil
		}
		
		lastErr = err
		// Exponential backoff
		time.Sleep(time.Duration(1<<uint(i)) * time.Second)
	}
	
	return fmt.Errorf("failed after %d retries: %w", cl.maxRetries, lastErr)
}

// FlushQueue sends all queued data to the server
func (cl *CentralLogger) FlushQueue() error {
	cl.mu.Lock()
	queueCopy := make([]SandboxData, len(cl.queue))
	copy(queueCopy, cl.queue)
	cl.queue = cl.queue[:0]
	cl.mu.Unlock()
	
	for _, data := range queueCopy {
		if err := cl.SendDataWithRetry(data); err != nil {
			// Re-queue failed items
			cl.QueueData(data)
			return err
		}
	}
	
	return nil
}

// BatchSend sends multiple data entries in a single request
func (cl *CentralLogger) BatchSend(dataList []SandboxData) error {
	payload := map[string]interface{}{
		"entries": dataList,
		"batch_timestamp": time.Now().UTC(),
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal batch data: %w", err)
	}
	
	req, err := http.NewRequest("POST", cl.endpoint+"/batch", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create batch request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cl.apiKey)
	req.Header.Set("User-Agent", "SandboxSpy-Logger/1.0")
	
	resp, err := cl.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send batch request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("batch server returned status %d", resp.StatusCode)
	}
	
	return nil
}