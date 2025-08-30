package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// LoadServerConfig loads server configuration from file
func LoadServerConfig(filename string) (*ServerConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		// Return default config if file doesn't exist
		return getDefaultServerConfig(), nil
	}
	
	var config ServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid config file: %w", err)
	}
	
	// Set defaults for missing values
	if config.Host == "" {
		config.Host = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.DatabasePath == "" {
		config.DatabasePath = "sandboxspy.db"
	}
	if config.RateLimit == 0 {
		config.RateLimit = 100
	}
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 10 * 1024 * 1024 // 10MB
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 3600 // 1 hour
	}
	
	return &config, nil
}

// getDefaultServerConfig returns default server configuration
func getDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:            "0.0.0.0",
		Port:            8080,
		DatabasePath:    "sandboxspy.db",
		APIKey:          generateAPIKey(),
		EnableAuth:      true,
		RateLimit:       100,
		EnableWebSocket: true,
		EnableDashboard: true,
		MaxRequestSize:  10 * 1024 * 1024,
		SessionTimeout:  3600,
		EnableCORS:      true,
		AllowedOrigins:  []string{"*"},
	}
}

// generateAPIKey generates a random API key
func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateSandboxID generates a unique ID for a sandbox entry
func generateSandboxID(entry SandboxEntry) string {
	data := fmt.Sprintf("%s-%s-%s-%d",
		entry.Hostname,
		entry.Username,
		entry.Domain,
		time.Now().UnixNano())
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

// generateClientID generates a unique client ID
func generateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Export format writers

func (s *Server) writeBlocklistTXT(w io.Writer, blocklist *Blocklist) {
	fmt.Fprintf(w, "# SandboxSpy Blocklist\n")
	fmt.Fprintf(w, "# Generated: %s\n", blocklist.UpdatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "# Total Entries: %d\n\n", blocklist.EntryCount)
	
	fmt.Fprintf(w, "## HOSTNAMES (%d)\n", len(blocklist.Hostnames))
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(w, "%s\n", hostname)
	}
	
	fmt.Fprintf(w, "\n## USERNAMES (%d)\n", len(blocklist.Usernames))
	for _, username := range blocklist.Usernames {
		fmt.Fprintf(w, "%s\n", username)
	}
	
	fmt.Fprintf(w, "\n## IP RANGES (%d)\n", len(blocklist.IPRanges))
	for _, ipRange := range blocklist.IPRanges {
		fmt.Fprintf(w, "%s\n", ipRange)
	}
	
	fmt.Fprintf(w, "\n## MAC PREFIXES (%d)\n", len(blocklist.MACPrefixes))
	for _, macPrefix := range blocklist.MACPrefixes {
		fmt.Fprintf(w, "%s\n", macPrefix)
	}
	
	fmt.Fprintf(w, "\n## PROCESSES (%d)\n", len(blocklist.Processes))
	for _, process := range blocklist.Processes {
		fmt.Fprintf(w, "%s\n", process)
	}
}

func (s *Server) writeBlocklistCSV(w io.Writer, blocklist *Blocklist) {
	fmt.Fprintf(w, "Type,Value,LastUpdated\n")
	
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(w, "hostname,%s,%s\n", hostname, blocklist.UpdatedAt.Format(time.RFC3339))
	}
	
	for _, username := range blocklist.Usernames {
		fmt.Fprintf(w, "username,%s,%s\n", username, blocklist.UpdatedAt.Format(time.RFC3339))
	}
	
	for _, ipRange := range blocklist.IPRanges {
		fmt.Fprintf(w, "ip_range,%s,%s\n", ipRange, blocklist.UpdatedAt.Format(time.RFC3339))
	}
	
	for _, macPrefix := range blocklist.MACPrefixes {
		fmt.Fprintf(w, "mac_prefix,%s,%s\n", macPrefix, blocklist.UpdatedAt.Format(time.RFC3339))
	}
	
	for _, process := range blocklist.Processes {
		fmt.Fprintf(w, "process,%s,%s\n", process, blocklist.UpdatedAt.Format(time.RFC3339))
	}
}

func (s *Server) writeSnortRules(w io.Writer, blocklist *Blocklist) {
	fmt.Fprintf(w, "# SandboxSpy Snort Rules\n")
	fmt.Fprintf(w, "# Generated: %s\n", blocklist.UpdatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "# Purpose: Detect potential sandbox environments\n\n")
	
	sid := 1000000
	
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(w, "alert tcp any any -> any any (msg:\"SANDBOX-DETECT Hostname %s\"; content:\"%s\"; nocase; sid:%d; rev:1;)\n",
			hostname, hostname, sid)
		sid++
	}
	
	for _, ipRange := range blocklist.IPRanges {
		ipParts := strings.Split(ipRange, "/")
		if len(ipParts) == 2 {
			fmt.Fprintf(w, "alert ip %s any -> any any (msg:\"SANDBOX-DETECT IP Range %s\"; sid:%d; rev:1;)\n",
				ipRange, ipRange, sid)
			sid++
		}
	}
	
	for _, process := range blocklist.Processes {
		fmt.Fprintf(w, "alert tcp any any -> any $HTTP_PORTS (msg:\"SANDBOX-DETECT Process %s\"; content:\"%s\"; nocase; http_client_body; sid:%d; rev:1;)\n",
			process, process, sid)
		sid++
	}
}

func (s *Server) writeIOCs(w io.Writer, blocklist *Blocklist) {
	iocs := map[string]interface{}{
		"type":     "bundle",
		"id":       fmt.Sprintf("bundle--%s", generateClientID()),
		"created":  time.Now().UTC().Format(time.RFC3339),
		"modified": blocklist.UpdatedAt.Format(time.RFC3339),
		"objects":  []interface{}{},
	}
	
	objects := []interface{}{}
	
	for _, hostname := range blocklist.Hostnames {
		indicator := map[string]interface{}{
			"type":        "indicator",
			"id":          fmt.Sprintf("indicator--%s", generateClientID()),
			"created":     blocklist.UpdatedAt.Format(time.RFC3339),
			"modified":    blocklist.UpdatedAt.Format(time.RFC3339),
			"name":        fmt.Sprintf("Sandbox Hostname: %s", hostname),
			"description": "Known sandbox environment hostname",
			"pattern":     fmt.Sprintf("[network-traffic:dst_ref.value = '%s']", hostname),
			"labels":      []string{"sandbox", "analysis-environment"},
			"valid_from":  blocklist.UpdatedAt.Format(time.RFC3339),
		}
		objects = append(objects, indicator)
	}
	
	for _, ipRange := range blocklist.IPRanges {
		indicator := map[string]interface{}{
			"type":        "indicator",
			"id":          fmt.Sprintf("indicator--%s", generateClientID()),
			"created":     blocklist.UpdatedAt.Format(time.RFC3339),
			"modified":    blocklist.UpdatedAt.Format(time.RFC3339),
			"name":        fmt.Sprintf("Sandbox IP Range: %s", ipRange),
			"description": "Known sandbox environment IP range",
			"pattern":     fmt.Sprintf("[ipv4-addr:value ISSUBSET '%s']", ipRange),
			"labels":      []string{"sandbox", "network"},
			"valid_from":  blocklist.UpdatedAt.Format(time.RFC3339),
		}
		objects = append(objects, indicator)
	}
	
	iocs["objects"] = objects
	
	jsonData, _ := json.MarshalIndent(iocs, "", "  ")
	w.Write(jsonData)
}

// Validation helpers

func validateSandboxEntry(entry *SandboxEntry) error {
	if entry.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	
	if len(entry.Hostname) > 255 {
		return fmt.Errorf("hostname too long")
	}
	
	if entry.Confidence < 0 || entry.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	
	return nil
}

func sanitizeInput(input string) string {
	// Remove potential SQL injection characters
	replacer := strings.NewReplacer(
		"'", "",
		"\"", "",
		";", "",
		"--", "",
		"/*", "",
		"*/", "",
		"xp_", "",
		"sp_", "",
	)
	return replacer.Replace(input)
}

// HTTP helpers

func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	writeJSONResponse(w, statusCode, map[string]string{
		"error": message,
		"code":  fmt.Sprintf("%d", statusCode),
	})
}