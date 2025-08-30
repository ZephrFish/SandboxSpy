package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

// BlocklistExporter handles exporting blocklists in various formats
type BlocklistExporter struct {
	storage CloudStorage
}

// NewBlocklistExporter creates a new blocklist exporter
func NewBlocklistExporter(storage CloudStorage) *BlocklistExporter {
	return &BlocklistExporter{
		storage: storage,
	}
}

// ExportJSON exports the blocklist in JSON format
func (be *BlocklistExporter) ExportJSON(filename string) error {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return fmt.Errorf("failed to get blocklist: %w", err)
	}
	
	// Sort entries for consistency
	sort.Strings(blocklist.Hostnames)
	sort.Strings(blocklist.Usernames)
	sort.Strings(blocklist.IPRanges)
	sort.Strings(blocklist.MACPrefixes)
	sort.Strings(blocklist.Processes)
	
	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(blocklist, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blocklist: %w", err)
	}
	
	// Write to file
	if err := ioutil.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}
	
	return nil
}

// ExportTXT exports the blocklist in plain text format
func (be *BlocklistExporter) ExportTXT(filename string) error {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return fmt.Errorf("failed to get blocklist: %w", err)
	}
	
	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create TXT file: %w", err)
	}
	defer file.Close()
	
	// Write header
	fmt.Fprintf(file, "# SandboxSpy Blocklist\n")
	fmt.Fprintf(file, "# Generated: %s\n", blocklist.UpdatedAt.Format(time.RFC3339))
	fmt.Fprintf(file, "# Total Entries: %d\n\n", blocklist.EntryCount)
	
	// Write hostnames
	fmt.Fprintf(file, "## HOSTNAMES (%d)\n", len(blocklist.Hostnames))
	sort.Strings(blocklist.Hostnames)
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(file, "%s\n", hostname)
	}
	
	// Write usernames
	fmt.Fprintf(file, "\n## USERNAMES (%d)\n", len(blocklist.Usernames))
	sort.Strings(blocklist.Usernames)
	for _, username := range blocklist.Usernames {
		fmt.Fprintf(file, "%s\n", username)
	}
	
	// Write IP ranges
	fmt.Fprintf(file, "\n## IP RANGES (%d)\n", len(blocklist.IPRanges))
	sort.Strings(blocklist.IPRanges)
	for _, ipRange := range blocklist.IPRanges {
		fmt.Fprintf(file, "%s\n", ipRange)
	}
	
	// Write MAC prefixes
	fmt.Fprintf(file, "\n## MAC PREFIXES (%d)\n", len(blocklist.MACPrefixes))
	sort.Strings(blocklist.MACPrefixes)
	for _, macPrefix := range blocklist.MACPrefixes {
		fmt.Fprintf(file, "%s\n", macPrefix)
	}
	
	// Write processes
	fmt.Fprintf(file, "\n## PROCESSES (%d)\n", len(blocklist.Processes))
	sort.Strings(blocklist.Processes)
	for _, process := range blocklist.Processes {
		fmt.Fprintf(file, "%s\n", process)
	}
	
	return nil
}

// ExportCSV exports the blocklist in CSV format
func (be *BlocklistExporter) ExportCSV(filename string) error {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return fmt.Errorf("failed to get blocklist: %w", err)
	}
	
	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()
	
	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	// Write header
	header := []string{"Type", "Value", "Category", "Confidence", "LastUpdated"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}
	
	// Write hostnames
	for _, hostname := range blocklist.Hostnames {
		record := []string{
			"hostname",
			hostname,
			"sandbox",
			"high",
			blocklist.UpdatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	// Write usernames
	for _, username := range blocklist.Usernames {
		record := []string{
			"username",
			username,
			"sandbox",
			"high",
			blocklist.UpdatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	// Write IP ranges
	for _, ipRange := range blocklist.IPRanges {
		record := []string{
			"ip_range",
			ipRange,
			"network",
			"high",
			blocklist.UpdatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	// Write MAC prefixes
	for _, macPrefix := range blocklist.MACPrefixes {
		record := []string{
			"mac_prefix",
			macPrefix,
			"hardware",
			"high",
			blocklist.UpdatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	// Write processes
	for _, process := range blocklist.Processes {
		record := []string{
			"process",
			process,
			"software",
			"medium",
			blocklist.UpdatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	return nil
}

// ExportIOCs exports Indicators of Compromise in STIX/OpenIOC format
func (be *BlocklistExporter) ExportIOCs(filename string) error {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return fmt.Errorf("failed to get blocklist: %w", err)
	}
	
	// Create IOC structure
	iocs := map[string]interface{}{
		"type":        "bundle",
		"id":          fmt.Sprintf("bundle--%s", generateUUID()),
		"created":     time.Now().UTC().Format(time.RFC3339),
		"modified":    blocklist.UpdatedAt.Format(time.RFC3339),
		"objects":     []interface{}{},
	}
	
	objects := []interface{}{}
	
	// Add hostnames as indicators
	for _, hostname := range blocklist.Hostnames {
		indicator := map[string]interface{}{
			"type":        "indicator",
			"id":          fmt.Sprintf("indicator--%s", generateUUID()),
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
	
	// Add IP ranges as indicators
	for _, ipRange := range blocklist.IPRanges {
		indicator := map[string]interface{}{
			"type":        "indicator",
			"id":          fmt.Sprintf("indicator--%s", generateUUID()),
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
	
	// Marshal to JSON
	jsonData, err := json.MarshalIndent(iocs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal IOCs: %w", err)
	}
	
	// Write to file
	if err := ioutil.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write IOC file: %w", err)
	}
	
	return nil
}

// ExportSnortRules exports blocklist as Snort IDS rules
func (be *BlocklistExporter) ExportSnortRules(filename string) error {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return fmt.Errorf("failed to get blocklist: %w", err)
	}
	
	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create Snort rules file: %w", err)
	}
	defer file.Close()
	
	// Write header
	fmt.Fprintf(file, "# SandboxSpy Snort Rules\n")
	fmt.Fprintf(file, "# Generated: %s\n", blocklist.UpdatedAt.Format(time.RFC3339))
	fmt.Fprintf(file, "# Purpose: Detect potential sandbox environments\n\n")
	
	sid := 1000000 // Starting SID for custom rules
	
	// Create rules for hostnames
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(file, "alert tcp any any -> any any (msg:\"SANDBOX-DETECT Hostname %s\"; content:\"%s\"; nocase; sid:%d; rev:1;)\n",
			hostname, hostname, sid)
		sid++
	}
	
	// Create rules for IP ranges
	for _, ipRange := range blocklist.IPRanges {
		ipParts := strings.Split(ipRange, "/")
		if len(ipParts) == 2 {
			fmt.Fprintf(file, "alert ip %s any -> any any (msg:\"SANDBOX-DETECT IP Range %s\"; sid:%d; rev:1;)\n",
				ipRange, ipRange, sid)
			sid++
		}
	}
	
	// Create rules for processes (in HTTP traffic)
	for _, process := range blocklist.Processes {
		fmt.Fprintf(file, "alert tcp any any -> any $HTTP_PORTS (msg:\"SANDBOX-DETECT Process %s\"; content:\"%s\"; nocase; http_client_body; sid:%d; rev:1;)\n",
			process, process, sid)
		sid++
	}
	
	return nil
}

// ExportAll exports blocklist in all supported formats
func (be *BlocklistExporter) ExportAll(baseFilename string) error {
	timestamp := time.Now().Format("20060102_150405")
	
	// Export JSON
	if err := be.ExportJSON(fmt.Sprintf("%s_%s.json", baseFilename, timestamp)); err != nil {
		return fmt.Errorf("failed to export JSON: %w", err)
	}
	
	// Export TXT
	if err := be.ExportTXT(fmt.Sprintf("%s_%s.txt", baseFilename, timestamp)); err != nil {
		return fmt.Errorf("failed to export TXT: %w", err)
	}
	
	// Export CSV
	if err := be.ExportCSV(fmt.Sprintf("%s_%s.csv", baseFilename, timestamp)); err != nil {
		return fmt.Errorf("failed to export CSV: %w", err)
	}
	
	// Export IOCs
	if err := be.ExportIOCs(fmt.Sprintf("%s_%s_iocs.json", baseFilename, timestamp)); err != nil {
		return fmt.Errorf("failed to export IOCs: %w", err)
	}
	
	// Export Snort rules
	if err := be.ExportSnortRules(fmt.Sprintf("%s_%s.rules", baseFilename, timestamp)); err != nil {
		return fmt.Errorf("failed to export Snort rules: %w", err)
	}
	
	return nil
}

// generateUUID generates a simple UUID v4-like string
func generateUUID() string {
	return fmt.Sprintf("%d-%d-%d-%d-%d",
		time.Now().Unix(),
		time.Now().UnixNano()%1000000,
		os.Getpid(),
		rand.Intn(1000000),
		rand.Intn(1000000))
}

// Stats returns statistics about the blocklist
func (be *BlocklistExporter) Stats() (map[string]int, error) {
	blocklist, err := be.storage.GetBlocklist()
	if err != nil {
		return nil, err
	}
	
	stats := map[string]int{
		"total_entries":   blocklist.EntryCount,
		"hostnames":       len(blocklist.Hostnames),
		"usernames":       len(blocklist.Usernames),
		"ip_ranges":       len(blocklist.IPRanges),
		"mac_prefixes":    len(blocklist.MACPrefixes),
		"processes":       len(blocklist.Processes),
	}
	
	return stats, nil
}