package security

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

// Validator provides input validation and sanitization
type Validator struct {
	maxHostnameLength  int
	maxUsernameLength  int
	maxProcessLength   int
	maxPathLength      int
	allowedIPRanges    []*net.IPNet
	blockedIPRanges    []*net.IPNet
	sqlInjectionRegex  *regexp.Regexp
	pathTraversalRegex *regexp.Regexp
	xssPatternRegex    *regexp.Regexp
}

// NewValidator creates a new input validator
func NewValidator() *Validator {
	return &Validator{
		maxHostnameLength:  255,
		maxUsernameLength:  32,
		maxProcessLength:   255,
		maxPathLength:      4096,
		sqlInjectionRegex:  regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onclick|onerror|onload)`),
		pathTraversalRegex: regexp.MustCompile(`\.\.\/|\.\.\\|\.\.%2[fF]|\.\.%5[cC]`),
		xssPatternRegex:    regexp.MustCompile(`<[^>]*script|javascript:|on\w+\s*=`),
	}
}

// ValidateHostname validates a hostname
func (v *Validator) ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	
	if len(hostname) > v.maxHostnameLength {
		return fmt.Errorf("hostname exceeds maximum length of %d", v.maxHostnameLength)
	}
	
	// Check for valid hostname pattern (RFC 1123)
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format")
	}
	
	// Check for SQL injection patterns
	if v.sqlInjectionRegex.MatchString(hostname) {
		return fmt.Errorf("potentially malicious hostname detected")
	}
	
	return nil
}

// ValidateUsername validates a username
func (v *Validator) ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	if len(username) > v.maxUsernameLength {
		return fmt.Errorf("username exceeds maximum length of %d", v.maxUsernameLength)
	}
	
	// Allow alphanumeric, underscore, hyphen, and dot
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username format")
	}
	
	// Check for SQL injection patterns
	if v.sqlInjectionRegex.MatchString(username) {
		return fmt.Errorf("potentially malicious username detected")
	}
	
	return nil
}

// ValidateIPAddress validates an IP address
func (v *Validator) ValidateIPAddress(ip string) error {
	if ip == "" {
		return nil // IP can be empty
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format")
	}
	
	// Check against blocked IP ranges
	for _, blockedRange := range v.blockedIPRanges {
		if blockedRange.Contains(parsedIP) {
			return fmt.Errorf("IP address is in blocked range")
		}
	}
	
	// If allowed ranges are configured, check if IP is in allowed range
	if len(v.allowedIPRanges) > 0 {
		allowed := false
		for _, allowedRange := range v.allowedIPRanges {
			if allowedRange.Contains(parsedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP address is not in allowed range")
		}
	}
	
	return nil
}

// ValidateMACAddress validates a MAC address
func (v *Validator) ValidateMACAddress(mac string) error {
	if mac == "" {
		return nil // MAC can be empty
	}
	
	// Standard MAC address format with colons or hyphens
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	if !macRegex.MatchString(mac) {
		return fmt.Errorf("invalid MAC address format")
	}
	
	return nil
}

// ValidateProcessName validates a process name
func (v *Validator) ValidateProcessName(process string) error {
	if process == "" {
		return nil // Process can be empty
	}
	
	if len(process) > v.maxProcessLength {
		return fmt.Errorf("process name exceeds maximum length of %d", v.maxProcessLength)
	}
	
	// Check for path traversal attempts
	if v.pathTraversalRegex.MatchString(process) {
		return fmt.Errorf("potential path traversal in process name")
	}
	
	// Check for SQL injection patterns
	if v.sqlInjectionRegex.MatchString(process) {
		return fmt.Errorf("potentially malicious process name detected")
	}
	
	return nil
}

// ValidateFilePath validates a file path
func (v *Validator) ValidateFilePath(path string) error {
	if path == "" {
		return nil // Path can be empty
	}
	
	if len(path) > v.maxPathLength {
		return fmt.Errorf("file path exceeds maximum length of %d", v.maxPathLength)
	}
	
	// Check for path traversal attempts
	if v.pathTraversalRegex.MatchString(path) {
		return fmt.Errorf("potential path traversal detected")
	}
	
	// Clean the path and check if it tries to escape
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal attempt detected")
	}
	
	// Check for SQL injection patterns
	if v.sqlInjectionRegex.MatchString(path) {
		return fmt.Errorf("potentially malicious file path detected")
	}
	
	return nil
}

// ValidateJSON validates JSON input
func (v *Validator) ValidateJSON(jsonStr string) error {
	if jsonStr == "" {
		return fmt.Errorf("JSON input cannot be empty")
	}
	
	// Check for XSS patterns before parsing
	if v.xssPatternRegex.MatchString(jsonStr) {
		return fmt.Errorf("potential XSS pattern detected in JSON")
	}
	
	// Validate JSON structure
	var js json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &js); err != nil {
		return fmt.Errorf("invalid JSON format: %v", err)
	}
	
	return nil
}

// SanitizeString removes potentially dangerous characters
func (v *Validator) SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove control characters except newline and tab
	controlCharsRegex := regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	input = controlCharsRegex.ReplaceAllString(input, "")
	
	// Escape HTML entities
	replacements := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"&":  "&amp;",
		"\"": "&quot;",
		"'":  "&#39;",
	}
	
	for old, new := range replacements {
		input = strings.ReplaceAll(input, old, new)
	}
	
	return input
}

// ValidateAPIKey validates an API key format
func (v *Validator) ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}
	
	// API key should be alphanumeric and certain special chars
	apiKeyRegex := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	if !apiKeyRegex.MatchString(apiKey) {
		return fmt.Errorf("invalid API key format")
	}
	
	// Check minimum length for security
	if len(apiKey) < 32 {
		return fmt.Errorf("API key too short for security requirements")
	}
	
	return nil
}

// ValidateDomain validates a domain name
func (v *Validator) ValidateDomain(domain string) error {
	if domain == "" {
		return nil // Domain can be empty
	}
	
	// Check for valid domain pattern
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format")
	}
	
	// Check for SQL injection patterns
	if v.sqlInjectionRegex.MatchString(domain) {
		return fmt.Errorf("potentially malicious domain detected")
	}
	
	return nil
}

// ValidateFingerprint validates a fingerprint hash
func (v *Validator) ValidateFingerprint(fingerprint string) error {
	if fingerprint == "" {
		return nil // Fingerprint can be empty
	}
	
	// Fingerprint should be hexadecimal
	fingerprintRegex := regexp.MustCompile(`^[a-fA-F0-9]+$`)
	if !fingerprintRegex.MatchString(fingerprint) {
		return fmt.Errorf("invalid fingerprint format")
	}
	
	return nil
}

// ValidateTags validates a list of tags
func (v *Validator) ValidateTags(tags []string) error {
	tagRegex := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	
	for _, tag := range tags {
		if tag == "" {
			continue
		}
		
		if len(tag) > 50 {
			return fmt.Errorf("tag '%s' exceeds maximum length", tag)
		}
		
		if !tagRegex.MatchString(tag) {
			return fmt.Errorf("invalid tag format: %s", tag)
		}
		
		// Check for SQL injection patterns
		if v.sqlInjectionRegex.MatchString(tag) {
			return fmt.Errorf("potentially malicious tag detected: %s", tag)
		}
	}
	
	return nil
}

// SetAllowedIPRanges sets the allowed IP ranges
func (v *Validator) SetAllowedIPRanges(ranges []string) error {
	v.allowedIPRanges = make([]*net.IPNet, 0, len(ranges))
	
	for _, r := range ranges {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return fmt.Errorf("invalid CIDR range %s: %v", r, err)
		}
		v.allowedIPRanges = append(v.allowedIPRanges, ipnet)
	}
	
	return nil
}

// SetBlockedIPRanges sets the blocked IP ranges
func (v *Validator) SetBlockedIPRanges(ranges []string) error {
	v.blockedIPRanges = make([]*net.IPNet, 0, len(ranges))
	
	for _, r := range ranges {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return fmt.Errorf("invalid CIDR range %s: %v", r, err)
		}
		v.blockedIPRanges = append(v.blockedIPRanges, ipnet)
	}
	
	return nil
}