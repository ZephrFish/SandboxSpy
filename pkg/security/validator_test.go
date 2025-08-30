package security

import (
	"strings"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}
	
	if v.maxHostnameLength != 255 {
		t.Errorf("Expected maxHostnameLength to be 255, got %d", v.maxHostnameLength)
	}
}

func TestValidateHostname(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"Valid hostname", "example.com", false},
		{"Valid subdomain", "sub.example.com", false},
		{"Valid with hyphen", "my-server.example.com", false},
		{"Empty hostname", "", true},
		{"Too long hostname", strings.Repeat("a", 256), true},
		{"SQL injection attempt", "example.com'; DROP TABLE users;--", true},
		{"Invalid characters", "example.com<script>", true},
		{"Valid localhost", "localhost", false},
		{"Valid IP-like hostname", "192-168-1-1.example.com", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateHostname(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname(%s) error = %v, wantErr %v", tt.hostname, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"Valid username", "john.doe", false},
		{"Username with underscore", "john_doe", false},
		{"Username with hyphen", "john-doe", false},
		{"Empty username", "", true},
		{"Too long username", strings.Repeat("a", 33), true},
		{"SQL injection", "admin'; DROP TABLE users;--", true},
		{"Special characters", "user@#$%", true},
		{"Alphanumeric", "user123", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%s) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"Empty IP", "", false}, // Empty is allowed
		{"Invalid format", "999.999.999.999", true},
		{"Not an IP", "not-an-ip", true},
		{"SQL injection", "192.168.1.1'; DROP TABLE--", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateIPAddress(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPAddress(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestValidateMACAddress(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{"Valid MAC with colons", "AA:BB:CC:DD:EE:FF", false},
		{"Valid MAC with hyphens", "AA-BB-CC-DD-EE-FF", false},
		{"Lowercase MAC", "aa:bb:cc:dd:ee:ff", false},
		{"Empty MAC", "", false}, // Empty is allowed
		{"Invalid format", "AA:BB:CC:DD:EE", true},
		{"Invalid characters", "GG:HH:II:JJ:KK:LL", true},
		{"No separator", "AABBCCDDEEFF", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateMACAddress(tt.mac)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMACAddress(%s) error = %v, wantErr %v", tt.mac, err, tt.wantErr)
			}
		})
	}
}

func TestValidateProcessName(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		process string
		wantErr bool
	}{
		{"Valid process", "explorer.exe", false},
		{"Process with path", "C:\\Windows\\System32\\cmd.exe", false},
		{"Empty process", "", false}, // Empty is allowed
		{"Path traversal", "../../../etc/passwd", true},
		{"SQL injection", "process.exe'; DROP TABLE--", true},
		{"Too long", strings.Repeat("a", 256), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateProcessName(tt.process)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProcessName(%s) error = %v, wantErr %v", tt.process, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Valid Windows path", "C:\\Windows\\System32", false},
		{"Valid Unix path", "/usr/local/bin", false},
		{"Empty path", "", false}, // Empty is allowed
		{"Path traversal dots", "../../../etc/passwd", true},
		{"Path traversal encoded", "..%2F..%2Fetc%2Fpasswd", true},
		{"SQL injection", "C:\\test'; DROP TABLE--", true},
		{"Too long", strings.Repeat("a", 4097), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath(%s) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateJSON(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"Valid JSON object", `{"key": "value"}`, false},
		{"Valid JSON array", `[1, 2, 3]`, false},
		{"Empty JSON", "", true},
		{"Invalid JSON", `{key: value}`, true},
		{"XSS attempt", `{"key": "<script>alert('xss')</script>"}`, true},
		{"JavaScript code", `{"key": "javascript:alert(1)"}`, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateJSON(tt.json)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSON(%s) error = %v, wantErr %v", tt.json, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Normal text", "Hello World", "Hello World"},
		{"HTML tags", "<script>alert('xss')</script>", "&amp;lt;script&amp;gt;alert(&#39;xss&#39;)&amp;lt;/script&amp;gt;"},
		{"Quotes", `"Hello" 'World'`, "&quot;Hello&quot; &#39;World&#39;"},
		{"Ampersand", "A & B", "A &amp; B"},
		{"Null bytes", "Hello\x00World", "HelloWorld"},
		{"Control chars", "Hello\x01\x02World", "HelloWorld"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateAPIKey(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		apiKey  string
		wantErr bool
	}{
		{"Valid API key", "abcdef1234567890abcdef1234567890", false},
		{"With hyphens", "abcd-efgh-ijkl-mnop-qrst-uvwx-yz12-3456", false},
		{"With underscores", "abcd_efgh_ijkl_mnop_qrst_uvwx_yz12_3456", false},
		{"Empty key", "", true},
		{"Too short", "abc123", true},
		{"Special characters", "abc@#$%^&*()123456789012345678901", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateAPIKey(tt.apiKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAPIKey(%s) error = %v, wantErr %v", tt.apiKey, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"Valid domain", "example.com", false},
		{"Subdomain", "sub.example.com", false},
		{"Multi-level", "a.b.c.example.com", false},
		{"With hyphen", "my-domain.com", false},
		{"Empty domain", "", false}, // Empty is allowed
		{"Invalid format", ".example.com", true},
		{"SQL injection", "example.com'; DROP TABLE--", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%s) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFingerprint(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{"Valid hex", "abc123def456", false},
		{"Uppercase hex", "ABC123DEF456", false},
		{"Empty fingerprint", "", false}, // Empty is allowed
		{"Invalid characters", "xyz123", true},
		{"With spaces", "abc 123", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateFingerprint(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFingerprint(%s) error = %v, wantErr %v", tt.fingerprint, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTags(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		tags    []string
		wantErr bool
	}{
		{"Valid tags", []string{"tag1", "tag2", "tag-3"}, false},
		{"With underscores", []string{"tag_1", "tag_2"}, false},
		{"Empty tag in list", []string{"tag1", "", "tag2"}, false},
		{"Too long tag", []string{strings.Repeat("a", 51)}, true},
		{"Invalid characters", []string{"tag@#$"}, true},
		{"SQL injection", []string{"tag'; DROP TABLE--"}, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateTags(tt.tags)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTags(%v) error = %v, wantErr %v", tt.tags, err, tt.wantErr)
			}
		})
	}
}

func TestSetAllowedIPRanges(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		ranges  []string
		wantErr bool
	}{
		{"Valid CIDR", []string{"192.168.1.0/24"}, false},
		{"Multiple CIDRs", []string{"192.168.1.0/24", "10.0.0.0/8"}, false},
		{"Invalid CIDR", []string{"192.168.1.0/33"}, true},
		{"Not CIDR format", []string{"192.168.1.1"}, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.SetAllowedIPRanges(tt.ranges)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetAllowedIPRanges(%v) error = %v, wantErr %v", tt.ranges, err, tt.wantErr)
			}
		})
	}
}

func TestSetBlockedIPRanges(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		ranges  []string
		wantErr bool
	}{
		{"Valid CIDR", []string{"192.168.1.0/24"}, false},
		{"Multiple CIDRs", []string{"192.168.1.0/24", "10.0.0.0/8"}, false},
		{"Invalid CIDR", []string{"invalid"}, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.SetBlockedIPRanges(tt.ranges)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetBlockedIPRanges(%v) error = %v, wantErr %v", tt.ranges, err, tt.wantErr)
			}
		})
	}
}

func BenchmarkValidateHostname(b *testing.B) {
	v := NewValidator()
	hostname := "test.example.com"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.ValidateHostname(hostname)
	}
}

func BenchmarkSanitizeString(b *testing.B) {
	v := NewValidator()
	input := "<script>alert('test')</script>"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.SanitizeString(input)
	}
}