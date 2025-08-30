package detector

import (
	"runtime"
	"strings"
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := New()
	if d == nil {
		t.Fatal("New() returned nil")
	}
	
	if d.config == nil {
		t.Fatal("Detector config is nil")
	}
	
	if !d.config.EnableFileCheck {
		t.Error("Expected EnableFileCheck to be true by default")
	}
	
	if !d.config.EnableProcessCheck {
		t.Error("Expected EnableProcessCheck to be true by default")
	}
}

func TestValidateHostname(t *testing.T) {
	d := New()
	
	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		{"Sandbox hostname", "sandbox-test", true},
		{"Malware hostname", "malware-analysis", true},
		{"WIN prefix", "WIN-ABC123", true},
		{"Desktop prefix", "DESKTOP-XYZ", true},
		{"Normal hostname", "mycomputer", false},
		{"Production server", "prod-server-01", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.detectSandboxHostname(tt.hostname)
			if result != tt.expected {
				t.Errorf("detectSandboxHostname(%s) = %v, want %v", tt.hostname, result, tt.expected)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	d := New()
	
	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{"Sandbox user", "sandbox", true},
		{"Admin user", "admin", true},
		{"Test user", "test", true},
		{"Analyst user", "analyst", true},
		{"Normal user", "john.doe", false},
		{"Email-like user", "user@example", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.detectSandboxUsername(tt.username)
			if result != tt.expected {
				t.Errorf("detectSandboxUsername(%s) = %v, want %v", tt.username, result, tt.expected)
			}
		})
	}
}

func TestDetectSandboxMAC(t *testing.T) {
	d := New()
	
	tests := []struct {
		name     string
		macs     []string
		expected bool
	}{
		{
			name:     "VMware MAC",
			macs:     []string{"00:0C:29:12:34:56"},
			expected: true,
		},
		{
			name:     "VirtualBox MAC",
			macs:     []string{"08:00:27:AB:CD:EF"},
			expected: true,
		},
		{
			name:     "Xen MAC",
			macs:     []string{"00:16:3E:11:22:33"},
			expected: true,
		},
		{
			name:     "Normal MAC",
			macs:     []string{"B8:27:EB:11:22:33"},
			expected: false,
		},
		{
			name:     "Multiple MACs with sandbox",
			macs:     []string{"B8:27:EB:11:22:33", "00:50:56:AA:BB:CC"},
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.detectSandboxMAC(tt.macs)
			if result != tt.expected {
				t.Errorf("detectSandboxMAC(%v) = %v, want %v", tt.macs, result, tt.expected)
			}
		})
	}
}

func TestDetectIPRange(t *testing.T) {
	d := New()
	
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"Valid IPv4", "192.168.1.100", "192.168.1.0/24"},
		{"Another IPv4", "10.0.0.5", "10.0.0.0/24"},
		{"Invalid IP", "not-an-ip", ""},
		{"Empty IP", "", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.detectIPRange(tt.ip)
			if result != tt.expected {
				t.Errorf("detectIPRange(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestGenerateTags(t *testing.T) {
	d := New()
	
	result := &DetectionResult{
		MACAddresses: []string{"00:0C:29:12:34:56"},
		Processes:    []string{"vboxservice.exe"},
		Confidence:   0.85,
	}
	
	tags := d.generateTags(result)
	
	// Check for expected tags
	hasVMware := false
	hasHighConfidence := false
	
	for _, tag := range tags {
		if tag == "vmware" {
			hasVMware = true
		}
		if tag == "high-confidence" {
			hasHighConfidence = true
		}
	}
	
	if !hasVMware {
		t.Error("Expected 'vmware' tag for VMware MAC address")
	}
	
	if !hasHighConfidence {
		t.Error("Expected 'high-confidence' tag for confidence >= 0.8")
	}
}

func TestGenerateFingerprint(t *testing.T) {
	d := New()
	
	result := &DetectionResult{
		Hostname:     "test-host",
		Username:     "test-user",
		Domain:       "test-domain",
		MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
	}
	
	fingerprint := d.generateFingerprint(result)
	
	if len(fingerprint) != 16 {
		t.Errorf("Expected fingerprint length of 16, got %d", len(fingerprint))
	}
	
	// Verify it's hexadecimal
	for _, c := range fingerprint {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("Fingerprint contains non-hex character: %c", c)
		}
	}
	
	// Test consistency
	fingerprint2 := d.generateFingerprint(result)
	if fingerprint != fingerprint2 {
		t.Error("Fingerprint generation is not consistent")
	}
}

func TestCheckCPUCores(t *testing.T) {
	d := New()
	
	// This test depends on the system, so we just verify the function works
	cores := runtime.NumCPU()
	
	result := d.CheckCPUCores(cores + 1)
	if result != true {
		t.Error("CheckCPUCores should return true when threshold is above actual cores")
	}
	
	result = d.CheckCPUCores(1)
	if result != false {
		t.Error("CheckCPUCores should return false when threshold is 1 (most systems have >1 core)")
	}
}

func TestRunAllDetections(t *testing.T) {
	d := New()
	
	// Disable some checks for testing
	d.config.EnableTimingCheck = false
	
	result := d.RunAllDetections()
	
	if result == nil {
		t.Fatal("RunAllDetections returned nil")
	}
	
	// Verify basic fields are populated
	if result.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	
	if result.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	
	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	
	// Check metadata contains expected keys
	expectedKeys := []string{"os", "arch", "cpu_cores", "go_version", "total_checks", "positive_checks"}
	for _, key := range expectedKeys {
		if _, exists := result.Metadata[key]; !exists {
			t.Errorf("Metadata missing expected key: %s", key)
		}
	}
}

func TestDetectionResultStructure(t *testing.T) {
	result := &DetectionResult{
		Hostname:     "test-host",
		Username:     "test-user",
		Domain:       "WORKGROUP",
		IPAddress:    "192.168.1.100",
		IPRange:      "192.168.1.0/24",
		MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
		Processes:    []string{"explorer.exe"},
		FilePaths:    []string{"C:\\Windows\\System32"},
		Confidence:   0.5,
		IsSandbox:    true,
		Tags:         []string{"test"},
		Fingerprint:  "abc123",
		Metadata:     map[string]string{"test": "value"},
	}
	
	// Verify all fields are accessible
	if result.Hostname != "test-host" {
		t.Error("Hostname field not set correctly")
	}
	
	if len(result.MACAddresses) != 1 {
		t.Error("MACAddresses slice not set correctly")
	}
	
	if result.Metadata["test"] != "value" {
		t.Error("Metadata map not set correctly")
	}
}

func BenchmarkRunAllDetections(b *testing.B) {
	d := New()
	d.config.EnableTimingCheck = false // Disable timing check for consistent benchmarks
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.RunAllDetections()
	}
}

func BenchmarkGenerateFingerprint(b *testing.B) {
	d := New()
	result := &DetectionResult{
		Hostname:     "benchmark-host",
		Username:     "benchmark-user",
		Domain:       "benchmark-domain",
		MACAddresses: []string{"AA:BB:CC:DD:EE:FF"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.generateFingerprint(result)
	}
}