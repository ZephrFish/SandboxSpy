package detector

import (
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// AdvancedDetector provides advanced sandbox detection capabilities
type AdvancedDetector struct {
	*Detector
}

// NewAdvancedDetector creates a new advanced detector
func NewAdvancedDetector() *AdvancedDetector {
	return &AdvancedDetector{
		Detector: New(),
	}
}

// CheckSpecificMACs checks for specific MAC address patterns and maps them to vendors
func (d *AdvancedDetector) CheckSpecificMACs() map[string]string {
	macVendorMap := map[string]string{
		"00:05:69": "VMware",
		"00:0C:29": "VMware", 
		"00:1C:14": "VMware",
		"00:50:56": "VMware",
		"08:00:27": "VirtualBox",
		"0A:00:27": "VirtualBox",
		"00:21:F6": "VirtualBox",
		"00:14:4F": "VirtualBox",
		"00:0F:4B": "VirtualBox",
		"00:16:3E": "Xen",
		"00:1A:4A": "Xen",
		"02:16:3E": "Xen",
		"00:03:FF": "Microsoft Virtual PC",
		"00:15:5D": "Microsoft Hyper-V",
		"00:0D:3A": "Microsoft Azure",
		"52:54:00": "QEMU",
		"00:08:02": "QEMU",
		"00:1C:42": "Parallels",
		"00:50:F2": "Parallels",
		"00:05:00": "Bochs",
		"00:23:7D": "Novell Virtual",
		"00:0C:B6": "ACRN",
	}
	
	result := make(map[string]string)
	
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	
	for _, iface := range interfaces {
		mac := iface.HardwareAddr.String()
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		
		macUpper := strings.ToUpper(mac)
		for prefix, vendor := range macVendorMap {
			if strings.HasPrefix(macUpper, prefix) {
				result[mac] = vendor
				break
			}
		}
		
		if _, found := result[mac]; !found {
			result[mac] = "Unknown"
		}
	}
	
	return result
}

// CheckExtendedUsernames checks for additional suspicious usernames
func (d *AdvancedDetector) CheckExtendedUsernames() bool {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	
	suspiciousUsernames := []string{
		"currentuser",
		"sanbox_user",
		"honey",
		"vmware",
		"vbox",
		"tester",
		"maltest",
		"malware",
		"virus",
		"sample",
		"any.run",
		"john",
		"johndoe",
		"jane",
		"janedoe",
		"default",
		"analysis",
		"researcher",
		"student",
		"testing",
		"test123",
		"user123",
		"win7",
		"win10",
		"windows",
		"pc",
		"desktop",
		"computer",
		"admin123",
		"administrator",
		"guest",
		"public",
		"temp",
		"tmp",
		"abc",
		"xyz",
		"123",
		"111",
		"aaa",
		"zzz",
		"fuck",
		"shit",
		"motherfucker",
	}
	
	usernameLower := strings.ToLower(username)
	
	for _, suspicious := range suspiciousUsernames {
		if usernameLower == suspicious || strings.Contains(usernameLower, suspicious) {
			return true
		}
	}
	
	// Check for very short usernames
	if len(username) <= 3 {
		return true
	}
	
	// Check for purely numeric usernames
	isNumeric := true
	for _, char := range username {
		if char < '0' || char > '9' {
			isNumeric = false
			break
		}
	}
	if isNumeric {
		return true
	}
	
	return false
}

// AggressiveTimingCheck performs multiple timing checks to detect acceleration
func (d *AdvancedDetector) AggressiveTimingCheck() bool {
	// Perform multiple timing checks
	anomalies := 0
	
	for i := 0; i < 5; i++ {
		start := time.Now()
		time.Sleep(50 * time.Millisecond)
		elapsed := time.Since(start)
		
		// Check if sleep was significantly accelerated
		if elapsed < 45*time.Millisecond {
			anomalies++
		}
	}
	
	// If majority of checks show acceleration, likely sandbox
	return anomalies >= 3
}

// ScanMemoryArtifacts checks for sandbox artifacts in memory
func (d *AdvancedDetector) ScanMemoryArtifacts() bool {
	// Check various runtime properties that might indicate sandbox
	
	// Check for low CPU count
	if runtime.NumCPU() <= 2 {
		return true
	}
	
	// Check available memory (this is cross-platform)
	// Sandboxes often have limited resources
	// Note: Getting actual memory requires platform-specific code
	// For now, we'll use other indicators
	
	// Check goroutine count - sandboxes might have monitoring goroutines
	if runtime.NumGoroutine() > 100 {
		return true
	}
	
	return false
}

// CheckFilesystemArtifacts checks for sandbox-related files
func (d *AdvancedDetector) CheckFilesystemArtifacts() bool {
	// Extended list of sandbox artifacts
	sandboxPaths := []string{
		// VMware
		"/tmp/VMwareDnD",
		"/tmp/.vmware",
		"C:\\ProgramData\\VMware",
		"C:\\Program Files\\VMware",
		
		// VirtualBox
		"/tmp/.vbox",
		"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
		"/usr/bin/VBoxClient",
		"/usr/bin/VBoxService",
		
		// QEMU
		"/usr/bin/qemu-ga",
		"/etc/qemu-ga",
		
		// Xen
		"/proc/xen",
		"/usr/lib/xen",
		
		// Hyper-V
		"C:\\Windows\\System32\\vmicres.dll",
		"C:\\Windows\\System32\\vmicsvc.exe",
		
		// Parallels
		"/Library/Parallels",
		"C:\\Program Files\\Parallels",
		
		// Any.run specific
		"C:\\any.run",
		"C:\\InSightDeep",
		
		// Hybrid Analysis
		"C:\\HybridAnalysis",
		
		// Joe Sandbox
		"C:\\Joe",
		"C:\\JoeSandbox",
		
		// Cuckoo
		"C:\\cuckoo",
		"C:\\tcpdump.exe",
		"C:\\windump.exe",
		
		// General sandbox indicators
		"C:\\sample.exe",
		"C:\\malware.exe",
		"C:\\virus.exe",
		"C:\\sandbox",
		"C:\\analysis",
		"/tmp/sample",
		"/tmp/malware",
		"/tmp/analysis",
	}
	
	for _, path := range sandboxPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	
	// Check for suspicious directories in temp
	tempDir := os.TempDir()
	entries, err := os.ReadDir(tempDir)
	if err == nil {
		suspiciousCount := 0
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			if strings.Contains(name, "sandbox") ||
			   strings.Contains(name, "malware") ||
			   strings.Contains(name, "analysis") ||
			   strings.Contains(name, "sample") ||
			   strings.Contains(name, "virus") ||
			   strings.Contains(name, "vbox") ||
			   strings.Contains(name, "vmware") {
				suspiciousCount++
			}
		}
		if suspiciousCount >= 2 {
			return true
		}
	}
	
	return false
}

// CheckEnvironmentVariables checks for sandbox-related environment variables
func (d *AdvancedDetector) CheckEnvironmentVariables() map[string]string {
	suspicious := make(map[string]string)
	
	// Check for sandbox-related environment variables
	checkVars := []string{
		"VBOX_",
		"VMWARE_",
		"QEMU_",
		"XEN_",
		"PARALLELS_",
		"SANDBOX_",
		"ANALYSIS_",
		"CUCKOO_",
		"HYBRID_",
		"JOE_",
		"ANY_RUN_",
		"INTEZER_",
		"TRIAGE_",
	}
	
	environ := os.Environ()
	for _, env := range environ {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := parts[0]
		value := parts[1]
		
		for _, prefix := range checkVars {
			if strings.HasPrefix(strings.ToUpper(key), prefix) {
				suspicious[key] = value
			}
		}
	}
	
	// Also check for specific suspicious values
	if val := os.Getenv("ComputerName"); val != "" {
		valLower := strings.ToLower(val)
		if strings.Contains(valLower, "sandbox") ||
		   strings.Contains(valLower, "malware") ||
		   strings.Contains(valLower, "analysis") ||
		   strings.Contains(valLower, "test") ||
		   strings.Contains(valLower, "virus") {
			suspicious["ComputerName"] = val
		}
	}
	
	return suspicious
}