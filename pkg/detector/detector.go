package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

// Detector performs sandbox detection
type Detector struct {
	config *Config
}

// Config holds detector configuration
type Config struct {
	EnableFileCheck    bool
	EnableProcessCheck bool
	EnableNetworkCheck bool
	EnableTimingCheck  bool
}

// DetectionResult contains all detection findings
type DetectionResult struct {
	Hostname       string
	Username       string
	Domain         string
	IPAddress      string
	IPRange        string
	MACAddresses   []string
	Processes      []string
	FilePaths      []string
	Confidence     float64
	IsSandbox      bool
	Tags           []string
	Fingerprint    string
	Metadata       map[string]string
}

// New creates a new detector
func New() *Detector {
	return &Detector{
		config: &Config{
			EnableFileCheck:    true,
			EnableProcessCheck: true,
			EnableNetworkCheck: true,
			EnableTimingCheck:  true,
		},
	}
}

// RunAllDetections runs all detection methods
func (d *Detector) RunAllDetections() *DetectionResult {
	result := &DetectionResult{
		Metadata: make(map[string]string),
	}
	
	// Get basic system info
	result.Hostname, _ = os.Hostname()
	result.Username = os.Getenv("USERNAME")
	if result.Username == "" {
		result.Username = os.Getenv("USER")
	}
	result.Domain = os.Getenv("USERDOMAIN")
	
	// Get network info
	result.IPAddress = d.getExternalIP()
	result.IPRange = d.detectIPRange(result.IPAddress)
	result.MACAddresses = d.collectMACAddresses()
	
	// Run detection checks
	checks := 0
	positives := 0
	
	// Create advanced detector for additional checks
	advDetector := &AdvancedDetector{Detector: d}
	
	if d.config.EnableFileCheck {
		if paths := d.detectSandboxFiles(); len(paths) > 0 {
			result.FilePaths = paths
			positives++
		}
		checks++
		
		// Advanced filesystem checks
		if advDetector.CheckFilesystemArtifacts() {
			positives++
			result.Tags = append(result.Tags, "filesystem-artifacts")
		}
		checks++
	}
	
	if d.config.EnableProcessCheck {
		if procs := d.detectSandboxProcesses(); len(procs) > 0 {
			result.Processes = procs
			positives++
		}
		checks++
		
		// Check for injected DLLs
		if dlls := advDetector.CheckInjectedDLLs(); len(dlls) > 0 {
			positives++
			result.Tags = append(result.Tags, "dll-injection")
			result.Metadata["injected_dlls"] = strings.Join(dlls, ",")
		}
		checks++
		
		// Check for debugger
		if advDetector.IsDebuggerPresent() {
			positives++
			result.Tags = append(result.Tags, "debugger-detected")
		}
		checks++
	}
	
	if d.config.EnableNetworkCheck {
		if d.detectSandboxMAC(result.MACAddresses) {
			positives++
		}
		checks++
		
		// Advanced MAC vendor mapping
		if macVendors := advDetector.CheckSpecificMACs(); len(macVendors) > 0 {
			for mac, vendor := range macVendors {
				result.Metadata[fmt.Sprintf("mac_%s", mac)] = vendor
				if vendor != "Unknown" {
					positives++
					result.Tags = append(result.Tags, strings.ToLower(vendor))
				}
			}
		}
		checks++
	}
	
	if d.detectSandboxHostname(result.Hostname) {
		positives++
		checks++
	}
	
	if d.detectSandboxUsername(result.Username) {
		positives++
		checks++
	}
	
	// Extended username check
	if advDetector.CheckExtendedUsernames() {
		positives++
		result.Tags = append(result.Tags, "suspicious-username")
		checks++
	}
	
	if d.config.EnableTimingCheck {
		if d.detectTimingAnomaly() {
			positives++
			checks++
		}
		
		// Aggressive timing check
		if advDetector.AggressiveTimingCheck() {
			positives++
			result.Tags = append(result.Tags, "timing-anomaly")
		}
		checks++
	}
	
	// WMI checks (Windows only)
	if runtime.GOOS == "windows" {
		if advDetector.CheckWMIPortConnectors() {
			positives++
			result.Tags = append(result.Tags, "wmi-port-connectors")
		}
		checks++
		
		systemInfo := advDetector.CheckWMISystemInfo()
		if systemInfo != "" && strings.Contains(strings.ToLower(systemInfo), "virtual") {
			positives++
			result.Metadata["wmi_system"] = systemInfo
		}
		checks++
	}
	
	// Memory artifact scanning
	if advDetector.ScanMemoryArtifacts() {
		positives++
		result.Tags = append(result.Tags, "memory-artifacts")
		checks++
	}
	
	// Registry artifact detection (Windows only)
	if runtime.GOOS == "windows" && advDetector.CheckRegistryArtifacts() {
		positives++
		result.Tags = append(result.Tags, "registry-artifacts")
		checks++
	}
	
	// Calculate confidence
	if checks > 0 {
		result.Confidence = float64(positives) / float64(checks)
	}
	
	// Determine if sandbox (adjusted threshold for more checks)
	result.IsSandbox = result.Confidence >= 0.25 || positives >= 3
	
	// Generate tags
	result.Tags = append(result.Tags, d.generateTags(result)...)
	
	// Generate fingerprint
	result.Fingerprint = d.generateFingerprint(result)
	
	// Add metadata
	result.Metadata["os"] = runtime.GOOS
	result.Metadata["arch"] = runtime.GOARCH
	result.Metadata["cpu_cores"] = fmt.Sprintf("%d", runtime.NumCPU())
	result.Metadata["go_version"] = runtime.Version()
	result.Metadata["total_checks"] = fmt.Sprintf("%d", checks)
	result.Metadata["positive_checks"] = fmt.Sprintf("%d", positives)
	
	return result
}

// detectSandboxFiles checks for sandbox-related files
func (d *Detector) detectSandboxFiles() []string {
	var detected []string
	
	sandboxPaths := []string{
		`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vm3dgl.dll`,
		`C:\windows\System32\Drivers\vmdum.dll`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`,
		`C:\windows\System32\Drivers\VBoxGuest.sys`,
		`C:\windows\System32\vboxdisp.dll`,
		`C:\windows\System32\vboxhook.dll`,
		`C:\windows\System32\vboxservice.exe`,
		`C:\windows\System32\vboxtray.exe`,
	}
	
	for _, path := range sandboxPaths {
		if _, err := os.Stat(path); err == nil {
			detected = append(detected, path)
		}
	}
	
	return detected
}

// detectSandboxProcesses checks for sandbox-related processes
func (d *Detector) detectSandboxProcesses() []string {
	var detected []string
	
	sandboxProcs := []string{
		"vboxservice.exe",
		"vboxtray.exe",
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vmusrvc.exe",
		"vmsrvc.exe",
		"xenservice.exe",
		"qemu-ga.exe",
		"prl_cc.exe",
		"prl_tools.exe",
		"srvhost.exe", // Any.run specific
	}
	
	processes, err := ps.Processes()
	if err != nil {
		return detected
	}
	
	for _, proc := range processes {
		procName := strings.ToLower(proc.Executable())
		for _, sandboxProc := range sandboxProcs {
			if procName == sandboxProc {
				detected = append(detected, procName)
			}
		}
	}
	
	return detected
}

// detectSandboxMAC checks for sandbox MAC addresses
func (d *Detector) detectSandboxMAC(macs []string) bool {
	sandboxMACs := []string{
		"00:0C:29", // VMware
		"00:1C:14", // VMware
		"00:50:56", // VMware
		"00:05:69", // VMware
		"08:00:27", // VirtualBox
		"00:16:3E", // Xen
	}
	
	for _, mac := range macs {
		macUpper := strings.ToUpper(mac)
		for _, sandboxMAC := range sandboxMACs {
			if strings.HasPrefix(macUpper, sandboxMAC) {
				return true
			}
		}
	}
	
	return false
}

// detectSandboxHostname checks for known sandbox hostnames
func (d *Detector) detectSandboxHostname(hostname string) bool {
	sandboxHostnames := []string{
		"sandbox",
		"malware",
		"analysis",
		"test",
		"virus",
		"any.run",
		"hybrid",
		"cuckoo",
		"WIN-",
		"USER-PC",
		"DESKTOP-",
	}
	
	hostnameLower := strings.ToLower(hostname)
	for _, pattern := range sandboxHostnames {
		if strings.Contains(hostnameLower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// detectSandboxUsername checks for known sandbox usernames
func (d *Detector) detectSandboxUsername(username string) bool {
	sandboxUsernames := []string{
		"sandbox",
		"malware",
		"virus",
		"test",
		"admin",
		"user",
		"analyst",
		"research",
	}
	
	usernameLower := strings.ToLower(username)
	for _, pattern := range sandboxUsernames {
		if usernameLower == strings.ToLower(pattern) {
			return true
		}
	}
	
	return false
}

// detectTimingAnomaly checks for timing anomalies (accelerated sleep)
func (d *Detector) detectTimingAnomaly() bool {
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)
	
	// If sleep was significantly shorter than expected, likely sandbox
	return elapsed < 90*time.Millisecond
}

// collectMACAddresses gathers all MAC addresses
func (d *Detector) collectMACAddresses() []string {
	var macs []string
	
	ifaces, err := net.Interfaces()
	if err != nil {
		return macs
	}
	
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if mac != "" && mac != "00:00:00:00:00:00" {
			macs = append(macs, strings.ToUpper(mac))
		}
	}
	
	return macs
}

// getExternalIP attempts to get the external IP
func (d *Detector) getExternalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// detectIPRange detects the IP range
func (d *Detector) detectIPRange(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	
	if parsedIP.To4() != nil {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}
	
	return ""
}

// generateTags generates tags based on detection
func (d *Detector) generateTags(result *DetectionResult) []string {
	var tags []string
	
	// VM type detection
	for _, mac := range result.MACAddresses {
		macUpper := strings.ToUpper(mac)
		if strings.HasPrefix(macUpper, "00:0C:29") || 
		   strings.HasPrefix(macUpper, "00:50:56") {
			tags = append(tags, "vmware")
			break
		}
		if strings.HasPrefix(macUpper, "08:00:27") {
			tags = append(tags, "virtualbox")
			break
		}
	}
	
	// Process-based detection
	for _, proc := range result.Processes {
		if strings.Contains(proc, "vbox") {
			tags = append(tags, "virtualbox")
		}
		if strings.Contains(proc, "vmware") || strings.Contains(proc, "vmtool") {
			tags = append(tags, "vmware")
		}
	}
	
	// Confidence level
	if result.Confidence >= 0.8 {
		tags = append(tags, "high-confidence")
	} else if result.Confidence >= 0.5 {
		tags = append(tags, "medium-confidence")
	} else if result.Confidence > 0 {
		tags = append(tags, "low-confidence")
	}
	
	// Remove duplicates
	tagMap := make(map[string]bool)
	for _, tag := range tags {
		tagMap[tag] = true
	}
	
	uniqueTags := []string{}
	for tag := range tagMap {
		uniqueTags = append(uniqueTags, tag)
	}
	
	return uniqueTags
}

// generateFingerprint creates a unique fingerprint
func (d *Detector) generateFingerprint(result *DetectionResult) string {
	data := fmt.Sprintf("%s|%s|%s|%v",
		result.Hostname,
		result.Username,
		result.Domain,
		result.MACAddresses)
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

// CheckTempFiles checks if temp directory has few files (sandbox indicator)
func (d *Detector) CheckTempFiles(minFiles int) bool {
	tempDir := os.TempDir()
	files, err := ioutil.ReadDir(tempDir)
	if err != nil {
		return false
	}
	
	return len(files) < minFiles
}

// CheckCPUCores checks if CPU cores are below threshold
func (d *Detector) CheckCPUCores(minCores int) bool {
	return runtime.NumCPU() < minCores
}

// CheckProcessCount checks if process count is below threshold
func (d *Detector) CheckProcessCount(minProcs int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return false
	}
	
	return len(processes) < minProcs
}