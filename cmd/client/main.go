package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/client"
	"github.com/zephrfish/sandboxspy/pkg/detector"
	"github.com/zephrfish/sandboxspy/pkg/models"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	log.Printf("SandboxSpy Client v%s (built: %s)\n", Version, BuildTime)

	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		log.Printf("Warning: Could not load config.json: %v\n", err)
		config = getDefaultConfig()
	}

	// Initialize detector
	det := detector.New()
	
	// Run all detection methods
	log.Println("Running sandbox detection...")
	detectionResult := det.RunAllDetections()
	
	// Create sandbox entry
	entry := models.SandboxEntry{
		Hostname:       detectionResult.Hostname,
		Username:       detectionResult.Username,
		Domain:         detectionResult.Domain,
		IPAddress:      detectionResult.IPAddress,
		IPRange:        detectionResult.IPRange,
		MACAddresses:   detectionResult.MACAddresses,
		Processes:      detectionResult.Processes,
		FilePaths:      detectionResult.FilePaths,
		Confidence:     detectionResult.Confidence,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
		DetectionCount: 1,
		Tags:           detectionResult.Tags,
		Fingerprint:    detectionResult.Fingerprint,
		Metadata:       detectionResult.Metadata,
	}

	// Log detection results
	log.Printf("Detection Results:")
	log.Printf("  Hostname: %s", entry.Hostname)
	log.Printf("  Confidence: %.2f", entry.Confidence)
	log.Printf("  Is Sandbox: %v", detectionResult.IsSandbox)
	
	// If logging is enabled and this is a sandbox, send to server
	if config.Logging.Enabled && (detectionResult.IsSandbox || entry.Confidence >= config.Detection.ConfidenceThreshold) {
		log.Printf("Sandbox detected with confidence %.2f, sending to server...", entry.Confidence)
		
		// Initialize client based on provider
		switch config.Logging.Provider {
		case "server":
			serverConfig := config.Logging.Endpoints.Server
			cli := client.NewServerClient(serverConfig.URL, serverConfig.APIKey)
			
			// Check server health
			if err := cli.HealthCheck(); err != nil {
				log.Printf("Server health check failed: %v", err)
			} else {
				// Submit detection data
				if err := cli.SubmitSandboxData(entry); err != nil {
					log.Printf("Failed to submit data to server: %v", err)
				} else {
					log.Printf("Successfully submitted data to server")
					
					// Get and display statistics
					if stats, err := cli.GetStatistics(); err == nil {
						log.Printf("Server Statistics:")
						for key, value := range stats {
							log.Printf("  %s: %v", key, value)
						}
					}
				}
			}
			
		case "firebase":
			log.Printf("Firebase provider configured but not implemented in this example")
			
		default:
			log.Printf("Unknown logging provider: %s", config.Logging.Provider)
		}
	} else {
		log.Printf("Not a sandbox or confidence below threshold (%.2f < %.2f)", 
			entry.Confidence, config.Detection.ConfidenceThreshold)
	}
	
	// Export blocklist if configured
	if config.Blocklist.AutoUpdate && config.Logging.Provider == "server" {
		serverConfig := config.Logging.Endpoints.Server
		cli := client.NewServerClient(serverConfig.URL, serverConfig.APIKey)
		
		blocklist, err := cli.GetBlocklist()
		if err != nil {
			log.Printf("Failed to get blocklist: %v", err)
		} else {
			log.Printf("Retrieved blocklist with %d hostnames, %d IP ranges", 
				len(blocklist.Hostnames), len(blocklist.IPRanges))
			
			// Save blocklist locally
			if err := saveBlocklist(blocklist, "blocklist.json"); err != nil {
				log.Printf("Failed to save blocklist: %v", err)
			} else {
				log.Printf("Blocklist saved to blocklist.json")
			}
		}
	}
}

// Config represents the client configuration
type Config struct {
	Logging struct {
		Enabled  bool   `json:"enabled"`
		Provider string `json:"provider"`
		Endpoints struct {
			Server struct {
				URL    string `json:"url"`
				APIKey string `json:"api_key"`
			} `json:"server"`
			Firebase struct {
				ProjectID   string `json:"project_id"`
				APIKey      string `json:"api_key"`
				DatabaseURL string `json:"database_url"`
			} `json:"firebase"`
		} `json:"endpoints"`
		RetryPolicy struct {
			MaxRetries     int `json:"max_retries"`
			BackoffSeconds int `json:"backoff_seconds"`
		} `json:"retry_policy"`
		BatchSize              int `json:"batch_size"`
		FlushIntervalSeconds   int `json:"flush_interval_seconds"`
	} `json:"logging"`
	Detection struct {
		AutoIndexNew        bool    `json:"auto_index_new"`
		ConfidenceThreshold float64 `json:"confidence_threshold"`
		IPRangeDetection    bool    `json:"ip_range_detection"`
		ProcessMonitoring   bool    `json:"process_monitoring"`
	} `json:"detection"`
	Blocklist struct {
		AutoUpdate           bool     `json:"auto_update"`
		UpdateIntervalHours  int      `json:"update_interval_hours"`
		ExportFormats        []string `json:"export_formats"`
	} `json:"blocklist"`
}

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

func getDefaultConfig() *Config {
	return &Config{}
}

func saveBlocklist(blocklist *models.Blocklist, filename string) error {
	data, err := json.MarshalIndent(blocklist, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

func init() {
	// Set up logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	
	// Check if running with version flag
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Printf("SandboxSpy Client\nVersion: %s\nBuild Time: %s\n", Version, BuildTime)
		os.Exit(0)
	}
}