package models

import (
	"time"
)

// SandboxEntry represents a detected sandbox environment
type SandboxEntry struct {
	ID             string            `json:"id"`
	Hostname       string            `json:"hostname"`
	Username       string            `json:"username"`
	Domain         string            `json:"domain"`
	IPAddress      string            `json:"ip_address"`
	IPRange        string            `json:"ip_range"`
	MACAddresses   []string          `json:"mac_addresses"`
	Processes      []string          `json:"processes"`
	FilePaths      []string          `json:"file_paths"`
	Confidence     float64           `json:"confidence"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	DetectionCount int               `json:"detection_count"`
	Tags           []string          `json:"tags"`
	Fingerprint    string            `json:"fingerprint"`
	Metadata       map[string]string `json:"metadata"`
}

// Blocklist represents a compiled blocklist
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

// DetectionLog represents a detection event
type DetectionLog struct {
	ID            int       `json:"id"`
	SandboxID     string    `json:"sandbox_id"`
	DetectionTime time.Time `json:"detection_time"`
	SourceIP      string    `json:"source_ip"`
	RawData       string    `json:"raw_data"`
}

// Statistics represents server statistics
type Statistics struct {
	TotalEntries      int                    `json:"total_entries"`
	HighConfidence    int                    `json:"high_confidence"`
	UniqueHostnames   int                    `json:"unique_hostnames"`
	UniqueIPRanges    int                    `json:"unique_ip_ranges"`
	RecentDetections  int                    `json:"recent_detections"`
	TopHostnames      []TopItem              `json:"top_hostnames"`
	TopIPRanges       []TopItem              `json:"top_ip_ranges"`
	DetectionTimeline []TimelineItem         `json:"detection_timeline"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TopItem represents a top indicator
type TopItem struct {
	Item  string `json:"item"`
	Count int    `json:"count"`
}

// TimelineItem represents a timeline data point
type TimelineItem struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// HealthStatus represents server health
type HealthStatus struct {
	Status       string    `json:"status"`
	Time         time.Time `json:"time"`
	Database     bool      `json:"database"`
	ClientCount  int       `json:"client_count"`
	Version      string    `json:"version"`
	Uptime       string    `json:"uptime"`
	MemoryUsage  int64     `json:"memory_usage"`
	CPUUsage     float64   `json:"cpu_usage"`
}

// AdvancedQuery for complex searches
type AdvancedQuery struct {
	Hostname       string    `json:"hostname,omitempty"`
	Username       string    `json:"username,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	IPRange        string    `json:"ip_range,omitempty"`
	MinConfidence  float64   `json:"min_confidence,omitempty"`
	StartDate      time.Time `json:"start_date,omitempty"`
	EndDate        time.Time `json:"end_date,omitempty"`
	Tags           []string  `json:"tags,omitempty"`
	Limit          int       `json:"limit,omitempty"`
	Offset         int       `json:"offset,omitempty"`
	SortBy         string    `json:"sort_by,omitempty"`
	SortOrder      string    `json:"sort_order,omitempty"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    int         `json:"code"`
}

// BatchSubmission for batch operations
type BatchSubmission struct {
	Entries       []SandboxEntry `json:"entries"`
	BatchID       string         `json:"batch_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Source        string         `json:"source,omitempty"`
}

// WebSocketMessage for real-time updates
type WebSocketMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	ID        string      `json:"id"`
}

// ExportRequest for blocklist exports
type ExportRequest struct {
	Format        string   `json:"format"`
	MinConfidence float64  `json:"min_confidence,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	StartDate     string   `json:"start_date,omitempty"`
	EndDate       string   `json:"end_date,omitempty"`
}