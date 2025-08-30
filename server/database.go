package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database handles all database operations
type Database struct {
	db   *sql.DB
	path string
}

// SandboxEntry represents a sandbox detection entry
type SandboxEntry struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname"`
	Username       string    `json:"username"`
	Domain         string    `json:"domain"`
	IPAddress      string    `json:"ip_address"`
	IPRange        string    `json:"ip_range"`
	MACAddresses   []string  `json:"mac_addresses"`
	Processes      []string  `json:"processes"`
	FilePaths      []string  `json:"file_paths"`
	Confidence     float64   `json:"confidence"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	DetectionCount int       `json:"detection_count"`
	Tags           []string  `json:"tags"`
	Fingerprint    string    `json:"fingerprint"`
	Metadata       map[string]string `json:"metadata"`
}

// Blocklist represents compiled blocklist data
type Blocklist struct {
	Hostnames   []string  `json:"hostnames"`
	Usernames   []string  `json:"usernames"`
	IPRanges    []string  `json:"ip_ranges"`
	MACPrefixes []string  `json:"mac_prefixes"`
	Processes   []string  `json:"processes"`
	UpdatedAt   time.Time `json:"updated_at"`
	EntryCount  int       `json:"entry_count"`
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
}

// NewDatabase creates a new database instance
func NewDatabase(path string) *Database {
	return &Database{path: path}
}

// Initialize creates database tables and indexes
func (db *Database) Initialize() error {
	var err error
	db.db, err = sql.Open("sqlite3", db.path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS sandboxes (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		username TEXT,
		domain TEXT,
		ip_address TEXT,
		ip_range TEXT,
		mac_addresses TEXT,
		processes TEXT,
		file_paths TEXT,
		confidence REAL,
		first_seen DATETIME,
		last_seen DATETIME,
		detection_count INTEGER DEFAULT 1,
		tags TEXT,
		fingerprint TEXT UNIQUE,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_hostname ON sandboxes(hostname);
	CREATE INDEX IF NOT EXISTS idx_ip_range ON sandboxes(ip_range);
	CREATE INDEX IF NOT EXISTS idx_confidence ON sandboxes(confidence);
	CREATE INDEX IF NOT EXISTS idx_last_seen ON sandboxes(last_seen);
	CREATE INDEX IF NOT EXISTS idx_fingerprint ON sandboxes(fingerprint);

	CREATE TABLE IF NOT EXISTS detection_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sandbox_id TEXT,
		detection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_ip TEXT,
		raw_data TEXT,
		FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id)
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		key TEXT PRIMARY KEY,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		request_count INTEGER DEFAULT 0,
		is_active BOOLEAN DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		api_key TEXT,
		action TEXT,
		resource TEXT,
		details TEXT
	);
	`

	if _, err := db.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// InsertSandbox inserts a new sandbox entry
func (db *Database) InsertSandbox(entry *SandboxEntry) error {
	macJSON, _ := json.Marshal(entry.MACAddresses)
	processJSON, _ := json.Marshal(entry.Processes)
	pathJSON, _ := json.Marshal(entry.FilePaths)
	tagsJSON, _ := json.Marshal(entry.Tags)
	metadataJSON, _ := json.Marshal(entry.Metadata)

	query := `
	INSERT OR REPLACE INTO sandboxes (
		id, hostname, username, domain, ip_address, ip_range,
		mac_addresses, processes, file_paths, confidence,
		first_seen, last_seen, detection_count, tags, fingerprint, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.db.Exec(query,
		entry.ID, entry.Hostname, entry.Username, entry.Domain,
		entry.IPAddress, entry.IPRange, string(macJSON), string(processJSON),
		string(pathJSON), entry.Confidence, entry.FirstSeen, entry.LastSeen,
		entry.DetectionCount, string(tagsJSON), entry.Fingerprint, string(metadataJSON))

	return err
}

// UpdateSandbox updates an existing sandbox entry
func (db *Database) UpdateSandbox(entry *SandboxEntry) error {
	macJSON, _ := json.Marshal(entry.MACAddresses)
	processJSON, _ := json.Marshal(entry.Processes)
	pathJSON, _ := json.Marshal(entry.FilePaths)
	tagsJSON, _ := json.Marshal(entry.Tags)
	metadataJSON, _ := json.Marshal(entry.Metadata)

	query := `
	UPDATE sandboxes SET
		hostname = ?, username = ?, domain = ?, ip_address = ?, ip_range = ?,
		mac_addresses = ?, processes = ?, file_paths = ?, confidence = ?,
		last_seen = ?, detection_count = ?, tags = ?, metadata = ?,
		updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`

	_, err := db.db.Exec(query,
		entry.Hostname, entry.Username, entry.Domain, entry.IPAddress, entry.IPRange,
		string(macJSON), string(processJSON), string(pathJSON), entry.Confidence,
		entry.LastSeen, entry.DetectionCount, string(tagsJSON), string(metadataJSON),
		entry.ID)

	return err
}

// GetSandboxByID retrieves a sandbox entry by ID
func (db *Database) GetSandboxByID(id string) (*SandboxEntry, error) {
	query := `SELECT * FROM sandboxes WHERE id = ?`
	return db.querySandbox(query, id)
}

// GetSandboxByHostname retrieves a sandbox entry by hostname
func (db *Database) GetSandboxByHostname(hostname string) (*SandboxEntry, error) {
	query := `SELECT * FROM sandboxes WHERE hostname = ?`
	return db.querySandbox(query, hostname)
}

// querySandbox executes a query and returns a single sandbox entry
func (db *Database) querySandbox(query string, args ...interface{}) (*SandboxEntry, error) {
	var entry SandboxEntry
	var macJSON, processJSON, pathJSON, tagsJSON, metadataJSON string

	row := db.db.QueryRow(query, args...)
	err := row.Scan(
		&entry.ID, &entry.Hostname, &entry.Username, &entry.Domain,
		&entry.IPAddress, &entry.IPRange, &macJSON, &processJSON, &pathJSON,
		&entry.Confidence, &entry.FirstSeen, &entry.LastSeen, &entry.DetectionCount,
		&tagsJSON, &entry.Fingerprint, &metadataJSON,
		&sql.NullString{}, &sql.NullString{}, // created_at, updated_at
	)

	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	json.Unmarshal([]byte(macJSON), &entry.MACAddresses)
	json.Unmarshal([]byte(processJSON), &entry.Processes)
	json.Unmarshal([]byte(pathJSON), &entry.FilePaths)
	json.Unmarshal([]byte(tagsJSON), &entry.Tags)
	json.Unmarshal([]byte(metadataJSON), &entry.Metadata)

	return &entry, nil
}

// DeleteSandbox deletes a sandbox entry
func (db *Database) DeleteSandbox(id string) error {
	query := `DELETE FROM sandboxes WHERE id = ?`
	_, err := db.db.Exec(query, id)
	return err
}

// SearchSandboxes performs a text search across multiple fields
func (db *Database) SearchSandboxes(searchTerm string, limit int) ([]SandboxEntry, error) {
	query := `
	SELECT * FROM sandboxes 
	WHERE hostname LIKE ? OR username LIKE ? OR domain LIKE ? OR ip_address LIKE ?
	ORDER BY last_seen DESC
	LIMIT ?
	`

	searchPattern := "%" + searchTerm + "%"
	rows, err := db.db.Query(query, searchPattern, searchPattern, searchPattern, searchPattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return db.scanSandboxRows(rows)
}

// AdvancedQuery performs complex queries with multiple filters
func (db *Database) AdvancedQuery(q AdvancedQuery) ([]SandboxEntry, error) {
	var conditions []string
	var args []interface{}

	if q.Hostname != "" {
		conditions = append(conditions, "hostname LIKE ?")
		args = append(args, "%"+q.Hostname+"%")
	}

	if q.Username != "" {
		conditions = append(conditions, "username LIKE ?")
		args = append(args, "%"+q.Username+"%")
	}

	if q.Domain != "" {
		conditions = append(conditions, "domain LIKE ?")
		args = append(args, "%"+q.Domain+"%")
	}

	if q.IPRange != "" {
		conditions = append(conditions, "ip_range = ?")
		args = append(args, q.IPRange)
	}

	if q.MinConfidence > 0 {
		conditions = append(conditions, "confidence >= ?")
		args = append(args, q.MinConfidence)
	}

	if !q.StartDate.IsZero() {
		conditions = append(conditions, "last_seen >= ?")
		args = append(args, q.StartDate)
	}

	if !q.EndDate.IsZero() {
		conditions = append(conditions, "last_seen <= ?")
		args = append(args, q.EndDate)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := q.Limit
	if limit == 0 {
		limit = 100
	}

	query := fmt.Sprintf(`
	SELECT * FROM sandboxes %s
	ORDER BY last_seen DESC
	LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, limit, q.Offset)

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return db.scanSandboxRows(rows)
}

// scanSandboxRows scans multiple rows into sandbox entries
func (db *Database) scanSandboxRows(rows *sql.Rows) ([]SandboxEntry, error) {
	var entries []SandboxEntry

	for rows.Next() {
		var entry SandboxEntry
		var macJSON, processJSON, pathJSON, tagsJSON, metadataJSON string
		var createdAt, updatedAt sql.NullString

		err := rows.Scan(
			&entry.ID, &entry.Hostname, &entry.Username, &entry.Domain,
			&entry.IPAddress, &entry.IPRange, &macJSON, &processJSON, &pathJSON,
			&entry.Confidence, &entry.FirstSeen, &entry.LastSeen, &entry.DetectionCount,
			&tagsJSON, &entry.Fingerprint, &metadataJSON,
			&createdAt, &updatedAt,
		)

		if err != nil {
			continue
		}

		// Unmarshal JSON fields
		json.Unmarshal([]byte(macJSON), &entry.MACAddresses)
		json.Unmarshal([]byte(processJSON), &entry.Processes)
		json.Unmarshal([]byte(pathJSON), &entry.FilePaths)
		json.Unmarshal([]byte(tagsJSON), &entry.Tags)
		json.Unmarshal([]byte(metadataJSON), &entry.Metadata)

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetBlocklist retrieves the compiled blocklist
func (db *Database) GetBlocklist() (*Blocklist, error) {
	blocklist := &Blocklist{
		Hostnames:   []string{},
		Usernames:   []string{},
		IPRanges:    []string{},
		MACPrefixes: []string{},
		Processes:   []string{},
		UpdatedAt:   time.Now().UTC(),
	}

	// Get unique hostnames
	hostnameQuery := `SELECT DISTINCT hostname FROM sandboxes WHERE confidence >= 0.7`
	hostnames, err := db.getStringList(hostnameQuery)
	if err == nil {
		blocklist.Hostnames = hostnames
	}

	// Get unique usernames
	usernameQuery := `SELECT DISTINCT username FROM sandboxes WHERE confidence >= 0.7 AND username != ''`
	usernames, err := db.getStringList(usernameQuery)
	if err == nil {
		blocklist.Usernames = usernames
	}

	// Get unique IP ranges
	ipRangeQuery := `SELECT DISTINCT ip_range FROM sandboxes WHERE confidence >= 0.7 AND ip_range != ''`
	ipRanges, err := db.getStringList(ipRangeQuery)
	if err == nil {
		blocklist.IPRanges = ipRanges
	}

	// Get entry count
	countQuery := `SELECT COUNT(*) FROM sandboxes WHERE confidence >= 0.7`
	db.db.QueryRow(countQuery).Scan(&blocklist.EntryCount)

	return blocklist, nil
}

// GetFilteredBlocklist retrieves blocklist with custom confidence threshold
func (db *Database) GetFilteredBlocklist(minConfidence string) (*Blocklist, error) {
	confidence := 0.7
	if minConfidence != "" {
		fmt.Sscanf(minConfidence, "%f", &confidence)
	}

	blocklist := &Blocklist{
		UpdatedAt: time.Now().UTC(),
	}

	query := fmt.Sprintf("SELECT DISTINCT hostname FROM sandboxes WHERE confidence >= %f", confidence)
	hostnames, _ := db.getStringList(query)
	blocklist.Hostnames = hostnames

	return blocklist, nil
}

// getStringList executes a query and returns a list of strings
func (db *Database) getStringList(query string) ([]string, error) {
	rows, err := db.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err == nil {
			results = append(results, value)
		}
	}

	return results, nil
}

// GetStatistics returns database statistics
func (db *Database) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total entries
	var total int
	db.db.QueryRow("SELECT COUNT(*) FROM sandboxes").Scan(&total)
	stats["total_entries"] = total

	// High confidence entries
	var highConfidence int
	db.db.QueryRow("SELECT COUNT(*) FROM sandboxes WHERE confidence >= 0.8").Scan(&highConfidence)
	stats["high_confidence"] = highConfidence

	// Unique hostnames
	var uniqueHostnames int
	db.db.QueryRow("SELECT COUNT(DISTINCT hostname) FROM sandboxes").Scan(&uniqueHostnames)
	stats["unique_hostnames"] = uniqueHostnames

	// Unique IP ranges
	var uniqueIPRanges int
	db.db.QueryRow("SELECT COUNT(DISTINCT ip_range) FROM sandboxes WHERE ip_range != ''").Scan(&uniqueIPRanges)
	stats["unique_ip_ranges"] = uniqueIPRanges

	// Recent detections (last 24 hours)
	var recentDetections int
	yesterday := time.Now().Add(-24 * time.Hour)
	db.db.QueryRow("SELECT COUNT(*) FROM sandboxes WHERE last_seen > ?", yesterday).Scan(&recentDetections)
	stats["recent_detections"] = recentDetections

	return stats, nil
}

// GetDetectionTimeline returns detection counts over time
func (db *Database) GetDetectionTimeline(days int) ([]map[string]interface{}, error) {
	query := `
	SELECT DATE(last_seen) as date, COUNT(*) as count
	FROM sandboxes
	WHERE last_seen > datetime('now', '-' || ? || ' days')
	GROUP BY DATE(last_seen)
	ORDER BY date DESC
	`

	rows, err := db.db.Query(query, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var timeline []map[string]interface{}
	for rows.Next() {
		var date string
		var count int
		if err := rows.Scan(&date, &count); err == nil {
			timeline = append(timeline, map[string]interface{}{
				"date":  date,
				"count": count,
			})
		}
	}

	return timeline, nil
}

// GetTopIndicators returns the most common indicators
func (db *Database) GetTopIndicators(limit int) (map[string]interface{}, error) {
	indicators := make(map[string]interface{})

	// Top hostnames
	hostnameQuery := `
	SELECT hostname, COUNT(*) as count
	FROM sandboxes
	GROUP BY hostname
	ORDER BY count DESC
	LIMIT ?
	`
	hostnames, _ := db.getTopItems(hostnameQuery, limit)
	indicators["top_hostnames"] = hostnames

	// Top IP ranges
	ipRangeQuery := `
	SELECT ip_range, COUNT(*) as count
	FROM sandboxes
	WHERE ip_range != ''
	GROUP BY ip_range
	ORDER BY count DESC
	LIMIT ?
	`
	ipRanges, _ := db.getTopItems(ipRangeQuery, limit)
	indicators["top_ip_ranges"] = ipRanges

	return indicators, nil
}

// getTopItems executes a query and returns top items with counts
func (db *Database) getTopItems(query string, limit int) ([]map[string]interface{}, error) {
	rows, err := db.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var item string
		var count int
		if err := rows.Scan(&item, &count); err == nil {
			items = append(items, map[string]interface{}{
				"item":  item,
				"count": count,
			})
		}
	}

	return items, nil
}

// GetBlocklistStats returns blocklist statistics
func (db *Database) GetBlocklistStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	blocklist, err := db.GetBlocklist()
	if err != nil {
		return stats, err
	}

	stats["total_hostnames"] = len(blocklist.Hostnames)
	stats["total_usernames"] = len(blocklist.Usernames)
	stats["total_ip_ranges"] = len(blocklist.IPRanges)
	stats["last_updated"] = blocklist.UpdatedAt

	return stats, nil
}

// LogDetection logs a detection event
func (db *Database) LogDetection(sandboxID, sourceIP, rawData string) error {
	query := `INSERT INTO detection_log (sandbox_id, source_ip, raw_data) VALUES (?, ?, ?)`
	_, err := db.db.Exec(query, sandboxID, sourceIP, rawData)
	return err
}

// IsHealthy checks if the database is healthy
func (db *Database) IsHealthy() bool {
	var result int
	err := db.db.QueryRow("SELECT 1").Scan(&result)
	return err == nil && result == 1
}

// Close closes the database connection
func (db *Database) Close() error {
	if db.db != nil {
		return db.db.Close()
	}
	return nil
}