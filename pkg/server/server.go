package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/zephrfish/sandboxspy/pkg/models"
	"golang.org/x/time/rate"
)

// Server represents the SandboxSpy server
type Server struct {
	config    *Config
	db        *sql.DB
	router    *mux.Router
	logger    *logrus.Logger
	limiter   *rate.Limiter
	upgrader  websocket.Upgrader
	clients   map[string]*websocket.Conn
	clientsMu sync.RWMutex
	broadcast chan models.WebSocketMessage
}

// Config represents server configuration
type Config struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	DatabasePath    string `json:"database_path"`
	APIKey          string `json:"api_key"`
	EnableAuth      bool   `json:"enable_auth"`
	RateLimit       int    `json:"rate_limit"`
	EnableWebSocket bool   `json:"enable_websocket"`
	EnableDashboard bool   `json:"enable_dashboard"`
	TLSCert         string `json:"tls_cert"`
	TLSKey          string `json:"tls_key"`
}

// LoadConfig loads configuration from file
func LoadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		// Return default config if file doesn't exist
		return &Config{
			Host:            "0.0.0.0",
			Port:            8080,
			DatabasePath:    "sandboxspy.db",
			APIKey:          "change-me",
			EnableAuth:      true,
			RateLimit:       100,
			EnableWebSocket: true,
			EnableDashboard: true,
		}, nil
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// New creates a new server instance
func New(config *Config, logger *logrus.Logger) *Server {
	return &Server{
		config:    config,
		logger:    logger,
		router:    mux.NewRouter(),
		limiter:   rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit*2),
		upgrader:  websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		clients:   make(map[string]*websocket.Conn),
		broadcast: make(chan models.WebSocketMessage, 100),
	}
}

// Initialize initializes the server
func (s *Server) Initialize() error {
	// Initialize database
	if err := s.initDB(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	
	// Setup routes
	s.setupRoutes()
	
	// Start WebSocket broadcaster
	if s.config.EnableWebSocket {
		go s.websocketBroadcaster()
	}
	
	return nil
}

// initDB initializes the database
func (s *Server) initDB() error {
	var err error
	s.db, err = sql.Open("sqlite3", s.config.DatabasePath)
	if err != nil {
		return err
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
		metadata TEXT
	);
	
	CREATE INDEX IF NOT EXISTS idx_hostname ON sandboxes(hostname);
	CREATE INDEX IF NOT EXISTS idx_confidence ON sandboxes(confidence);
	CREATE INDEX IF NOT EXISTS idx_last_seen ON sandboxes(last_seen);
	`
	
	_, err = s.db.Exec(schema)
	return err
}

// setupRoutes sets up HTTP routes
func (s *Server) setupRoutes() {
	// Middleware
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.rateLimitMiddleware)
	if s.config.EnableAuth {
		s.router.Use(s.authMiddleware)
	}
	
	// API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/health", s.handleHealth).Methods("GET", "OPTIONS")
	api.HandleFunc("/sandbox", s.handleSubmitSandbox).Methods("POST", "OPTIONS")
	api.HandleFunc("/sandbox/batch", s.handleBatchSubmit).Methods("POST", "OPTIONS")
	api.HandleFunc("/search", s.handleSearch).Methods("GET", "OPTIONS")
	api.HandleFunc("/blocklist", s.handleGetBlocklist).Methods("GET", "OPTIONS")
	api.HandleFunc("/blocklist/export", s.handleExportBlocklist).Methods("GET", "OPTIONS")
	api.HandleFunc("/stats", s.handleGetStats).Methods("GET", "OPTIONS")
	
	// WebSocket
	if s.config.EnableWebSocket {
		s.router.HandleFunc("/ws", s.handleWebSocket)
	}
	
	// Dashboard
	if s.config.EnableDashboard {
		s.router.PathPrefix("/dashboard/").Handler(
			http.StripPrefix("/dashboard/", http.FileServer(http.Dir("./server/web"))),
		)
		s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
		})
	}
}

// Middleware

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"duration": time.Since(start),
			"ip":       r.RemoteAddr,
		}).Info("Request handled")
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health, dashboard, and OPTIONS requests
		if r.URL.Path == "/api/v1/health" || 
		   r.URL.Path == "/" || 
		   r.URL.Path == "/ws" ||
		   r.Method == "OPTIONS" ||
		   len(r.URL.Path) > 10 && r.URL.Path[:10] == "/dashboard" {
			next.ServeHTTP(w, r)
			return
		}
		
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}
		
		if apiKey != s.config.APIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := models.HealthStatus{
		Status:  "healthy",
		Time:    time.Now(),
		Version: "1.0.0",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleSubmitSandbox(w http.ResponseWriter, r *http.Request) {
	var entry models.SandboxEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Save to database
	if err := s.saveSandboxEntry(&entry); err != nil {
		s.logger.WithError(err).Error("Failed to save sandbox entry")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Broadcast update
	if s.config.EnableWebSocket {
		s.broadcast <- models.WebSocketMessage{
			Type:      "new_sandbox",
			Data:      entry,
			Timestamp: time.Now(),
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (s *Server) handleBatchSubmit(w http.ResponseWriter, r *http.Request) {
	var batch models.BatchSubmission
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	successCount := 0
	for _, entry := range batch.Entries {
		if err := s.saveSandboxEntry(&entry); err == nil {
			successCount++
		}
	}
	
	response := models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("Processed %d/%d entries", successCount, len(batch.Entries)),
		Code:    200,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	entries, err := s.searchSandboxes(query)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleGetBlocklist(w http.ResponseWriter, r *http.Request) {
	blocklist, err := s.getBlocklist()
	if err != nil {
		http.Error(w, "Failed to get blocklist", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blocklist)
}

func (s *Server) handleExportBlocklist(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	
	blocklist, err := s.getBlocklist()
	if err != nil {
		http.Error(w, "Failed to get blocklist", http.StatusInternalServerError)
		return
	}
	
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=blocklist.csv")
		s.exportCSV(w, blocklist)
	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=blocklist.txt")
		s.exportTXT(w, blocklist)
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blocklist)
	}
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.getStatistics()
	if err != nil {
		http.Error(w, "Failed to get statistics", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.WithError(err).Error("WebSocket upgrade failed")
		return
	}
	
	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())
	
	s.clientsMu.Lock()
	s.clients[clientID] = conn
	s.clientsMu.Unlock()
	
	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, clientID)
		s.clientsMu.Unlock()
		conn.Close()
	}()
	
	// Keep connection alive
	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		
		if msg["type"] == "ping" {
			conn.WriteJSON(map[string]interface{}{
				"type": "pong",
				"time": time.Now(),
			})
		}
	}
}

func (s *Server) websocketBroadcaster() {
	for msg := range s.broadcast {
		s.clientsMu.RLock()
		for _, conn := range s.clients {
			if err := conn.WriteJSON(msg); err != nil {
				conn.Close()
			}
		}
		s.clientsMu.RUnlock()
	}
}

// Database operations

func (s *Server) saveSandboxEntry(entry *models.SandboxEntry) error {
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("%s_%d", entry.Hostname, time.Now().UnixNano())
	}
	
	macJSON, _ := json.Marshal(entry.MACAddresses)
	procJSON, _ := json.Marshal(entry.Processes)
	pathJSON, _ := json.Marshal(entry.FilePaths)
	tagsJSON, _ := json.Marshal(entry.Tags)
	metaJSON, _ := json.Marshal(entry.Metadata)
	
	query := `
	INSERT OR REPLACE INTO sandboxes (
		id, hostname, username, domain, ip_address, ip_range,
		mac_addresses, processes, file_paths, confidence,
		first_seen, last_seen, detection_count, tags, fingerprint, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := s.db.Exec(query,
		entry.ID, entry.Hostname, entry.Username, entry.Domain,
		entry.IPAddress, entry.IPRange, string(macJSON), string(procJSON),
		string(pathJSON), entry.Confidence, entry.FirstSeen, entry.LastSeen,
		entry.DetectionCount, string(tagsJSON), entry.Fingerprint, string(metaJSON))
	
	return err
}

func (s *Server) searchSandboxes(query string) ([]models.SandboxEntry, error) {
	sqlQuery := `
	SELECT id, hostname, username, domain, ip_address, confidence, last_seen
	FROM sandboxes
	WHERE hostname LIKE ? OR username LIKE ? OR domain LIKE ?
	ORDER BY last_seen DESC
	LIMIT 100
	`
	
	searchPattern := "%" + query + "%"
	rows, err := s.db.Query(sqlQuery, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var entries []models.SandboxEntry
	for rows.Next() {
		var entry models.SandboxEntry
		err := rows.Scan(&entry.ID, &entry.Hostname, &entry.Username,
			&entry.Domain, &entry.IPAddress, &entry.Confidence, &entry.LastSeen)
		if err == nil {
			entries = append(entries, entry)
		}
	}
	
	return entries, nil
}

func (s *Server) getBlocklist() (*models.Blocklist, error) {
	blocklist := &models.Blocklist{
		UpdatedAt: time.Now(),
	}
	
	// Get unique hostnames
	rows, err := s.db.Query("SELECT DISTINCT hostname FROM sandboxes WHERE confidence >= 0.5")
	if err != nil {
		return blocklist, err
	}
	defer rows.Close()
	
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err == nil {
			blocklist.Hostnames = append(blocklist.Hostnames, hostname)
		}
	}
	
	return blocklist, nil
}

func (s *Server) getStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total entries
	var total int
	s.db.QueryRow("SELECT COUNT(*) FROM sandboxes").Scan(&total)
	stats["total_entries"] = total
	
	// High confidence
	var highConf int
	s.db.QueryRow("SELECT COUNT(*) FROM sandboxes WHERE confidence >= 0.8").Scan(&highConf)
	stats["high_confidence"] = highConf
	
	// Unique hostnames
	var uniqueHosts int
	s.db.QueryRow("SELECT COUNT(DISTINCT hostname) FROM sandboxes").Scan(&uniqueHosts)
	stats["unique_hostnames"] = uniqueHosts
	
	return stats, nil
}

func (s *Server) exportCSV(w http.ResponseWriter, blocklist *models.Blocklist) {
	fmt.Fprintln(w, "Type,Value")
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintf(w, "hostname,%s\n", hostname)
	}
}

func (s *Server) exportTXT(w http.ResponseWriter, blocklist *models.Blocklist) {
	for _, hostname := range blocklist.Hostnames {
		fmt.Fprintln(w, hostname)
	}
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.logger.WithField("address", addr).Info("Starting server")
	
	srv := &http.Server{
		Addr:    addr,
		Handler: s.router,
	}
	
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return srv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	
	return srv.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down server")
	
	if s.db != nil {
		s.db.Close()
	}
	
	close(s.broadcast)
	
	return nil
}