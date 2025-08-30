package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

// Server represents the SandboxSpy server
type Server struct {
	config     *ServerConfig
	db         *Database
	router     *mux.Router
	clients    map[string]*Client
	clientsMux sync.RWMutex
	limiter    *rate.Limiter
	upgrader   websocket.Upgrader
	broadcast  chan BroadcastMessage
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	DatabasePath      string `json:"database_path"`
	APIKey            string `json:"api_key"`
	EnableAuth        bool   `json:"enable_auth"`
	RateLimit         int    `json:"rate_limit"`
	EnableWebSocket   bool   `json:"enable_websocket"`
	EnableDashboard   bool   `json:"enable_dashboard"`
	TLSCert           string `json:"tls_cert"`
	TLSKey            string `json:"tls_key"`
	MaxRequestSize    int64  `json:"max_request_size"`
	SessionTimeout    int    `json:"session_timeout"`
	EnableCORS        bool   `json:"enable_cors"`
	AllowedOrigins    []string `json:"allowed_origins"`
}

// Client represents a connected client
type Client struct {
	ID           string
	APIKey       string
	LastSeen     time.Time
	RequestCount int
	conn         *websocket.Conn
}

// BroadcastMessage for WebSocket updates
type BroadcastMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	Time    time.Time   `json:"time"`
}

// NewServer creates a new server instance
func NewServer(config *ServerConfig) *Server {
	return &Server{
		config:    config,
		db:        NewDatabase(config.DatabasePath),
		router:    mux.NewRouter(),
		clients:   make(map[string]*Client),
		limiter:   rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit*2),
		upgrader:  websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		broadcast: make(chan BroadcastMessage, 100),
	}
}

// Initialize sets up the server routes and middleware
func (s *Server) Initialize() error {
	// Initialize database
	if err := s.db.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Setup middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.rateLimitMiddleware)
	if s.config.EnableAuth {
		s.router.Use(s.authMiddleware)
	}

	// Setup API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	
	// Sandbox data endpoints
	api.HandleFunc("/sandbox", s.handleSubmitSandbox).Methods("POST")
	api.HandleFunc("/sandbox/batch", s.handleBatchSubmit).Methods("POST")
	api.HandleFunc("/sandbox/{id}", s.handleGetSandbox).Methods("GET")
	api.HandleFunc("/sandbox/{id}", s.handleUpdateSandbox).Methods("PUT")
	api.HandleFunc("/sandbox/{id}", s.handleDeleteSandbox).Methods("DELETE")
	
	// Search and query endpoints
	api.HandleFunc("/search", s.handleSearch).Methods("GET")
	api.HandleFunc("/query", s.handleAdvancedQuery).Methods("POST")
	
	// Blocklist endpoints
	api.HandleFunc("/blocklist", s.handleGetBlocklist).Methods("GET")
	api.HandleFunc("/blocklist/export", s.handleExportBlocklist).Methods("GET")
	api.HandleFunc("/blocklist/stats", s.handleBlocklistStats).Methods("GET")
	
	// Statistics endpoints
	api.HandleFunc("/stats", s.handleGetStats).Methods("GET")
	api.HandleFunc("/stats/timeline", s.handleGetTimeline).Methods("GET")
	api.HandleFunc("/stats/top", s.handleGetTopIndicators).Methods("GET")
	
	// Health check
	api.HandleFunc("/health", s.handleHealthCheck).Methods("GET")
	
	// WebSocket endpoint
	if s.config.EnableWebSocket {
		s.router.HandleFunc("/ws", s.handleWebSocket)
		go s.websocketBroadcaster()
	}
	
	// Dashboard
	if s.config.EnableDashboard {
		s.router.PathPrefix("/dashboard/").Handler(http.StripPrefix("/dashboard/", http.FileServer(http.Dir("./web"))))
		s.router.HandleFunc("/", s.handleDashboardRedirect).Methods("GET")
	}

	return nil
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response recorder
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(rec, r)
		
		duration := time.Since(start)
		log.Printf("[%s] %s %s %d %v", r.RemoteAddr, r.Method, r.RequestURI, rec.statusCode, duration)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.EnableCORS {
			origin := r.Header.Get("Origin")
			allowed := false
			
			for _, allowedOrigin := range s.config.AllowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}
			
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
			}
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
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
		// Skip auth for health check and dashboard
		if r.URL.Path == "/api/v1/health" || strings.HasPrefix(r.URL.Path, "/dashboard") {
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
		
		// Update client tracking
		s.updateClientTracking(apiKey, r.RemoteAddr)
		
		next.ServeHTTP(w, r)
	})
}

// API Handlers

func (s *Server) handleSubmitSandbox(w http.ResponseWriter, r *http.Request) {
	var entry SandboxEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Process the entry
	entry.FirstSeen = time.Now().UTC()
	entry.LastSeen = time.Now().UTC()
	entry.ID = generateSandboxID(entry)
	
	// Check if exists
	existing, err := s.db.GetSandboxByHostname(entry.Hostname)
	if err == nil && existing != nil {
		// Update existing entry
		existing.LastSeen = time.Now().UTC()
		existing.DetectionCount++
		if err := s.db.UpdateSandbox(existing); err != nil {
			http.Error(w, "Failed to update entry", http.StatusInternalServerError)
			return
		}
		entry = *existing
	} else {
		// Create new entry
		entry.DetectionCount = 1
		if err := s.db.InsertSandbox(&entry); err != nil {
			http.Error(w, "Failed to insert entry", http.StatusInternalServerError)
			return
		}
	}
	
	// Broadcast update via WebSocket
	if s.config.EnableWebSocket {
		s.broadcast <- BroadcastMessage{
			Type: "new_sandbox",
			Data: entry,
			Time: time.Now().UTC(),
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (s *Server) handleBatchSubmit(w http.ResponseWriter, r *http.Request) {
	var batch struct {
		Entries []SandboxEntry `json:"entries"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	results := make([]SandboxEntry, 0, len(batch.Entries))
	for _, entry := range batch.Entries {
		entry.FirstSeen = time.Now().UTC()
		entry.LastSeen = time.Now().UTC()
		entry.ID = generateSandboxID(entry)
		entry.DetectionCount = 1
		
		if err := s.db.InsertSandbox(&entry); err == nil {
			results = append(results, entry)
		}
	}
	
	// Broadcast batch update
	if s.config.EnableWebSocket {
		s.broadcast <- BroadcastMessage{
			Type: "batch_update",
			Data: map[string]interface{}{
				"count": len(results),
				"entries": results,
			},
			Time: time.Now().UTC(),
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": len(results),
		"failed":  len(batch.Entries) - len(results),
		"entries": results,
	})
}

func (s *Server) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	
	entry, err := s.db.GetSandboxByID(id)
	if err != nil {
		http.Error(w, "Sandbox not found", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (s *Server) handleUpdateSandbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	
	var entry SandboxEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	entry.ID = id
	entry.LastSeen = time.Now().UTC()
	
	if err := s.db.UpdateSandbox(&entry); err != nil {
		http.Error(w, "Failed to update entry", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (s *Server) handleDeleteSandbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	
	if err := s.db.DeleteSandbox(id); err != nil {
		http.Error(w, "Failed to delete entry", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limit := 100 // Default limit
	
	results, err := s.db.SearchSandboxes(query, limit)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleAdvancedQuery(w http.ResponseWriter, r *http.Request) {
	var query AdvancedQuery
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		http.Error(w, "Invalid query", http.StatusBadRequest)
		return
	}
	
	results, err := s.db.AdvancedQuery(query)
	if err != nil {
		http.Error(w, "Query failed", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetBlocklist(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	
	blocklist, err := s.db.GetBlocklist()
	if err != nil {
		http.Error(w, "Failed to get blocklist", http.StatusInternalServerError)
		return
	}
	
	switch format {
	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		s.writeBlocklistTXT(w, blocklist)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		s.writeBlocklistCSV(w, blocklist)
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blocklist)
	}
}

func (s *Server) handleExportBlocklist(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	confidence := r.URL.Query().Get("confidence")
	
	blocklist, err := s.db.GetFilteredBlocklist(confidence)
	if err != nil {
		http.Error(w, "Failed to export blocklist", http.StatusInternalServerError)
		return
	}
	
	filename := fmt.Sprintf("sandboxspy_blocklist_%s", time.Now().Format("20060102_150405"))
	
	switch format {
	case "snort":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.rules", filename))
		s.writeSnortRules(w, blocklist)
	case "ioc":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_ioc.json", filename))
		s.writeIOCs(w, blocklist)
	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

func (s *Server) handleBlocklistStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetBlocklistStats()
	if err != nil {
		http.Error(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetStatistics()
	if err != nil {
		http.Error(w, "Failed to get statistics", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	days := 30 // Default to 30 days
	timeline, err := s.db.GetDetectionTimeline(days)
	if err != nil {
		http.Error(w, "Failed to get timeline", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(timeline)
}

func (s *Server) handleGetTopIndicators(w http.ResponseWriter, r *http.Request) {
	limit := 10 // Default top 10
	indicators, err := s.db.GetTopIndicators(limit)
	if err != nil {
		http.Error(w, "Failed to get top indicators", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(indicators)
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":     "healthy",
		"time":       time.Now().UTC(),
		"database":   s.db.IsHealthy(),
		"clients":    len(s.clients),
		"version":    "1.0.0",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleDashboardRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
}

// WebSocket handling

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	
	client := &Client{
		ID:       generateClientID(),
		LastSeen: time.Now(),
		conn:     conn,
	}
	
	s.clientsMux.Lock()
	s.clients[client.ID] = client
	s.clientsMux.Unlock()
	
	defer func() {
		s.clientsMux.Lock()
		delete(s.clients, client.ID)
		s.clientsMux.Unlock()
		conn.Close()
	}()
	
	// Send initial data
	initialData := map[string]interface{}{
		"type":    "connected",
		"message": "Connected to SandboxSpy server",
		"time":    time.Now().UTC(),
	}
	conn.WriteJSON(initialData)
	
	// Keep connection alive
	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}
		
		// Handle ping/pong
		if msg["type"] == "ping" {
			conn.WriteJSON(map[string]interface{}{
				"type": "pong",
				"time": time.Now().UTC(),
			})
		}
	}
}

func (s *Server) websocketBroadcaster() {
	for {
		msg := <-s.broadcast
		
		s.clientsMux.RLock()
		for _, client := range s.clients {
			err := client.conn.WriteJSON(msg)
			if err != nil {
				client.conn.Close()
			}
		}
		s.clientsMux.RUnlock()
	}
}

// Helper functions

func (s *Server) updateClientTracking(apiKey, remoteAddr string) {
	s.clientsMux.Lock()
	defer s.clientsMux.Unlock()
	
	if client, exists := s.clients[apiKey]; exists {
		client.LastSeen = time.Now()
		client.RequestCount++
	} else {
		s.clients[apiKey] = &Client{
			ID:           apiKey,
			APIKey:       apiKey,
			LastSeen:     time.Now(),
			RequestCount: 1,
		}
	}
}

// Start starts the server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		srv.Shutdown(ctx)
		s.db.Close()
	}()
	
	log.Printf("SandboxSpy Server starting on %s", addr)
	
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return srv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	
	return srv.ListenAndServe()
}

// responseRecorder to capture status codes
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *responseRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func main() {
	configFile := "server_config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	
	config, err := LoadServerConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	server := NewServer(config)
	
	if err := server.Initialize(); err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	
	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}