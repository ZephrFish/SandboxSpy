package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/models"
	"github.com/zephrfish/sandboxspy/pkg/security"
)

// SecurityMiddleware provides security features for HTTP handlers
type SecurityMiddleware struct {
	validator       *security.Validator
	rateLimiter     *security.MultiKeyRateLimiter
	apiKeys         map[string]string // API key -> client identifier
	cloudfrontSecret string
	enableAuth      bool
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(apiKeys map[string]string, cloudfrontSecret string, enableAuth bool) *SecurityMiddleware {
	sm := &SecurityMiddleware{
		validator:        security.NewValidator(),
		rateLimiter:     security.NewMultiKeyRateLimiter(),
		apiKeys:         apiKeys,
		cloudfrontSecret: cloudfrontSecret,
		enableAuth:      enableAuth,
	}
	
	// Configure rate limiters for different API key tiers
	sm.rateLimiter.AddLimiter("default", 100, time.Minute)
	sm.rateLimiter.AddLimiterWithBurst("premium", 1000, time.Minute, 2000)
	sm.rateLimiter.AddLimiterWithBurst("submission", 10, time.Minute, 20)
	
	return sm
}

// ValidateAPIKey validates the API key and returns the client identifier
func (sm *SecurityMiddleware) ValidateAPIKey(r *http.Request) (string, bool) {
	if !sm.enableAuth {
		return "anonymous", true
	}
	
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Try query parameter as fallback
		apiKey = r.URL.Query().Get("api_key")
	}
	
	if apiKey == "" {
		return "", false
	}
	
	// Validate API key format
	if err := sm.validator.ValidateAPIKey(apiKey); err != nil {
		log.Printf("Invalid API key format: %v", err)
		return "", false
	}
	
	clientID, valid := sm.apiKeys[apiKey]
	return clientID, valid
}

// AuthMiddleware provides API key authentication
func (sm *SecurityMiddleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID, valid := sm.ValidateAPIKey(r)
		if !valid {
			http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
			return
		}
		
		// Add client ID to request context
		r.Header.Set("X-Client-ID", clientID)
		
		next(w, r)
	}
}

// RateLimitMiddleware provides per-API-key rate limiting
func (sm *SecurityMiddleware) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.Header.Get("X-Client-ID")
		if clientID == "" {
			clientID = "anonymous"
		}
		
		// Determine rate limit tier based on endpoint
		tier := "default"
		if strings.Contains(r.URL.Path, "/sandbox") {
			tier = "submission"
		}
		
		// Check rate limit
		allowed, err := sm.rateLimiter.Allow(tier, clientID)
		if err != nil {
			// No rate limiter configured for this tier, use default
			allowed, _ = sm.rateLimiter.Allow("default", clientID)
		}
		
		if !allowed {
			// Get rate limiter to provide reset time
			limiter, _ := sm.rateLimiter.GetLimiter(tier)
			if limiter != nil {
				resetTime := limiter.GetResetTime(clientID)
				w.Header().Set("X-RateLimit-Reset", resetTime.Format(time.RFC3339))
				w.Header().Set("X-RateLimit-Remaining", "0")
			}
			
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		// Add rate limit headers
		if limiter, err := sm.rateLimiter.GetLimiter(tier); err == nil {
			remaining := limiter.GetRemaining(clientID)
			resetTime := limiter.GetResetTime(clientID)
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", resetTime.Format(time.RFC3339))
		}
		
		next(w, r)
	}
}

// ValidateInputMiddleware validates and sanitizes input data
func (sm *SecurityMiddleware) ValidateInputMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only validate for POST/PUT/PATCH requests
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
			next(w, r)
			return
		}
		
		// Parse body for validation
		if strings.Contains(r.URL.Path, "/sandbox") {
			var entry models.SandboxEntry
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&entry); err != nil {
				http.Error(w, "Invalid JSON format", http.StatusBadRequest)
				return
			}
			
			// Validate all fields
			if err := sm.ValidateSandboxEntry(&entry); err != nil {
				http.Error(w, "Validation failed: "+err.Error(), http.StatusBadRequest)
				return
			}
			
			// Re-encode the validated and sanitized data
			validatedBody, err := json.Marshal(entry)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			
			// Replace request body with validated data
			r.Body = &ValidatedBody{data: validatedBody}
			r.ContentLength = int64(len(validatedBody))
		}
		
		next(w, r)
	}
}

// CloudFrontMiddleware validates CloudFront origin requests
func (sm *SecurityMiddleware) CloudFrontMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip if CloudFront secret is not configured
		if sm.cloudfrontSecret == "" {
			next(w, r)
			return
		}
		
		// Check CloudFront secret header
		cfSecret := r.Header.Get("X-CloudFront-Secret")
		if cfSecret != sm.cloudfrontSecret {
			http.Error(w, "Access denied: Invalid origin", http.StatusForbidden)
			return
		}
		
		next(w, r)
	}
}

// SecurityHeadersMiddleware adds security headers to responses
func (sm *SecurityMiddleware) SecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
		
		// Add HSTS for HTTPS connections
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		next(w, r)
	}
}

// ValidateSandboxEntry validates all fields of a sandbox entry
func (sm *SecurityMiddleware) ValidateSandboxEntry(entry *models.SandboxEntry) error {
	// Validate hostname
	if err := sm.validator.ValidateHostname(entry.Hostname); err != nil {
		return err
	}
	
	// Validate username
	if err := sm.validator.ValidateUsername(entry.Username); err != nil {
		return err
	}
	
	// Validate domain
	if err := sm.validator.ValidateDomain(entry.Domain); err != nil {
		return err
	}
	
	// Validate IP address
	if err := sm.validator.ValidateIPAddress(entry.IPAddress); err != nil {
		return err
	}
	
	// Validate MAC addresses
	for _, mac := range entry.MACAddresses {
		if err := sm.validator.ValidateMACAddress(mac); err != nil {
			return err
		}
	}
	
	// Validate processes
	for _, process := range entry.Processes {
		if err := sm.validator.ValidateProcessName(process); err != nil {
			return err
		}
	}
	
	// Validate file paths
	for _, path := range entry.FilePaths {
		if err := sm.validator.ValidateFilePath(path); err != nil {
			return err
		}
	}
	
	// Validate fingerprint
	if err := sm.validator.ValidateFingerprint(entry.Fingerprint); err != nil {
		return err
	}
	
	// Validate tags
	if err := sm.validator.ValidateTags(entry.Tags); err != nil {
		return err
	}
	
	// Sanitize string fields
	entry.Hostname = sm.validator.SanitizeString(entry.Hostname)
	entry.Username = sm.validator.SanitizeString(entry.Username)
	entry.Domain = sm.validator.SanitizeString(entry.Domain)
	
	return nil
}

// ValidatedBody wraps validated request body data
type ValidatedBody struct {
	data []byte
	pos  int
}

// Read implements io.Reader for ValidatedBody
func (vb *ValidatedBody) Read(p []byte) (n int, err error) {
	if vb.pos >= len(vb.data) {
		return 0, nil
	}
	
	n = copy(p, vb.data[vb.pos:])
	vb.pos += n
	return n, nil
}

// Close implements io.Closer for ValidatedBody
func (vb *ValidatedBody) Close() error {
	return nil
}

// Chain combines multiple middleware functions
func Chain(middlewares ...func(http.HandlerFunc) http.HandlerFunc) func(http.HandlerFunc) http.HandlerFunc {
	return func(final http.HandlerFunc) http.HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}