# SandboxSpy Server Deployment Guide

## Overview
The SandboxSpy Server is a centralized collection point for sandbox detection data, allowing multiple SandboxSpy clients to report findings to a central database. It provides REST APIs, WebSocket support for real-time updates, and a web dashboard for monitoring.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  SandboxSpy │────▶│  SandboxSpy  │────▶│   SQLite/    │
│   Clients   │     │    Server    │     │   Database   │
└─────────────┘     └──────────────┘     └──────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  Web Dashboard│
                    └──────────────┘
```

## Features
- **REST API**: Full CRUD operations for sandbox data
- **WebSocket**: Real-time updates for connected clients
- **Web Dashboard**: Visual monitoring interface
- **Authentication**: API key-based authentication
- **Rate Limiting**: Configurable request rate limiting
- **Multiple Export Formats**: JSON, CSV, Snort rules, IOCs
- **Database**: SQLite for easy deployment (upgradeable to PostgreSQL/MySQL)

## Installation

### Prerequisites
```bash
# Install Go dependencies
go get github.com/gorilla/mux
go get github.com/gorilla/websocket
go get github.com/mattn/go-sqlite3
go get golang.org/x/time/rate
```

### Building the Server
```bash
# Navigate to server directory
cd server/

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o sandboxspy-server *.go

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o sandboxspy-server.exe *.go

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o sandboxspy-server *.go
```

## Configuration

### Server Configuration (`server_config.json`)
```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "database_path": "sandboxspy.db",
  "api_key": "generate-a-secure-api-key-here",
  "enable_auth": true,
  "rate_limit": 100,
  "enable_websocket": true,
  "enable_dashboard": true,
  "tls_cert": "/path/to/cert.pem",
  "tls_key": "/path/to/key.pem",
  "max_request_size": 10485760,
  "session_timeout": 3600,
  "enable_cors": true,
  "allowed_origins": ["https://yourdomain.com"]
}
```

### Client Configuration (`config.json`)
```json
{
  "logging": {
    "enabled": true,
    "provider": "server",
    "endpoints": {
      "server": {
        "url": "https://your-server.com:8080",
        "api_key": "your-api-key"
      }
    }
  }
}
```

## Deployment Options

### 1. Local Development
```bash
# Start server with default config
./sandboxspy-server

# Start with custom config
./sandboxspy-server custom_config.json

# Access dashboard at http://localhost:8080/dashboard
```

### 2. Docker Deployment
```dockerfile
# Dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o sandboxspy-server server/*.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/sandboxspy-server .
COPY server/web ./web
EXPOSE 8080
CMD ["./sandboxspy-server"]
```

```bash
# Build and run
docker build -t sandboxspy-server .
docker run -d -p 8080:8080 -v $(pwd)/data:/data sandboxspy-server
```

### 3. Systemd Service (Linux)
```ini
# /etc/systemd/system/sandboxspy-server.service
[Unit]
Description=SandboxSpy Server
After=network.target

[Service]
Type=simple
User=sandboxspy
WorkingDirectory=/opt/sandboxspy
ExecStart=/opt/sandboxspy/sandboxspy-server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Install and start
sudo cp sandboxspy-server /opt/sandboxspy/
sudo systemctl daemon-reload
sudo systemctl enable sandboxspy-server
sudo systemctl start sandboxspy-server
```

### 4. Cloud Deployment

#### AWS EC2
```bash
# Launch EC2 instance (Ubuntu 20.04)
# SSH into instance

# Install dependencies
sudo apt update
sudo apt install -y golang-go git

# Clone and build
git clone https://github.com/yourusername/SandboxSpy.git
cd SandboxSpy/server
go build -o sandboxspy-server *.go

# Configure and run
nano server_config.json  # Edit configuration
nohup ./sandboxspy-server &
```

#### Heroku
```yaml
# Procfile
web: ./sandboxspy-server
```

```bash
heroku create sandboxspy-server
git push heroku main
heroku config:set API_KEY=your-secure-api-key
```

#### Docker Compose
```yaml
version: '3.8'
services:
  sandboxspy-server:
    build: ./server
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
      - ./config:/config
    environment:
      - API_KEY=${API_KEY}
    restart: unless-stopped
```

## SSL/TLS Configuration

### Using Let's Encrypt
```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Update config
{
  "tls_cert": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
  "tls_key": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
}
```

### Using Nginx Reverse Proxy
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## API Usage

### Submit Sandbox Data
```bash
curl -X POST https://your-server.com:8080/api/v1/sandbox \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "SANDBOX-PC",
    "username": "analyst",
    "ip_address": "192.168.1.100",
    "confidence": 0.85
  }'
```

### Get Blocklist
```bash
curl -X GET https://your-server.com:8080/api/v1/blocklist \
  -H "X-API-Key: your-api-key"
```

### Export Blocklist
```bash
# Export as Snort rules
curl -X GET "https://your-server.com:8080/api/v1/blocklist/export?format=snort" \
  -H "X-API-Key: your-api-key" \
  -o sandbox.rules
```

### Search Sandboxes
```bash
curl -X GET "https://your-server.com:8080/api/v1/search?q=vmware" \
  -H "X-API-Key: your-api-key"
```

## Monitoring

### Health Check
```bash
curl https://your-server.com:8080/api/v1/health
```

### Statistics
```bash
curl -X GET https://your-server.com:8080/api/v1/stats \
  -H "X-API-Key: your-api-key"
```

### Logs
```bash
# View server logs
tail -f /var/log/sandboxspy-server.log

# With systemd
journalctl -u sandboxspy-server -f
```

## Database Management

### Backup
```bash
# SQLite backup
sqlite3 sandboxspy.db ".backup backup.db"

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup/sandboxspy"
DATE=$(date +%Y%m%d_%H%M%S)
sqlite3 sandboxspy.db ".backup ${BACKUP_DIR}/sandboxspy_${DATE}.db"
```

### Migration to PostgreSQL
```sql
-- Create PostgreSQL schema
CREATE DATABASE sandboxspy;
CREATE USER sandboxspy_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE sandboxspy TO sandboxspy_user;
```

Update server code to use PostgreSQL driver:
```go
import _ "github.com/lib/pq"
db, err := sql.Open("postgres", "postgres://user:pass@localhost/sandboxspy?sslmode=disable")
```

## Security Best Practices

### 1. API Key Generation
```bash
# Generate secure API key
openssl rand -hex 32
```

### 2. Firewall Rules
```bash
# Allow only HTTPS
sudo ufw allow 443/tcp
sudo ufw deny 8080/tcp  # Block direct access
```

### 3. Rate Limiting
Configure appropriate rate limits in `server_config.json`:
```json
{
  "rate_limit": 100  // requests per second
}
```

### 4. Database Security
```bash
# Restrict database file permissions
chmod 600 sandboxspy.db
chown sandboxspy:sandboxspy sandboxspy.db
```

### 5. Regular Updates
```bash
# Update dependencies
go get -u ./...
go mod tidy
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
```bash
# Find process using port
lsof -i :8080
# Kill process
kill -9 <PID>
```

2. **Database Locked**
```bash
# Check for locks
fuser sandboxspy.db
# Remove stale lock
rm sandboxspy.db-journal
```

3. **WebSocket Connection Failed**
- Check firewall rules
- Ensure WebSocket upgrade headers are passed through proxy
- Verify CORS settings

4. **High Memory Usage**
- Implement database cleanup routine
- Set appropriate connection limits
- Enable database vacuuming for SQLite

### Debug Mode
```bash
# Enable debug logging
export SANDBOXSPY_DEBUG=true
./sandboxspy-server
```

## Performance Tuning

### Database Optimization
```sql
-- Add indexes
CREATE INDEX idx_hostname ON sandboxes(hostname);
CREATE INDEX idx_last_seen ON sandboxes(last_seen);
CREATE INDEX idx_confidence ON sandboxes(confidence);

-- Vacuum database (SQLite)
VACUUM;
```

### Connection Pooling
```go
// In server code
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Caching
Implement Redis for frequently accessed data:
```bash
# Install Redis
sudo apt install redis-server

# Configure in server
"cache": {
  "enabled": true,
  "redis_url": "localhost:6379"
}
```

## Integration Examples

### Python Client
```python
import requests

class SandboxSpyClient:
    def __init__(self, server_url, api_key):
        self.server_url = server_url
        self.api_key = api_key
        self.headers = {'X-API-Key': api_key}
    
    def submit_detection(self, hostname, ip_address, confidence=0.5):
        data = {
            'hostname': hostname,
            'ip_address': ip_address,
            'confidence': confidence
        }
        response = requests.post(
            f'{self.server_url}/api/v1/sandbox',
            json=data,
            headers=self.headers
        )
        return response.json()

# Usage
client = SandboxSpyClient('https://server.com:8080', 'api-key')
client.submit_detection('SANDBOX-001', '192.168.1.50', 0.9)
```

### Automation Script
```bash
#!/bin/bash
# Auto-export blocklist daily

SERVER="https://your-server.com:8080"
API_KEY="your-api-key"
OUTPUT_DIR="/var/blocklists"

# Export all formats
for format in json csv snort ioc; do
  curl -X GET "${SERVER}/api/v1/blocklist/export?format=${format}" \
    -H "X-API-Key: ${API_KEY}" \
    -o "${OUTPUT_DIR}/sandboxspy_$(date +%Y%m%d).${format}"
done
```

## Maintenance

### Regular Tasks
- **Daily**: Check logs, monitor disk space
- **Weekly**: Backup database, review statistics
- **Monthly**: Update dependencies, clean old entries
- **Quarterly**: Security audit, performance review

### Cleanup Script
```bash
#!/bin/bash
# Remove entries older than 90 days
sqlite3 sandboxspy.db "DELETE FROM sandboxes WHERE last_seen < datetime('now', '-90 days');"
sqlite3 sandboxspy.db "VACUUM;"
```

## Support

For issues or questions:
- Check server logs: `journalctl -u sandboxspy-server`
- Dashboard: `http://your-server:8080/dashboard`
- API Health: `http://your-server:8080/api/v1/health`

## License

This server component is part of the SandboxSpy project and is intended for defensive security research purposes only.