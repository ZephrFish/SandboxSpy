# SandboxSpy

A sandbox detection and monitoring system that collects environmental data from potentially malicious environments to build blocklists for security researchers.

## Overview

SandboxSpy consists of a client that detects sandbox environments and a server that collects and aggregates this data. The system identifies sandboxes through various detection methods including hostname patterns, MAC addresses, running processes, and timing anomalies.

## Features

- Multiple sandbox detection techniques
- Client-server architecture with REST API
- Real-time WebSocket updates
- Web dashboard for monitoring
- Automatic blocklist generation in multiple formats (JSON, CSV, TXT, Snort, IOC)
- Docker deployment support
- CloudFront CDN integration

## Quick Start

### Build Windows Clients

```bash
# Build Windows executables with embedded server URL
SERVER_URL="https://your-server.com" API_KEY="your-api-key" ./build-windows.sh

# Output files will be in output/ directory:
# - SandboxSpy-x64.exe (64-bit Windows)
# - SandboxSpy-x86.exe (32-bit Windows)
```

### Run Server Locally

```bash
# Start server on port 8080
go run cmd/server/main.go

# Access dashboard at http://localhost:8080/dashboard/
```

### Docker Deployment

```bash
# Production deployment with Docker Compose
cd deployments/docker
docker-compose -f docker-compose.prod.yml up -d

# This starts:
# - Nginx reverse proxy with SSL
# - SandboxSpy server
# - PostgreSQL database
# - Redis cache
```

## API Endpoints

- `GET /api/v1/health` - Health check
- `POST /api/v1/sandbox` - Submit sandbox data
- `GET /api/v1/sandbox` - List sandbox entries
- `GET /api/v1/blocklist` - Get blocklist
- `GET /api/v1/export` - Export data in various formats
- `GET /api/v1/stats` - Get statistics
- `WS /ws` - WebSocket for real-time updates

## Configuration

Server configuration is done through `server_config.json`:

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "database_path": "sandboxspy.db",
  "api_key": "your-api-key",
  "enable_auth": true,
  "rate_limit": 100,
  "enable_websocket": true,
  "enable_dashboard": true
}
```

## Detection Methods

The client detects sandboxes using:

- Known sandbox hostnames and usernames
- Virtual machine MAC address patterns
- Sandbox-specific processes and files
- Timing anomalies
- CPU core count and memory checks

## Project Structure

```
SandboxSpy/
├── cmd/                    # Entry points
│   ├── client/            # Client executable
│   └── server/            # Server executable
├── pkg/                   # Core packages
│   ├── client/           # Client library
│   ├── detector/         # Detection engine
│   ├── server/           # Server implementation
│   ├── models/           # Data models
│   ├── security/         # Security components
│   └── middleware/       # HTTP middleware
├── deployments/          # Deployment configurations
│   ├── docker/          # Docker files
│   └── aws/             # AWS/Terraform configs
├── scripts/             # Utility scripts
└── output/              # Built executables
```

## Building from Source

```bash
# Install dependencies
go mod download

# Build server
go build -o sandboxspy-server cmd/server/main.go

# Build client
GOOS=windows GOARCH=amd64 go build -o sandboxspy-client.exe cmd/client/main.go
```

## Requirements

- Go 1.19 or higher
- Docker and Docker Compose (for containerized deployment)
- PostgreSQL (for production)
- Redis (for caching)

## License

MIT License