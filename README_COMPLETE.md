# SandboxSpy - Complete Sandbox Detection & Intelligence Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Go](https://img.shields.io/badge/go-1.19+-blue.svg)]()
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)]()

## 🎯 Overview

SandboxSpy is a comprehensive sandbox detection and intelligence platform designed for defensive security research. It automatically detects sandbox environments, collects indicators, and builds collaborative blocklists for the security research community.

### Key Features

- **🔍 Advanced Detection**: Multiple detection methods including file paths, processes, network, timing, and behavioral analysis
- **☁️ Cloud Intelligence**: Centralized collection and sharing of sandbox indicators
- **🐳 Docker-Ready**: Pre-configured Docker images with embedded URLs and API keys
- **📊 Real-time Dashboard**: Web-based monitoring with WebSocket updates
- **🔐 Secure by Design**: API authentication, rate limiting, and encrypted communications
- **📦 Multi-Platform**: Builds for Windows (32/64-bit), Linux, and macOS
- **🚀 Easy Deployment**: One-command build and deployment system

## 🚀 Quick Start

### Option 1: Docker (Recommended) - All-in-One Build

```bash
# Clone the repository
git clone https://github.com/zephrfish/sandboxspy.git
cd sandboxspy

# Build everything with Docker (includes pre-configured URLs)
./build.sh all

# This will:
# 1. Build Docker image with server and all client binaries
# 2. Extract binaries to ./output/
# 3. Create configs with auto-generated API key
# 4. Configure clients with server URL
```

### Option 2: Run Complete Stack

```bash
# Start server and all services
./build.sh run

# Access dashboard at http://localhost:8080/dashboard
# API key will be displayed in console
```

### Option 3: Manual Docker Build

```bash
# Build the all-in-one Docker image
docker build -f deployments/docker/Dockerfile.all-in-one -t sandboxspy:latest .

# Run server
docker run -d -p 8080:8080 -v $(pwd)/data:/data sandboxspy:latest server

# Export client binaries with pre-configured URLs
docker run -v $(pwd)/output:/output sandboxspy:latest export
```

## 📦 Installation

### Prerequisites

- Go 1.19+ (for native builds)
- Docker & Docker Compose
- Git

### Complete Installation

```bash
# Install dependencies
go mod download

# Build everything
make all

# Or use the build script
./build.sh all
```

## 🏗️ Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Windows Client  │────▶│                  │────▶│                  │
├──────────────────┤     │  SandboxSpy      │     │   PostgreSQL/    │
│   Linux Client   │────▶│     Server       │────▶│     SQLite       │
├──────────────────┤     │                  │     │                  │
│   macOS Client   │────▶│   (Port 8080)    │────▶│    Database      │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                 │
                                 ▼
                         ┌──────────────────┐
                         │  Web Dashboard   │
                         │  (Real-time)     │
                         └──────────────────┘
```

## 🔧 Configuration

### Client Configuration (Auto-Generated)

The Docker build automatically configures clients with:

```json
{
  "logging": {
    "enabled": true,
    "provider": "server",
    "endpoints": {
      "server": {
        "url": "http://your-server:8080",
        "api_key": "auto-generated-key"
      }
    }
  },
  "detection": {
    "confidence_threshold": 0.5
  }
}
```

### Server Configuration

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "api_key": "your-secure-api-key",
  "enable_dashboard": true,
  "enable_websocket": true
}
```

## 🐳 Docker Usage

### Build All Components

```bash
# Build with custom server URL and API key
docker build \
  --build-arg SERVER_URL=https://your-server.com \
  --build-arg API_KEY=your-api-key \
  -f deployments/docker/Dockerfile.all-in-one \
  -t sandboxspy:latest .
```

### Run Server

```bash
docker run -d \
  --name sandboxspy-server \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  sandboxspy:latest server
```

### Extract Client Binaries

```bash
# Extract all pre-configured client binaries
docker run --rm \
  -v $(pwd)/output:/output \
  sandboxspy:latest export

# Binaries will be in ./output/ with embedded configuration
```

### Docker Compose Stack

```bash
# Start full stack (server, redis, postgres, dashboard)
docker-compose -f deployments/docker/docker-compose.yml up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 📊 Web Dashboard

Access the dashboard at `http://localhost:8080/dashboard`

Features:
- Real-time detection updates via WebSocket
- Statistics and metrics
- Blocklist export (JSON, CSV, Snort rules)
- Search and filtering
- Detection timeline visualization

## 🔌 API Documentation

### Submit Detection

```bash
curl -X POST http://localhost:8080/api/v1/sandbox \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "SANDBOX-PC",
    "confidence": 0.85,
    "ip_address": "192.168.1.100"
  }'
```

### Get Blocklist

```bash
curl -X GET http://localhost:8080/api/v1/blocklist \
  -H "X-API-Key: your-api-key"
```

### Export Blocklist

```bash
# Snort rules
curl -X GET "http://localhost:8080/api/v1/blocklist/export?format=snort" \
  -H "X-API-Key: your-api-key" \
  -o sandbox.rules
```

## 🛠️ Development

### Project Structure

```
sandboxspy/
├── cmd/                    # Application entrypoints
│   ├── client/            # Client application
│   └── server/            # Server application
├── pkg/                   # Go packages
│   ├── client/           # Client library
│   ├── detector/         # Detection engine
│   ├── models/           # Data models
│   └── server/           # Server implementation
├── deployments/          # Deployment configurations
│   └── docker/          # Docker files
├── server/              # Legacy server code
│   └── web/            # Dashboard files
├── build.sh            # Build automation script
├── Makefile           # Make targets
└── go.mod             # Go module definition
```

### Building from Source

```bash
# Build server
go build -o bin/sandboxspy-server cmd/server/main.go

# Build client for Windows
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w -H=windowsgui" \
  -o bin/sandboxspy.exe cmd/client/main.go

# Build all platforms
make all
```

### Testing

```bash
# Run tests
make test

# Run with coverage
make coverage

# Run linters
make lint
```

## 🔍 Detection Methods

SandboxSpy uses multiple detection techniques:

1. **File System Detection**
   - VMware tools and drivers
   - VirtualBox Guest Additions
   - QEMU guest agent

2. **Process Detection**
   - Virtualization services
   - Analysis tools
   - Monitoring processes

3. **Network Detection**
   - MAC address prefixes
   - IP range analysis
   - Network adapter names

4. **Behavioral Detection**
   - Timing anomalies
   - Resource constraints
   - System characteristics

5. **Environment Detection**
   - Hostname patterns
   - Username patterns
   - Domain indicators

## 📈 Monitoring & Metrics

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sandboxspy'
    static_configs:
      - targets: ['localhost:9090']
```

### Grafana Dashboard

Import the dashboard from `deployments/grafana/dashboard.json`

## 🔒 Security Considerations

- **API Authentication**: All API endpoints require authentication
- **Rate Limiting**: Configurable rate limits prevent abuse
- **Data Privacy**: No sensitive data is collected
- **Secure Communications**: Support for TLS/HTTPS
- **Input Validation**: All inputs are validated and sanitized

## 🚢 Deployment

### Kubernetes

```bash
kubectl apply -f deployments/k8s/
```

### Docker Swarm

```bash
docker stack deploy -c deployments/docker/docker-compose.yml sandboxspy
```

### Systemd Service

```bash
sudo cp deployments/systemd/sandboxspy.service /etc/systemd/system/
sudo systemctl enable sandboxspy
sudo systemctl start sandboxspy
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

SandboxSpy is intended for defensive security research purposes only. Use responsibly and in accordance with applicable laws and regulations.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/zephrfish/sandboxspy/issues)
- **Documentation**: [Wiki](https://github.com/zephrfish/sandboxspy/wiki)
- **Community**: Security research forums

## 🎉 Quick Commands Reference

```bash
# Build everything
./build.sh all

# Start server
docker run -p 8080:8080 sandboxspy:latest server

# Run client
docker run sandboxspy:latest client

# Export binaries
docker run -v $(pwd)/output:/output sandboxspy:latest export

# Access dashboard
open http://localhost:8080/dashboard

# View API health
curl http://localhost:8080/api/v1/health

# Clean everything
./build.sh clean
```

## 🏆 Features Checklist

- ✅ Multi-platform client support (Windows, Linux, macOS)
- ✅ Centralized server with REST API
- ✅ Real-time WebSocket updates
- ✅ Web dashboard with analytics
- ✅ Docker support with pre-configured URLs
- ✅ Automatic blocklist generation
- ✅ Multiple export formats (JSON, CSV, Snort, IOC)
- ✅ SQLite and PostgreSQL support
- ✅ Redis caching
- ✅ Prometheus metrics
- ✅ Rate limiting and authentication
- ✅ Comprehensive detection methods
- ✅ CI/CD ready
- ✅ Production-ready deployment options

---

**Built with ❤️ for the Security Research Community**