#!/bin/bash
# SandboxSpy Windows Build Script
# Builds Windows executables with embedded server configuration

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
VERSION=${VERSION:-"2.0.0"}
BUILD_TIME=$(date +%FT%T%z)
SERVER_URL=${SERVER_URL:-"http://localhost:8080"}
API_KEY=${API_KEY:-"sandboxspy-$(openssl rand -hex 16)"}

echo -e "${GREEN}=== SandboxSpy Windows Build ===${NC}"
echo "Version: $VERSION"
echo "Server URL: $SERVER_URL"
echo "API Key: $API_KEY"
echo ""

# Create output directory
mkdir -p output
mkdir -p configs

# Create client configuration with embedded server URL
cat > configs/config.json <<EOF
{
  "logging": {
    "enabled": true,
    "provider": "server",
    "endpoints": {
      "server": {
        "url": "$SERVER_URL",
        "api_key": "$API_KEY"
      }
    },
    "retry_policy": {
      "max_retries": 3,
      "backoff_seconds": 2
    }
  },
  "detection": {
    "auto_index_new": true,
    "confidence_threshold": 0.5,
    "ip_range_detection": true,
    "process_monitoring": true
  },
  "blocklist": {
    "auto_update": true,
    "update_interval_hours": 24,
    "export_formats": ["json", "txt", "csv", "snort"]
  }
}
EOF

# Build Windows 64-bit executable
echo -e "${YELLOW}Building Windows 64-bit executable...${NC}"
GOOS=windows GOARCH=amd64 go build \
    -ldflags="-s -w -H=windowsgui -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o output/SandboxSpy-x64.exe \
    cmd/client/main.go

# Build Windows 32-bit executable
echo -e "${YELLOW}Building Windows 32-bit executable...${NC}"
GOOS=windows GOARCH=386 go build \
    -ldflags="-s -w -H=windowsgui -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o output/SandboxSpy-x86.exe \
    cmd/client/main.go

# Copy configuration to output
cp configs/config.json output/

# Build server for local testing
echo -e "${YELLOW}Building server for local testing...${NC}"
go build \
    -ldflags="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o output/sandboxspy-server \
    cmd/server/main.go

# Create server configuration
cat > output/server_config.json <<EOF
{
  "host": "0.0.0.0",
  "port": 8080,
  "database_path": "sandboxspy.db",
  "api_key": "$API_KEY",
  "enable_auth": true,
  "rate_limit": 100,
  "enable_websocket": true,
  "enable_dashboard": true
}
EOF

echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo ""
echo "Output files:"
echo "  - output/SandboxSpy-x64.exe    (Windows 64-bit client)"
echo "  - output/SandboxSpy-x86.exe    (Windows 32-bit client)"
echo "  - output/config.json           (Client configuration)"
echo "  - output/sandboxspy-server     (Server binary)"
echo "  - output/server_config.json   (Server configuration)"
echo ""
echo "The Windows executables are pre-configured to connect to:"
echo "  Server URL: $SERVER_URL"
echo "  API Key: $API_KEY"
echo ""
echo "To start the server locally:"
echo "  cd output && ./sandboxspy-server server_config.json"
echo ""
echo "To deploy clients:"
echo "  1. Copy SandboxSpy-x64.exe (or x86) to target Windows system"
echo "  2. Copy config.json to same directory as executable"
echo "  3. Run the executable - it will automatically connect to server"