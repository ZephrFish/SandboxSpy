#!/bin/bash
# SandboxSpy Build Script
# Builds everything including Docker images with pre-configured URLs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}
BUILD_TIME=$(date +%FT%T%z)
SERVER_URL=${SERVER_URL:-"http://localhost:8080"}
API_KEY=${API_KEY:-"sandboxspy-$(openssl rand -hex 16)"}

echo -e "${GREEN}=== SandboxSpy Build System ===${NC}"
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Server URL: $SERVER_URL"
echo ""

# Function to print status
print_status() {
    echo -e "${YELLOW}>>> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Build with Docker (recommended)
build_docker() {
    print_status "Building Docker image with all components..."
    
    docker build \
        --build-arg SERVER_URL="$SERVER_URL" \
        --build-arg API_KEY="$API_KEY" \
        -f deployments/docker/Dockerfile.all-in-one \
        -t sandboxspy:latest \
        -t sandboxspy:$VERSION \
        .
    
    print_success "Docker image built: sandboxspy:$VERSION"
}

# Extract binaries from Docker
extract_binaries() {
    print_status "Extracting binaries from Docker image..."
    
    mkdir -p ./output
    
    # Run container to export binaries
    docker run --rm \
        -v "$(pwd)/output:/output" \
        sandboxspy:latest export
    
    print_success "Binaries extracted to ./output/"
}

# Build server natively
build_server_native() {
    print_status "Building server binary natively..."
    
    mkdir -p bin
    
    CGO_ENABLED=1 go build \
        -ldflags="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
        -o bin/sandboxspy-server \
        ./cmd/server
    
    print_success "Server built: bin/sandboxspy-server"
}

# Build client natively
build_client_native() {
    print_status "Building client binaries natively..."
    
    mkdir -p bin
    
    # Windows 64-bit
    GOOS=windows GOARCH=amd64 go build \
        -ldflags="-s -w -H=windowsgui -X main.Version=$VERSION" \
        -o bin/sandboxspy-windows-amd64.exe \
        ./cmd/client
    
    # Windows 32-bit
    GOOS=windows GOARCH=386 go build \
        -ldflags="-s -w -H=windowsgui -X main.Version=$VERSION" \
        -o bin/sandboxspy-windows-386.exe \
        ./cmd/client
    
    # Linux 64-bit
    GOOS=linux GOARCH=amd64 go build \
        -ldflags="-s -w -X main.Version=$VERSION" \
        -o bin/sandboxspy-linux-amd64 \
        ./cmd/client
    
    # macOS 64-bit
    GOOS=darwin GOARCH=amd64 go build \
        -ldflags="-s -w -X main.Version=$VERSION" \
        -o bin/sandboxspy-darwin-amd64 \
        ./cmd/client
    
    print_success "Client binaries built in bin/"
}

# Create config files
create_configs() {
    print_status "Creating configuration files..."
    
    mkdir -p configs
    
    # Client config
    cat > configs/client_config.json <<EOF
{
  "logging": {
    "enabled": true,
    "provider": "server",
    "endpoints": {
      "server": {
        "url": "$SERVER_URL",
        "api_key": "$API_KEY"
      }
    }
  },
  "detection": {
    "auto_index_new": true,
    "confidence_threshold": 0.5
  }
}
EOF
    
    # Server config
    cat > configs/server_config.json <<EOF
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
    
    print_success "Configuration files created in configs/"
    echo -e "${YELLOW}API Key: $API_KEY${NC}"
}

# Run docker-compose
run_docker_compose() {
    print_status "Starting services with docker-compose..."
    
    export API_KEY
    docker-compose -f deployments/docker/docker-compose.yml up -d
    
    print_success "Services started. Dashboard: http://localhost:8080/dashboard"
}

# Show usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all        - Build everything (Docker + native)"
    echo "  docker     - Build Docker image only"
    echo "  native     - Build native binaries only"
    echo "  extract    - Extract binaries from Docker image"
    echo "  configs    - Create configuration files"
    echo "  run        - Run with docker-compose"
    echo "  clean      - Clean build artifacts"
    echo ""
    echo "Environment variables:"
    echo "  SERVER_URL - Server URL for clients (default: http://localhost:8080)"
    echo "  API_KEY    - API key for authentication (default: auto-generated)"
    echo "  VERSION    - Version tag (default: from git)"
}

# Clean build artifacts
clean() {
    print_status "Cleaning build artifacts..."
    rm -rf bin/ output/ configs/
    docker rmi sandboxspy:latest 2>/dev/null || true
    print_success "Clean complete"
}

# Main execution
main() {
    case "${1:-all}" in
        all)
            check_prerequisites
            create_configs
            build_docker
            extract_binaries
            echo ""
            print_success "Build complete!"
            echo -e "${GREEN}Binaries available in ./output/${NC}"
            echo -e "${GREEN}Configs available in ./configs/${NC}"
            echo ""
            echo "To run the server:"
            echo "  docker run -p 8080:8080 sandboxspy:latest server"
            echo ""
            echo "To run with docker-compose:"
            echo "  ./build.sh run"
            ;;
        docker)
            check_prerequisites
            build_docker
            ;;
        native)
            check_prerequisites
            build_server_native
            build_client_native
            ;;
        extract)
            extract_binaries
            ;;
        configs)
            create_configs
            ;;
        run)
            check_prerequisites
            run_docker_compose
            ;;
        clean)
            clean
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"