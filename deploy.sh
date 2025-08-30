#!/bin/bash
# SandboxSpy Production Deployment Script
# Deploys to web server with optional CloudFront

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
DEPLOYMENT_TYPE=${1:-docker}  # docker, aws, or manual
DOMAIN=${DOMAIN:-"sandboxspy.example.com"}
CLOUDFRONT_ENABLED=${CLOUDFRONT_ENABLED:-false}
SSL_CERT_PATH=${SSL_CERT_PATH:-""}
SSL_KEY_PATH=${SSL_KEY_PATH:-""}

echo -e "${GREEN}=== SandboxSpy Production Deployment ===${NC}"
echo "Deployment Type: $DEPLOYMENT_TYPE"
echo "Domain: $DOMAIN"
echo "CloudFront: $CLOUDFRONT_ENABLED"
echo ""

# Generate secure API key if not set
if [ -z "$API_KEY" ]; then
    API_KEY=$(openssl rand -hex 32)
    echo -e "${YELLOW}Generated API Key: $API_KEY${NC}"
fi

# Generate database password
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(openssl rand -hex 16)
    echo -e "${YELLOW}Generated DB Password: $DB_PASSWORD${NC}"
fi

# Generate CloudFront secret if enabled
if [ "$CLOUDFRONT_ENABLED" = "true" ] && [ -z "$CLOUDFRONT_SECRET" ]; then
    CLOUDFRONT_SECRET=$(openssl rand -hex 32)
    echo -e "${YELLOW}Generated CloudFront Secret: $CLOUDFRONT_SECRET${NC}"
fi

# Function to deploy with Docker Compose
deploy_docker() {
    echo -e "${YELLOW}Deploying with Docker Compose...${NC}"
    
    # Create .env file
    cat > deployments/docker/.env <<EOF
API_KEY=$API_KEY
DB_PASSWORD=$DB_PASSWORD
CLOUDFRONT_SECRET=$CLOUDFRONT_SECRET
ALLOWED_ORIGINS=https://$DOMAIN
EOF
    
    # Create server config
    cat > deployments/docker/server_config_prod.json <<EOF
{
  "host": "0.0.0.0",
  "port": 8080,
  "database_path": "/data/sandboxspy.db",
  "api_key": "$API_KEY",
  "enable_auth": true,
  "rate_limit": 100,
  "enable_websocket": true,
  "enable_dashboard": true,
  "enable_cors": true,
  "allowed_origins": ["https://$DOMAIN"],
  "cloudfront_secret": "$CLOUDFRONT_SECRET"
}
EOF
    
    # Setup SSL certificates
    if [ -n "$SSL_CERT_PATH" ] && [ -n "$SSL_KEY_PATH" ]; then
        mkdir -p deployments/docker/ssl
        cp "$SSL_CERT_PATH" deployments/docker/ssl/fullchain.pem
        cp "$SSL_KEY_PATH" deployments/docker/ssl/privkey.pem
    else
        echo -e "${YELLOW}No SSL certificates provided. Using self-signed...${NC}"
        mkdir -p deployments/docker/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout deployments/docker/ssl/privkey.pem \
            -out deployments/docker/ssl/fullchain.pem \
            -subj "/CN=$DOMAIN"
    fi
    
    # Build and start services
    cd deployments/docker
    docker-compose -f docker-compose.prod.yml build
    docker-compose -f docker-compose.prod.yml up -d
    
    echo -e "${GREEN}Docker deployment complete!${NC}"
    echo "Services running at https://$DOMAIN"
}

# Function to deploy to AWS with CloudFront
deploy_aws() {
    echo -e "${YELLOW}Deploying to AWS with CloudFront...${NC}"
    
    # Check prerequisites
    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}Terraform not installed. Please install Terraform first.${NC}"
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}AWS CLI not installed. Please install AWS CLI first.${NC}"
        exit 1
    fi
    
    cd deployments/aws/terraform
    
    # Initialize Terraform
    terraform init
    
    # Deploy infrastructure
    terraform apply -var="domain_name=$DOMAIN" -auto-approve
    
    # Get outputs
    CLOUDFRONT_URL=$(terraform output -raw cloudfront_url)
    SERVER_IP=$(terraform output -raw server_ip)
    API_KEY=$(terraform output -raw api_key)
    
    echo -e "${GREEN}AWS deployment complete!${NC}"
    echo "CloudFront URL: $CLOUDFRONT_URL"
    echo "Server IP: $SERVER_IP"
    echo "API Key: $API_KEY"
}

# Function to build clients with production URLs
build_clients() {
    echo -e "${YELLOW}Building client executables...${NC}"
    
    if [ "$CLOUDFRONT_ENABLED" = "true" ]; then
        SERVER_URL="https://$DOMAIN"
    else
        SERVER_URL="https://$DOMAIN"
    fi
    
    # Build Windows clients
    SERVER_URL="$SERVER_URL" API_KEY="$API_KEY" ./build-windows.sh
    
    echo -e "${GREEN}Client build complete!${NC}"
    echo "Clients configured for: $SERVER_URL"
}

# Function to setup monitoring
setup_monitoring() {
    echo -e "${YELLOW}Setting up monitoring...${NC}"
    
    # Create monitoring compose file
    cat > deployments/docker/docker-compose.monitoring.yml <<'EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: sandboxspy-prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - sandboxspy-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: sandboxspy-grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=redis-datasource
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"
    networks:
      - sandboxspy-network
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:

networks:
  sandboxspy-network:
    external: true
EOF
    
    # Create Prometheus config
    cat > deployments/docker/prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'sandboxspy'
    static_configs:
      - targets: ['server:9090']
EOF
    
    echo -e "${GREEN}Monitoring setup complete!${NC}"
}

# Function to display deployment info
show_deployment_info() {
    echo ""
    echo -e "${GREEN}=== Deployment Complete ===${NC}"
    echo ""
    echo "Server URL: https://$DOMAIN"
    echo "API Key: $API_KEY"
    echo "Dashboard: https://$DOMAIN/dashboard/"
    echo ""
    echo "Client Configuration:"
    echo "  Server URL: https://$DOMAIN"
    echo "  API Key: $API_KEY"
    echo ""
    if [ "$CLOUDFRONT_ENABLED" = "true" ]; then
        echo "CloudFront Secret: $CLOUDFRONT_SECRET"
        echo "Configure CloudFront origin with this secret header."
        echo ""
    fi
    echo "To test the deployment:"
    echo "  curl -H 'X-API-Key: $API_KEY' https://$DOMAIN/api/v1/health"
    echo ""
    echo "Windows clients are in: output/"
    echo "Deploy them to target systems with the config.json file."
}

# Function to create systemd service
create_systemd_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/sandboxspy.service <<EOF
[Unit]
Description=SandboxSpy Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/opt/sandboxspy
ExecStart=/usr/local/bin/docker-compose -f deployments/docker/docker-compose.prod.yml up
ExecStop=/usr/local/bin/docker-compose -f deployments/docker/docker-compose.prod.yml down

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sandboxspy
    echo -e "${GREEN}Systemd service created!${NC}"
}

# Main deployment logic
case "$DEPLOYMENT_TYPE" in
    docker)
        deploy_docker
        build_clients
        show_deployment_info
        ;;
    aws)
        deploy_aws
        build_clients
        show_deployment_info
        ;;
    manual)
        echo "Manual deployment selected."
        echo "Server binary: bin/sandboxspy-server"
        echo "Configuration: server_config.json"
        build_clients
        show_deployment_info
        ;;
    monitoring)
        setup_monitoring
        ;;
    systemd)
        create_systemd_service
        ;;
    *)
        echo "Usage: $0 [docker|aws|manual|monitoring|systemd]"
        echo ""
        echo "Environment variables:"
        echo "  DOMAIN - Your domain name"
        echo "  API_KEY - API key for authentication"
        echo "  CLOUDFRONT_ENABLED - Enable CloudFront integration"
        echo "  SSL_CERT_PATH - Path to SSL certificate"
        echo "  SSL_KEY_PATH - Path to SSL private key"
        exit 1
        ;;
esac