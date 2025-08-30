#!/bin/bash
# SandboxSpy Secret Rotation Script
# Rotates secrets and updates configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SECRETS_BACKEND=${SECRETS_BACKEND:-"aws"} # aws, vault, or local
ENVIRONMENT=${ENVIRONMENT:-"production"}
ROTATION_LOG="/var/log/sandboxspy/rotation.log"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$ROTATION_LOG"
}

# Function to generate secure random string
generate_secret() {
    local length=${1:-32}
    openssl rand -base64 "$length" | tr -d '\n'
}

# Function to rotate AWS Secrets Manager secrets
rotate_aws_secrets() {
    log "Starting AWS Secrets Manager rotation..."
    
    # Rotate API keys
    log "Rotating API keys..."
    NEW_API_KEY=$(generate_secret 64)
    aws secretsmanager put-secret-value \
        --secret-id sandboxspy/api-keys \
        --secret-string "{\"default\":\"$NEW_API_KEY\"}" \
        --version-stage AWSPENDING
    
    # Rotate database password
    log "Rotating database password..."
    NEW_DB_PASSWORD=$(generate_secret 32)
    aws secretsmanager put-secret-value \
        --secret-id sandboxspy/database \
        --secret-string "{\"password\":\"$NEW_DB_PASSWORD\"}" \
        --version-stage AWSPENDING
    
    # Rotate Redis password
    log "Rotating Redis password..."
    NEW_REDIS_PASSWORD=$(generate_secret 32)
    aws secretsmanager put-secret-value \
        --secret-id sandboxspy/redis \
        --secret-string "{\"password\":\"$NEW_REDIS_PASSWORD\"}" \
        --version-stage AWSPENDING
    
    # Test new credentials
    if test_credentials; then
        # Promote pending secrets to current
        aws secretsmanager update-secret-version-stage \
            --secret-id sandboxspy/api-keys \
            --version-stage AWSCURRENT \
            --move-to-version-id AWSPENDING
        
        aws secretsmanager update-secret-version-stage \
            --secret-id sandboxspy/database \
            --version-stage AWSCURRENT \
            --move-to-version-id AWSPENDING
        
        aws secretsmanager update-secret-version-stage \
            --secret-id sandboxspy/redis \
            --version-stage AWSCURRENT \
            --move-to-version-id AWSPENDING
        
        log "AWS secrets rotation completed successfully"
    else
        log "ERROR: New credentials validation failed, rolling back..."
        exit 1
    fi
}

# Function to rotate HashiCorp Vault secrets
rotate_vault_secrets() {
    log "Starting HashiCorp Vault rotation..."
    
    # Login to Vault
    vault login -method=aws
    
    # Rotate API keys
    log "Rotating API keys..."
    NEW_API_KEY=$(generate_secret 64)
    vault kv put secret/sandboxspy/api-keys default="$NEW_API_KEY"
    
    # Rotate database password
    log "Rotating database password..."
    vault write -force database/rotate-root/sandboxspy
    
    # Rotate Redis password
    log "Rotating Redis password..."
    NEW_REDIS_PASSWORD=$(generate_secret 32)
    vault kv put secret/sandboxspy/redis password="$NEW_REDIS_PASSWORD"
    
    log "Vault secrets rotation completed successfully"
}

# Function to rotate local secrets (development)
rotate_local_secrets() {
    log "Starting local secrets rotation..."
    
    # Backup current .env file
    cp .env .env.backup.$(date +%Y%m%d%H%M%S)
    
    # Generate new secrets
    NEW_API_KEY=$(generate_secret 64)
    NEW_DB_PASSWORD=$(generate_secret 32)
    NEW_REDIS_PASSWORD=$(generate_secret 32)
    NEW_CLOUDFRONT_SECRET=$(generate_secret 64)
    NEW_JWT_SECRET=$(generate_secret 64)
    
    # Update .env file
    sed -i.bak "s/^API_KEY=.*/API_KEY=$NEW_API_KEY/" .env
    sed -i.bak "s/^DB_PASSWORD=.*/DB_PASSWORD=$NEW_DB_PASSWORD/" .env
    sed -i.bak "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$NEW_REDIS_PASSWORD/" .env
    sed -i.bak "s/^CLOUDFRONT_SECRET=.*/CLOUDFRONT_SECRET=$NEW_CLOUDFRONT_SECRET/" .env
    sed -i.bak "s/^JWT_SECRET=.*/JWT_SECRET=$NEW_JWT_SECRET/" .env
    
    log "Local secrets rotation completed successfully"
}

# Function to test new credentials
test_credentials() {
    log "Testing new credentials..."
    
    # Test database connection
    if ! PGPASSWORD="$NEW_DB_PASSWORD" psql -h localhost -U sandboxspy -d sandboxspy -c "SELECT 1" > /dev/null 2>&1; then
        log "ERROR: Database connection test failed"
        return 1
    fi
    
    # Test Redis connection
    if ! redis-cli -a "$NEW_REDIS_PASSWORD" ping > /dev/null 2>&1; then
        log "ERROR: Redis connection test failed"
        return 1
    fi
    
    # Test API endpoint with new key
    if ! curl -s -H "X-API-Key: $NEW_API_KEY" http://localhost:8080/api/v1/health | grep -q "healthy"; then
        log "ERROR: API health check failed"
        return 1
    fi
    
    log "All credential tests passed"
    return 0
}

# Function to restart services after rotation
restart_services() {
    log "Restarting services..."
    
    case "$ENVIRONMENT" in
        docker)
            docker-compose restart
            ;;
        kubernetes)
            kubectl rollout restart deployment/sandboxspy-server
            ;;
        systemd)
            systemctl restart sandboxspy
            ;;
        *)
            log "WARNING: Unknown environment, skipping service restart"
            ;;
    esac
    
    log "Services restarted"
}

# Function to notify about rotation
notify_rotation() {
    local status=$1
    local message="Secret rotation for SandboxSpy ($ENVIRONMENT) - Status: $status"
    
    # Send Slack notification if webhook is configured
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL"
    fi
    
    # Send email notification if configured
    if [ -n "$NOTIFICATION_EMAIL" ]; then
        echo "$message" | mail -s "SandboxSpy Secret Rotation" "$NOTIFICATION_EMAIL"
    fi
    
    log "Notifications sent: $message"
}

# Main rotation flow
main() {
    log "=== Starting SandboxSpy secret rotation ==="
    log "Backend: $SECRETS_BACKEND"
    log "Environment: $ENVIRONMENT"
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$ROTATION_LOG")"
    
    # Perform rotation based on backend
    case "$SECRETS_BACKEND" in
        aws)
            rotate_aws_secrets
            ;;
        vault)
            rotate_vault_secrets
            ;;
        local)
            rotate_local_secrets
            ;;
        *)
            log "ERROR: Unknown secrets backend: $SECRETS_BACKEND"
            exit 1
            ;;
    esac
    
    # Restart services to pick up new secrets
    restart_services
    
    # Wait for services to be healthy
    sleep 10
    
    # Verify services are working with new credentials
    if test_credentials; then
        notify_rotation "SUCCESS"
        log "=== Secret rotation completed successfully ==="
        exit 0
    else
        notify_rotation "FAILED"
        log "=== Secret rotation failed ==="
        exit 1
    fi
}

# Run main function
main "$@"