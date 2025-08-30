#!/bin/bash
# SandboxSpy Server AWS User Data Script

set -e

# Variables from Terraform
API_KEY="${api_key}"
DOMAIN="${domain}"

# Update system
yum update -y
yum install -y git golang docker nginx certbot python3-certbot-nginx

# Install Go 1.19
wget https://go.dev/dl/go1.19.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile

# Clone SandboxSpy repository
cd /opt
git clone https://github.com/zephrfish/sandboxspy.git
cd sandboxspy

# Build server
go mod download
go build -o sandboxspy-server cmd/server/main.go

# Create configuration
cat > /opt/sandboxspy/server_config.json <<EOF
{
  "host": "0.0.0.0",
  "port": 8080,
  "database_path": "/var/lib/sandboxspy/sandboxspy.db",
  "api_key": "${API_KEY}",
  "enable_auth": true,
  "rate_limit": 100,
  "enable_websocket": true,
  "enable_dashboard": true,
  "enable_cors": true,
  "allowed_origins": ["https://${DOMAIN}"]
}
EOF

# Create data directory
mkdir -p /var/lib/sandboxspy
chown ec2-user:ec2-user /var/lib/sandboxspy

# Create systemd service
cat > /etc/systemd/system/sandboxspy.service <<EOF
[Unit]
Description=SandboxSpy Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/sandboxspy
ExecStart=/opt/sandboxspy/sandboxspy-server /opt/sandboxspy/server_config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx as reverse proxy (with CloudFront header verification)
cat > /etc/nginx/conf.d/sandboxspy.conf <<'EOF'
server {
    listen 8080;
    server_name _;

    # Verify CloudFront secret header
    if ($http_x_cloudfront_secret != "${cloudfront_secret}") {
        return 403;
    }

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_read_timeout 86400;
    }

    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Update SandboxSpy to listen on 8081 internally
sed -i 's/"port": 8080/"port": 8081/' /opt/sandboxspy/server_config.json

# Start services
systemctl daemon-reload
systemctl enable sandboxspy
systemctl start sandboxspy
systemctl enable nginx
systemctl start nginx

# Setup CloudWatch logging
yum install -y amazon-cloudwatch-agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/sandboxspy.log",
            "log_group_name": "/aws/ec2/sandboxspy",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json

echo "SandboxSpy server setup complete!"