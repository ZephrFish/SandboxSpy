# 🚀 SandboxSpy Quick Start Guide

## ✅ Build Complete!

Your SandboxSpy system has been successfully built with:
- **Windows executables** (x64 and x86)
- **Server binary** 
- **Pre-configured client connections**
- **Auto-generated API keys**

## 📁 Output Files

All files are in the `output/` directory:

```
output/
├── SandboxSpy-x64.exe      # Windows 64-bit client (5.9 MB)
├── SandboxSpy-x86.exe      # Windows 32-bit client (5.7 MB)
├── config.json             # Client configuration
├── sandboxspy-server       # Server binary (7.7 MB)
└── server_config.json      # Server configuration
```

## 🎯 How to Use

### 1. Start the Server (Already Running!)

The server is running at `http://localhost:8080`

To verify:
```bash
curl http://localhost:8080/api/v1/health
```

Access the dashboard:
```
http://localhost:8080/dashboard/
```

### 2. Deploy Windows Clients

The Windows executables are **pre-configured** to connect to your server.

#### On Target Windows Systems:

1. Copy these files to the Windows machine:
   - `SandboxSpy-x64.exe` (or x86 for 32-bit)
   - `config.json`

2. Run the executable:
   ```cmd
   SandboxSpy-x64.exe
   ```

The client will:
- ✅ Automatically detect sandbox indicators
- ✅ Connect to your server at `http://localhost:8080`
- ✅ Submit detection results
- ✅ Download updated blocklists

### 3. View Results

Check the dashboard or use the API:

```bash
# Get statistics
curl -H "X-API-Key: sandboxspy-2a514b84da1e622fc3ae4a7ca84d8810" \
     http://localhost:8080/api/v1/stats

# Get blocklist
curl -H "X-API-Key: sandboxspy-2a514b84da1e622fc3ae4a7ca84d8810" \
     http://localhost:8080/api/v1/blocklist

# Export blocklist as Snort rules
curl -H "X-API-Key: sandboxspy-2a514b84da1e622fc3ae4a7ca84d8810" \
     "http://localhost:8080/api/v1/blocklist/export?format=snort" \
     -o sandbox.rules
```

## 🔑 Configuration Details

### Server Configuration
- **URL**: `http://localhost:8080`
- **API Key**: `sandboxspy-2a514b84da1e622fc3ae4a7ca84d8810`
- **Database**: SQLite (sandboxspy.db)
- **Dashboard**: Enabled
- **WebSocket**: Enabled

### Client Configuration
The clients are pre-configured with:
- Server URL: `http://localhost:8080`
- API Key: Matching the server
- Detection threshold: 0.5
- Auto-update blocklists: Enabled

## 🐳 Docker Alternative

To build everything with Docker (including all platforms):

```bash
# Build Docker image
docker build -f deployments/docker/Dockerfile.all-in-one \
  --build-arg SERVER_URL=http://your-server:8080 \
  --build-arg API_KEY=your-api-key \
  -t sandboxspy:latest .

# Run server
docker run -d -p 8080:8080 sandboxspy:latest server

# Export binaries
docker run -v $(pwd)/docker-output:/output sandboxspy:latest export
```

## 📊 What Gets Detected

The clients detect:
- **VMware** indicators (files, processes, MACs)
- **VirtualBox** indicators
- **QEMU/KVM** indicators
- **Sandbox-specific hostnames** (WIN-, USER-PC, etc.)
- **Sandbox usernames** (admin, test, malware, etc.)
- **Timing anomalies**
- **Process counts**
- **Network configurations**

## 🔄 Next Steps

1. **Deploy to Production Server**:
   - Copy server binary to your server
   - Update `SERVER_URL` in build script
   - Rebuild clients with production URL

2. **Customize Detection**:
   - Edit `pkg/detector/detector.go` for more patterns
   - Adjust confidence thresholds
   - Add custom indicators

3. **Scale Up**:
   - Use PostgreSQL instead of SQLite
   - Deploy with Docker Compose
   - Add Redis caching
   - Enable Prometheus metrics

## 🛠️ Rebuild When Needed

To rebuild with different settings:

```bash
# With custom server URL
SERVER_URL=https://your-server.com API_KEY=your-key ./build-windows.sh

# Or rebuild everything
./build.sh all
```

## ✨ Features

- ✅ **Zero-configuration clients** - Pre-configured with server details
- ✅ **Automatic detection** - Multiple sandbox detection methods
- ✅ **Real-time updates** - WebSocket dashboard
- ✅ **Blocklist generation** - JSON, CSV, TXT, Snort formats
- ✅ **Cross-platform** - Windows (32/64-bit), Linux, macOS
- ✅ **API access** - Full REST API for automation
- ✅ **Secure** - API key authentication, rate limiting

## 📝 Testing the System

1. **Test submission**:
```bash
curl -X POST http://localhost:8080/api/v1/sandbox \
  -H "X-API-Key: sandboxspy-2a514b84da1e622fc3ae4a7ca84d8810" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "TEST-SANDBOX",
    "confidence": 0.95,
    "ip_address": "192.168.56.101",
    "tags": ["vmware", "test"]
  }'
```

2. **Check dashboard**: http://localhost:8080/dashboard/

---

**Your SandboxSpy system is ready for deployment!** 🎉