# SandboxSpy Central Logging Documentation

## Overview
SandboxSpy has been enhanced with cloud-based central logging capabilities to automatically collect, index, and share sandbox environment indicators across research teams. This allows security researchers to build comprehensive blocklists of known sandbox hostnames, IP ranges, and other indicators.

## Features

### 1. Automatic Sandbox Detection & Indexing
- **Real-time Detection**: Automatically detects sandbox environments using multiple indicators
- **Cloud Storage**: Stores detected sandbox data in cloud databases (Firebase, Elasticsearch, custom APIs)
- **Deduplication**: Prevents duplicate entries using hostname fingerprinting
- **Confidence Scoring**: Assigns confidence scores based on multiple detection factors

### 2. Data Collection
The system collects and indexes:
- **Hostnames**: Sandbox system hostnames
- **Usernames**: Common sandbox usernames
- **IP Addresses**: External IP addresses of sandboxes
- **IP Ranges**: Automatically detected /24 subnets
- **MAC Addresses**: Network adapter MAC addresses
- **Processes**: Sandbox-specific processes (VMware tools, VirtualBox, etc.)
- **File Paths**: Detected virtualization-related files
- **System Metrics**: CPU cores, process count, temp files

### 3. Blocklist Export Formats
Export collected data in multiple formats:
- **JSON**: Structured data for programmatic access
- **CSV**: For spreadsheet analysis
- **TXT**: Simple text lists
- **IOCs**: STIX/OpenIOC format for threat intelligence platforms
- **Snort Rules**: IDS/IPS rules for network detection

## Configuration

### Basic Setup

1. **Edit `config.json`**:
```json
{
  "logging": {
    "enabled": true,
    "provider": "firebase",
    "endpoints": {
      "firebase": {
        "project_id": "your-project-id",
        "api_key": "your-api-key",
        "database_url": "https://your-project.firebaseio.com"
      }
    }
  },
  "detection": {
    "auto_index_new": true,
    "confidence_threshold": 0.7
  }
}
```

2. **Firebase Setup** (Recommended):
   - Create a Firebase project at https://console.firebase.google.com
   - Enable Realtime Database
   - Get your API key from Project Settings
   - Set database rules for write access (secure in production)

3. **Alternative Storage Providers**:
   - **Elasticsearch**: Use for large-scale deployments
   - **Custom API**: Integrate with your existing infrastructure

## Usage

### Basic Operation
```bash
# Compile with cloud logging support
GOOS=windows GOARCH=amd64 go build -o SandboxSpy.exe *.go

# Run with default config
./SandboxSpy.exe

# The tool will:
# 1. Detect if running in a sandbox
# 2. Collect environment data
# 3. Send to cloud if sandbox detected
# 4. Auto-update blocklist
```

### Manual Blocklist Export
```go
// In your code
storage := NewFirebaseStorage(projectID, apiKey, databaseURL)
exporter := NewBlocklistExporter(storage)

// Export all formats
exporter.ExportAll("sandbox_blocklist")

// Export specific format
exporter.ExportJSON("blocklist.json")
exporter.ExportCSV("blocklist.csv")
exporter.ExportSnortRules("sandbox.rules")
```

## Data Structure

### Sandbox Entry Schema
```json
{
  "id": "unique-identifier",
  "hostname": "SANDBOX-PC",
  "username": "malware",
  "domain": "WORKGROUP",
  "ip_address": "192.168.1.100",
  "ip_range": "192.168.1.0/24",
  "mac_addresses": ["00:0C:29:XX:XX:XX"],
  "processes": ["vmtoolsd.exe", "vboxservice.exe"],
  "confidence": 0.85,
  "first_seen": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-02T00:00:00Z",
  "detection_count": 5,
  "tags": ["vmware", "high-confidence"],
  "fingerprint": "a1b2c3d4e5f6"
}
```

### Confidence Scoring
Confidence scores (0.0-1.0) are calculated based on:
- Known sandbox hostname patterns (+0.2)
- Sandbox MAC address prefixes (+0.3)
- Virtualization processes detected (+0.2)
- Multiple detections over time (+0.2)
- File path indicators (+0.1)

## API Integration

### REST API Endpoints
If using a custom API backend:

```http
POST /api/sandbox
Content-Type: application/json
X-API-Key: your-api-key

{
  "hostname": "SANDBOX-PC",
  "username": "analyst",
  ...
}
```

### Batch Upload
```http
POST /api/sandbox/batch
Content-Type: application/json
X-API-Key: your-api-key

{
  "entries": [
    {...},
    {...}
  ],
  "batch_timestamp": "2024-01-01T00:00:00Z"
}
```

### Retrieve Blocklist
```http
GET /api/blocklist
X-API-Key: your-api-key

Response:
{
  "hostnames": ["SANDBOX-PC", "MALWARE-VM"],
  "ip_ranges": ["192.168.56.0/24"],
  "updated_at": "2024-01-01T00:00:00Z"
}
```

## Security Considerations

### For Researchers
1. **API Key Security**: Store API keys securely, never commit to version control
2. **Data Privacy**: Only collect necessary data for research purposes
3. **Access Control**: Implement proper authentication on cloud databases
4. **Rate Limiting**: Implement rate limiting to prevent abuse
5. **Data Retention**: Set appropriate data retention policies

### Database Security (Firebase)
```json
{
  "rules": {
    "sandboxes": {
      ".read": "auth != null",
      ".write": "auth != null && auth.token.researcher == true"
    }
  }
}
```

## Advanced Features

### IP Range Detection
The system automatically detects and groups IP addresses into /24 subnets, helping identify sandbox network ranges used by analysis platforms.

### Process Monitoring
Detects sandbox-specific processes:
- VMware: `vmtoolsd.exe`, `vmwaretray.exe`
- VirtualBox: `vboxservice.exe`, `vboxtray.exe`
- QEMU: `qemu-ga.exe`
- Parallels: `prl_tools.exe`
- Any.run: `srvhost.exe`

### MAC Address Prefixes
Known sandbox MAC prefixes:
- VMware: `00:0C:29`, `00:1C:14`, `00:50:56`
- VirtualBox: `08:00:27`
- Xen: `00:16:3E`

## Integration Examples

### Python Client
```python
import requests
import json

class SandboxSpyClient:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.headers = {'X-API-Key': api_key}
    
    def report_sandbox(self, hostname, ip_address):
        data = {
            'hostname': hostname,
            'ip_address': ip_address,
            'confidence': 0.8
        }
        response = requests.post(
            f"{self.api_url}/sandbox",
            json=data,
            headers=self.headers
        )
        return response.json()
    
    def get_blocklist(self):
        response = requests.get(
            f"{self.api_url}/blocklist",
            headers=self.headers
        )
        return response.json()
```

### PowerShell Integration
```powershell
function Submit-SandboxData {
    param(
        [string]$Hostname,
        [string]$IPAddress
    )
    
    $body = @{
        hostname = $Hostname
        ip_address = $IPAddress
    } | ConvertTo-Json
    
    $headers = @{
        'X-API-Key' = 'your-api-key'
        'Content-Type' = 'application/json'
    }
    
    Invoke-RestMethod -Uri "https://api.example.com/sandbox" `
        -Method POST `
        -Headers $headers `
        -Body $body
}
```

## Troubleshooting

### Common Issues

1. **Connection Failed**: Check firewall rules and network connectivity
2. **Authentication Error**: Verify API keys and permissions
3. **Data Not Appearing**: Check confidence threshold in config
4. **Duplicate Entries**: System should auto-deduplicate, check fingerprinting

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export SANDBOXSPY_DEBUG=true
./SandboxSpy.exe
```

## Contributing

To contribute sandbox indicators:
1. Run SandboxSpy in known sandbox environments
2. Verify data accuracy
3. Submit pull requests with new indicators
4. Share blocklists with the research community

## License & Ethics

This tool is for defensive security research only. Use responsibly and in accordance with applicable laws and ethical guidelines.

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/SandboxSpy/issues
- Documentation: This file
- Community: Security research forums