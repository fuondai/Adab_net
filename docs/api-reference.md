# API Reference

## Authentication

### Get Token

```http
POST /api/auth/token
```

Request:

```json
{
  "api_key": "your-api-key"
}
```

Response:

```json
{
  "token": "jwt-token",
  "expires_in": 3600
}
```

## Scanning Endpoints

### Port Scan

```http
POST /api/scan/ports
```

Request:

```json
{
  "target": "example.com",
  "ports": [80, 443],
  "scan_type": "sS"
}
```

### DNS Scan

```http
POST /api/scan/dns
```

Request:

```json
{
  "domain": "example.com",
  "record_types": ["A", "MX", "NS"]
}
```

### Vulnerability Scan

```http
POST /api/scan/vulnerabilities
```

Request:

```json
{
  "target": "example.com",
  "scan_type": "full"
}
```

## Response Format

Successful Response:

```json
{
  "status": "success",
  "data": {
    // Scan results
  }
}
```

Error Response:

```json
{
  "status": "error",
  "message": "Error description"
}
```
