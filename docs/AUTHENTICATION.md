# MCP Gateway Authentication Support

## Overview

The MCP Gateway now supports secure authentication for remote MCP servers using bearer tokens, basic authentication, and API keys. All sensitive authentication data is encrypted at rest using AES-256-GCM encryption.

## Supported Authentication Types

### 1. Bearer Token Authentication

```json
{
  "name": "authenticated-server",
  "url": "https://api.example.com/mcp",
  "type": "http",
  "auth": {
    "type": "bearer",
    "bearer_token": "your-secret-bearer-token-here"
  }
}
```

### 2. Basic Authentication

```json
{
  "name": "basic-auth-server", 
  "url": "https://api.example.com/mcp",
  "type": "http",
  "auth": {
    "type": "basic",
    "username": "your-username",
    "password": "your-password"
  }
}
```

### 3. API Key Authentication

```json
{
  "name": "api-key-server",
  "url": "https://api.example.com/mcp",
  "type": "http", 
  "auth": {
    "type": "api-key",
    "api_key": "your-api-key-here",
    "header_name": "X-API-Key"
  }
}
```

## API Usage

### Create Server with Authentication

```powershell
$body = Get-Content example-auth-server.json -Raw
Invoke-WebRequest -Uri "http://localhost:8080/api/upstream-servers" -Method POST -Body $body -ContentType "application/json"
```

### Update Server Authentication

```powershell
$updateBody = @{
    auth = @{
        type = "bearer"
        bearer_token = "new-token-here"
    }
} | ConvertTo-Json -Depth 3

Invoke-WebRequest -Uri "http://localhost:8080/api/upstream-servers/1" -Method PUT -Body $updateBody -ContentType "application/json"
```

## Security Features

1. **Encryption at Rest**: All sensitive authentication data (tokens, passwords, API keys) are encrypted using AES-256-GCM before being stored in the database.

2. **Secure Key Management**: Encryption keys are:
   - Generated automatically on first run
   - Stored in `~/.config/mcp-gateway/secret.key` with restricted permissions (0600)
   - Can be overridden via `MCP_GATEWAY_SECRET_KEY` environment variable

3. **Secret Masking**: Sensitive authentication data is not returned in list operations for security.

## Authentication in Action

When the MCP client connects to an upstream server:

- **HTTP/HTTPS**: Authentication headers are added to each request
- **WebSocket**: Authentication headers are added during the WebSocket handshake
- **Bearer Token**: Added as `Authorization: Bearer <token>`
- **Basic Auth**: Added as `Authorization: Basic <base64(username:password)>`
- **API Key**: Added as custom header (default: `X-API-Key: <key>`)

## Environment Variables

- `MCP_GATEWAY_SECRET_KEY`: Base64-encoded 32-byte encryption key (optional)

If not set, a key will be generated and stored in the user's config directory.
