# MCP Gateway Authentication

## Overview

The MCP Gateway supports two types of authentication:

1. **Upstream Server Authentication** - For authenticating to remote MCP servers
2. **Gateway Access Authentication** - For securing access to the gateway itself

## Gateway Access Authentication

### Overview

The gateway now supports token-based authentication to secure access to MCP protocol endpoints. When authentication is enabled, all MCP communication requires a valid access token.

### Default Credentials

- **Username**: `admin`
- **Password**: `password`

> **Important**: Change the default password in production environments.

### Authentication Flow

1. **Login**: POST to `/auth/login` with username and password
2. **Receive Token**: Get an access token with expiration time
3. **Use Token**: Include token in `Authorization: Bearer <token>` header for all MCP requests

### API Endpoints

#### Public Endpoints (No Authentication Required)

- `GET /health` - Health check
- `GET /info` - Gateway information
- `POST /auth/login` - User login

#### Protected Endpoints (Authentication Required)

- `GET /` - MCP SSE endpoint
- `GET,POST /mcp` - MCP WebSocket endpoint  
- `POST /mcp/http` - MCP HTTP endpoint
- `GET /admin` - Admin panel
- All `/gateway/*` endpoints
- All `/api/*` upstream server management endpoints

#### Authentication Management Endpoints

- `POST /auth/tokens` - Create a new access token
- `GET /auth/tokens` - List user's tokens
- `DELETE /auth/tokens/revoke?id=<token_id>` - Revoke a token

### Token Management

#### Creating Tokens

```bash
curl -X POST http://localhost:8080/auth/tokens \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "VS Code Extension",
    "expires_at": "2024-12-31T23:59:59Z"
  }'
```

#### Listing Tokens

```bash
curl -X GET http://localhost:8080/auth/tokens \
  -H "Authorization: Bearer <your_token>"
```

#### Revoking Tokens

```bash
curl -X DELETE "http://localhost:8080/auth/tokens/revoke?id=1" \
  -H "Authorization: Bearer <your_token>"
```

### Configuration

Authentication is controlled by the `security.enable_auth` setting in `config.yaml`:

```yaml
security:
  enable_auth: true  # Set to false to disable authentication
  api_keys: []       # Reserved for future use
  allowed_ips: []    # Reserved for future use
```

### Admin Panel

The admin panel provides a web interface for:

- User login/logout
- Token creation and management
- Token usage monitoring

Access the admin panel at: `http://localhost:8080/admin`

### MCP Client Configuration

When authentication is enabled, MCP clients must include the authorization header:

#### VS Code MCP Extension

Update your VS Code settings:

```json
{
  "mcp.servers": {
    "my-gateway": {
      "url": "http://localhost:8080",
      "headers": {
        "Authorization": "Bearer your_token_here"
      }
    }
  }
}
```

#### cURL Examples

```bash
# Login to get token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token for MCP requests
curl -X POST http://localhost:8080/mcp/http \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## Upstream Server Authentication

The MCP Gateway supports secure authentication for remote MCP servers using bearer tokens, basic authentication, and API keys. All sensitive authentication data is encrypted at rest using AES-256-GCM encryption.

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
