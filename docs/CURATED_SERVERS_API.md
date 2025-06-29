# Curated Servers API Documentation

## Overview

The MCP Gateway now supports managing curated MCP servers through a dedicated database table and REST API. This replaces the previous hard-coded list with a fully manageable CRUD interface.

## Database Schema

### curated_servers table
- `id` (INTEGER PRIMARY KEY) - Unique identifier
- `name` (TEXT UNIQUE NOT NULL) - Server name
- `type` (TEXT NOT NULL) - Server type: 'stdio', 'http', 'ws'
- `url` (TEXT) - URL for http/ws servers
- `command` (TEXT) - Command for stdio servers
- `args` (TEXT JSON) - Arguments array for stdio servers
- `description` (TEXT) - Server description
- `created_at` (DATETIME) - Creation timestamp
- `updated_at` (DATETIME) - Last update timestamp

## API Endpoints

### Public Endpoints

#### GET /gateway/curation
Returns the list of curated servers in a format compatible with the original API.

**Response:**
```json
{
  "servers": [
    {
      "id": 1,
      "name": "filesystem",
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "description": "File system operations and file management"
    }
  ],
  "total": 5,
  "updated_at": "2025-06-29T12:00:00Z",
  "version": "2.0"
}
```

### Admin Endpoints (Require Authentication)

#### GET /api/curated-servers
List all curated servers.

**Response:**
```json
{
  "success": true,
  "message": "Curated servers retrieved successfully",
  "data": [
    {
      "id": 1,
      "name": "filesystem",
      "type": "stdio",
      "url": "",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "description": "File system operations and file management",
      "created_at": "2025-06-29T12:00:00Z",
      "updated_at": "2025-06-29T12:00:00Z"
    }
  ]
}
```

#### GET /api/curated-servers/{id}
Get a specific curated server by ID.

#### POST /api/curated-servers
Create a new curated server.

**Request Body:**
```json
{
  "name": "my-server",
  "type": "stdio",
  "command": "node",
  "args": ["server.js"],
  "description": "My custom MCP server"
}
```

**For HTTP/WebSocket servers:**
```json
{
  "name": "my-http-server", 
  "type": "http",
  "url": "http://localhost:3000/mcp",
  "description": "My HTTP MCP server"
}
```

#### PUT /api/curated-servers/{id}
Update an existing curated server. All fields are optional.

**Request Body:**
```json
{
  "name": "updated-name",
  "description": "Updated description"
}
```

#### DELETE /api/curated-servers/{id}
Delete a curated server.

## Server Types

### stdio
- **Required fields:** `name`, `type`, `command`
- **Optional fields:** `args`, `description`
- **Example:** Command-line tools, npm packages

### http
- **Required fields:** `name`, `type`, `url`
- **Optional fields:** `description`
- **Example:** HTTP-based MCP servers

### ws (WebSocket)
- **Required fields:** `name`, `type`, `url`
- **Optional fields:** `description`
- **Example:** WebSocket-based MCP servers

## Default Migration

The system automatically populates the database with these default curated servers on first run:

1. **filesystem** - File system operations
2. **brave-search** - Web search using Brave API
3. **sqlite** - SQLite database operations
4. **github** - GitHub repository management
5. **postgres** - PostgreSQL database operations

## Authentication

Admin API endpoints require authentication via:
- Bearer token in Authorization header
- Session token in cookie (for web UI)

## Audit Logging

All CRUD operations on curated servers are logged in the audit log with:
- Admin username
- Action performed
- Server details
- Timestamp

## Error Handling

Standard API response format:
```json
{
  "success": false,
  "message": "Error description",
  "error": "Detailed error message"
}
```

Common error codes:
- `400` - Bad Request (invalid input)
- `401` - Unauthorized
- `404` - Server not found
- `409` - Conflict (duplicate name)
- `500` - Internal server error
