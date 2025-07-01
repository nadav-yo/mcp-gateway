# Blocked Tools API Documentation

## Overview
The Blocked Tools API allows administrators to manage which tools are blocked for specific servers. This enables fine-grained control over which tools can be called on upstream servers or curated servers.

## Database Schema
The `blocked_tools` table stores blocked tool entries with the following structure:

```sql
CREATE TABLE blocked_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('servers', 'curated_servers')),
    tool_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, type, tool_name)
);
```

## API Endpoints

All blocked tools endpoints require admin authentication.

### Create Blocked Tool
**POST** `/api/blocked-tools`

Creates a new blocked tool entry.

**Request Body:**
```json
{
    "server_id": 1,
    "type": "servers",
    "tool_name": "dangerous_tool"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Blocked tool created successfully",
    "data": {
        "id": 1,
        "server_id": 1,
        "type": "servers",
        "tool_name": "dangerous_tool",
        "created_at": "2025-07-01T10:40:14Z"
    }
}
```

### Get Blocked Tool
**GET** `/api/blocked-tools/{id}`

Retrieves a specific blocked tool by ID.

**Response:**
```json
{
    "success": true,
    "message": "Blocked tool retrieved successfully",
    "data": {
        "id": 1,
        "server_id": 1,
        "type": "servers",
        "tool_name": "dangerous_tool",
        "created_at": "2025-07-01T10:40:14Z"
    }
}
```

### List All Blocked Tools
**GET** `/api/blocked-tools`

Retrieves all blocked tools.

**Response:**
```json
{
    "success": true,
    "message": "Blocked tools retrieved successfully",
    "data": [
        {
            "id": 1,
            "server_id": 1,
            "type": "servers",
            "tool_name": "dangerous_tool",
            "created_at": "2025-07-01T10:40:14Z"
        }
    ]
}
```

### List Blocked Tools by Server
**GET** `/api/blocked-tools/server/{server_id}?type={type}`

Retrieves all blocked tools for a specific server.

**Query Parameters:**
- `type`: Required. Must be either "servers" or "curated_servers"

**Response:**
```json
{
    "success": true,
    "message": "Blocked tools retrieved successfully",
    "data": [
        {
            "id": 1,
            "server_id": 1,
            "type": "servers",
            "tool_name": "dangerous_tool",
            "created_at": "2025-07-01T10:40:14Z"
        }
    ]
}
```

### List Blocked Tools with Query Parameters
**GET** `/api/blocked-tools?server_id={server_id}&type={type}`

Alternative way to filter blocked tools by server.

### Delete Blocked Tool by ID
**DELETE** `/api/blocked-tools/{id}`

Deletes a blocked tool by its ID.

**Response:**
```json
{
    "success": true,
    "message": "Blocked tool deleted successfully"
}
```

### Delete Blocked Tool by Details
**DELETE** `/api/blocked-tools/server/{server_id}/tool/{tool_name}?type={type}`

Deletes a blocked tool by server ID, tool name, and type.

**Query Parameters:**
- `type`: Required. Must be either "servers" or "curated_servers"

**Response:**
```json
{
    "success": true,
    "message": "Blocked tool deleted successfully"
}
```

## Server Types

The `type` field specifies which table the `server_id` refers to:

- **"servers"**: Refers to the `upstream_servers` table (regular upstream servers)
- **"curated_servers"**: Refers to the `curated_servers` table (curated servers)

## Validation

The API performs the following validations:

1. **Server Existence**: Verifies that the referenced server exists in the appropriate table
2. **Type Validation**: Ensures the type is either "servers" or "curated_servers"
3. **Duplicate Prevention**: Prevents creating duplicate blocked tool entries for the same server/tool combination
4. **Required Fields**: Validates that all required fields are provided

## Authentication

All endpoints require admin authentication when authentication is enabled in the gateway configuration.

## Audit Logging

All blocked tool operations are logged to the audit log with the following information:
- Admin username
- Action performed (created/deleted)
- Server ID and type
- Tool name
- Blocked tool ID (for specific operations)

## Error Handling

The API returns appropriate HTTP status codes:
- **200**: Success
- **201**: Created
- **400**: Bad Request (validation errors)
- **401**: Unauthorized
- **403**: Forbidden (non-admin users)
- **404**: Not Found
- **409**: Conflict (duplicate entries)
- **500**: Internal Server Error

Error responses follow this format:
```json
{
    "success": false,
    "message": "Error description",
    "error": "Detailed error message"
}
```

## Usage Examples

### Block a tool on an upstream server
```bash
curl -X POST http://localhost:8080/api/blocked-tools \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": 1,
    "type": "servers",
    "tool_name": "file_delete"
  }'
```

### List all blocked tools for a curated server
```bash
curl -X GET "http://localhost:8080/api/blocked-tools/server/2?type=curated_servers" \
  -H "Authorization: Bearer your-admin-token"
```

### Remove a blocked tool
```bash
curl -X DELETE "http://localhost:8080/api/blocked-tools/server/1/tool/file_delete?type=servers" \
  -H "Authorization: Bearer your-admin-token"
```
