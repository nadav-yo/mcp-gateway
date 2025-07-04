# MCP Gateway & Local Server

This project provides two complementary MCP (Model Context Protocol) implementations:

1. **MCP Gateway** - A remote server that aggregates multiple upstream MCP servers
2. **MCP Local Server** - A local STDIO-based server that can integrate with the gateway

## Features

### MCP Gateway
- **Full MCP Protocol Support**: Implements MCP protocol version 2024-11-05
- **Multiple Transport Options**: Supports WebSocket, HTTP, and SSE transport
- **Upstream Server Integration**: Aggregate tools and resources from multiple upstream MCP servers
- **Web UI**: Admin interface for managing servers, users, and monitoring
- **Authentication & Authorization**: User management with admin/user roles
- **Health Monitoring**: Built-in health check and statistics endpoints
- **Graceful Shutdown**: Proper cleanup on server shutdown

### MCP Local Server
- **STDIO Transport**: Communicates via standard input/output for local process integration
- **Gateway Integration**: Can connect to the MCP Gateway for approved server lists
- **Local Tools & Resources**: Define and execute tools/serve resources locally
- **Shared Client Library**: Uses the same client library as the gateway
- **Configurable**: Flexible configuration through YAML files

## Features

- **Full MCP Protocol Support**: Implements MCP protocol version 2024-11-05
- **Multiple Transport Options**: Supports both WebSocket and HTTP transport
- **Configurable Tools**: Define custom tools with JSON schema validation
- **Resource Management**: Serve resources with various MIME types
- **Upstream Server Integration**: Aggregate tools and resources from multiple upstream MCP servers
- **Health Monitoring**: Built-in health check and info endpoints
- **Graceful Shutdown**: Proper cleanup on server shutdown

## Quick Start

1. **Build the servers**:
   ```bash
   # Unix/Linux/macOS
   ./build.sh
   
   # Windows
   build.bat
   ```

2. **Run the gateway server**:
   ```bash
   # Unix/Linux/macOS
   ./run.sh                 # Uses config.yaml by default
   ./run.sh /path/to/config.yaml   # Optionally specify a custom config file path
   
   # Windows
   run.bat                  # Uses config.yaml by default
   run.bat C:\path\to\config.yaml   # Optionally specify a custom config file path
   ```

3. **Test the server**:
   ```bash
   curl http://localhost:8080/health
   ```

4. **Access the web UI**:
   Open http://localhost:8080 in your browser



## API Endpoints

- `GET /health` - Health check endpoint
- `GET /info` - Server information and capabilities
- `WebSocket /mcp` - MCP protocol over WebSocket
- `POST /mcp/http` - MCP protocol over HTTP

## MCP Protocol Methods

The server implements standard MCP methods:

- `initialize` - Initialize the connection
- `tools/list` - List available tools (aggregated from all upstream servers)
- `tools/call` - Execute a tool (routed to appropriate upstream server)
- `resources/list` - List available resources
- `resources/read` - Read a resource
- `prompts/list` - List available prompts (aggregated from all upstream servers)
- `prompts/get` - Get a specific prompt (routed to appropriate upstream server)
- `logging/setLevel` - Set logging level for this server

## Development

### Project Structure

```
mcp-gateway/
├── main.go                 # Application entry point
├── config.yaml            # Configuration file
├── pkg/
│   ├── config/            # Configuration management
│   └── types/             # MCP type definitions
└── internal/
    └── server/            # HTTP/WebSocket server implementation
```

### Adding Custom Tools

1. Add tool configuration to `config.yaml`
2. Implement tool logic in `server.go`'s `executeTool` method
3. Update input schema as needed

### Adding Custom Resources

1. Add resource configuration to `config.yaml`  
2. Implement resource reading logic in `server.go`'s `readResource` method
3. Handle different MIME types as needed

### Managing Upstream Servers

1. Use the CRUD API endpoints to add/remove upstream MCP servers
2. The gateway will automatically aggregate tools and resources from all connected servers
3. Tool calls are automatically routed to the appropriate upstream server

## Testing

Test the MCP server using any MCP-compatible client or with direct HTTP/WebSocket calls:

```bash
# Test initialize
curl -X POST http://localhost:8080/mcp/http \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test-client", "version": "1.0.0"}
    }
  }'

# Test tools list
```bash
curl -X POST http://localhost:8080/mcp/http \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'
```



## API Endpoints

- `GET /health` - Health check endpoint
- `GET /info` - Server information and capabilities
- `WebSocket /mcp` - MCP protocol over WebSocket
- `POST /mcp/http` - MCP protocol over HTTP

## MCP Protocol Methods

The server implements standard MCP methods:

- `initialize` - Initialize the connection
- `tools/list` - List available tools (aggregated from all upstream servers)
- `tools/call` - Execute a tool (routed to appropriate upstream server)
- `resources/list` - List available resources
- `resources/read` - Read a resource
- `prompts/list` - List available prompts (aggregated from all upstream servers)
- `prompts/get` - Get a specific prompt (routed to appropriate upstream server)
- `logging/setLevel` - Set logging level

## Development

### Project Structure

```
mcp-gateway/
├── main.go                 # Application entry point
├── config.yaml            # Configuration file
├── cmd/
│   └── mcp-local/         # Local MCP server
├── pkg/
│   ├── config/            # Configuration management
│   └── types/             # MCP type definitions
├── internal/
│   ├── server/            # HTTP/WebSocket server implementation
│   ├── local/             # Local server implementation
│   ├── client/            # MCP client library
│   ├── database/          # Database operations
│   ├── handlers/          # HTTP handlers
│   └── logger/            # Logging utilities
└── ui-react/              # Web UI
```

### Adding Custom Tools

1. Add tool configuration to `config.yaml`
2. Implement tool logic in `server.go`'s `executeTool` method
3. Update input schema as needed

### Adding Custom Resources

1. Add resource configuration to `config.yaml`  
2. Implement resource reading logic in `server.go`'s `readResource` method
3. Handle different MIME types as needed

### Managing Upstream Servers

1. Use the CRUD API endpoints to add/remove upstream MCP servers
2. The gateway will automatically aggregate tools and resources from all connected servers
3. Tool calls are automatically routed to the appropriate upstream server

## Testing

Test the MCP server using any MCP-compatible client or with direct HTTP/WebSocket calls:

```bash
# Test initialize
curl -X POST http://localhost:8080/mcp/http \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test-client", "version": "1.0.0"}
    }
  }'

# Test tools list
curl -X POST http://localhost:8080/mcp/http \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'
```

## License

MIT License
