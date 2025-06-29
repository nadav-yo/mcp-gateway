# MCP Local Server

This is a local Model Context Protocol (MCP) server that runs as a STDIO process and can optionally connect to the MCP Gateway to form a circle of trust.

## Features

- **STDIO Transport**: Communicates via standard input/output for local process integration
- **Gateway Integration**: Can connect to the MCP Gateway to get approved server lists
- **Local Tools**: Define and execute tools locally
- **Local Resources**: Serve local resources and data
- **Shared Client Library**: Uses the same client library as the gateway for consistency
- **Configurable**: Flexible configuration through YAML files

## Quick Start

### Building

```bash
# Build both gateway and local server
./build.sh

# Or on Windows
build.bat
```

### Running

```bash
# Run standalone local server
./mcp-local -mcp-config mcp.json

# Run with gateway integration
./mcp-local -mcp-config mcp.json -gateway http://localhost:8080

# Enable debug logging
./mcp-local -mcp-config mcp.json -debug
```

### Testing with MCP Client

The local server uses STDIO transport, so you can test it directly:

```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}' | ./mcp-local
```

## Configuration

The local server uses a single JSON configuration file (`mcp.json`) that defines:

1. **Upstream MCP servers** - servers to connect to and aggregate tools/resources from
2. **Curation registry** - required URL for upstream curation service

### MCP.json Configuration

The `mcp.json` file defines upstream servers and curation registry:

```json
{
  "servers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/directory"]
    }
  },
  "curationRegistry": {
    "url": "https://registry.example.com/api/v1/curated-servers",
    "token": ""
  }
}
```

**Required fields:**
- `curationRegistry.url`: URL for the upstream curation service

**Optional fields:**
- `curationRegistry.token`: Bearer token for authentication (can be set via `MCP_CURATION_TOKEN` environment variable)

**Environment Variables:**
- `MCP_CURATION_TOKEN`: Sets the bearer token for curation registry authentication when not specified in the config file

### Local Server Defaults

The local server uses sensible built-in defaults:

- **Name**: "mcp-local"
- **Description**: "Local MCP Server with Gateway Integration"
- **Version**: "2024-11-05" (MCP protocol version)
- **Authentication**: Disabled (local STDIO communication)
- **Logging**: MCP-compliant JSON-RPC notifications

No additional configuration files are needed - the server gets its identity and capabilities from the aggregated upstream servers.

## Gateway Integration

When connected to the MCP Gateway, the local server can:

1. **Authenticate**: Verify its identity with the gateway
2. **Get Approved Servers**: Receive a list of approved MCP servers to connect to
3. **Report Status**: Send health and status information to the gateway
4. **Sync Capabilities**: Share its local tools and resources with the gateway

## Architecture

```
┌─────────────────┐    STDIO     ┌─────────────────┐
│   MCP Client    │◄────────────►│  Local Server   │
│ (VS Code, etc.) │              │                 │
└─────────────────┘              └─────────────────┘
                                          │
                                          │ HTTP/WS
                                          ▼
                                 ┌─────────────────┐
                                 │  MCP Gateway    │
                                 │                 │
                                 └─────────────────┘
                                          │
                                          │
                                          ▼
                              ┌─────────────────────────┐
                              │  Upstream MCP Servers   │
                              │                         │
                              └─────────────────────────┘
```

## Development

### Project Structure

```
cmd/mcp-local/
├── main.go              # Entry point for local server
internal/local/
├── server.go            # Local MCP server implementation
local-config.yaml        # Sample configuration
```

### Adding Local Tools

1. Define the tool in `local-config.yaml`
2. Implement the tool logic in `server.go`'s `handleToolsCall` method
3. Update input schema as needed

### Adding Local Resources

1. Define the resource in `local-config.yaml`
2. Implement resource reading logic in `server.go`'s `handleResourcesRead` method
3. Handle different MIME types as needed

## Future Enhancements

- [ ] Dynamic tool/resource registration
- [ ] Tool execution engine
- [ ] Resource file system integration
- [ ] Gateway authentication and authorization
- [ ] Server discovery and approval workflows
- [ ] Local caching of gateway responses
- [ ] Plugin system for extensibility

## Security Considerations

Since this is a local server:

- No authentication required by default for local connections
- When connecting to gateway, use proper authentication
- Validate all inputs from STDIO
- Sandbox tool execution
- Limit resource access to configured paths

## License

MIT License
