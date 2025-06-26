# MCP Gateway Logging Configuration

The MCP Gateway now uses structured logging with zerolog. You can control the log level in several ways:

## Environment Variable
Set the `LOG_LEVEL` environment variable:
```bash
export LOG_LEVEL=debug
./mcp-gateway
```

## Available Log Levels
- `debug` - Most verbose, includes debug information
- `info` - General information (default)
- `warn` or `warning` - Warning messages
- `error` - Error messages only
- `fatal` - Fatal errors only
- `panic` - Panic level (most severe)

## Dynamic Log Level Changes
You can also change the log level at runtime via the MCP protocol:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "logging/setLevel",
  "params": {
    "level": "debug"
  }
}
```

## Log Format
Logs are now structured with:
- Timestamp
- Log level
- Component (e.g., "main", "server", "mcp-client")
- Context fields (upstream name, tool name, etc.)
- Message

Example log output:
```
2024-06-26 10:30:15 INF Starting MCP Gateway Server... component=main port=8080
2024-06-26 10:30:15 INF Successfully connected to upstream server component=mcp-client upstream=test-server
2024-06-26 10:30:16 DBG Sending HTTP request component=mcp-client upstream=test-server url=http://localhost:3000
```
