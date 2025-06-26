# MCP Gateway

A dynamic Model Context Protocol (MCP) gateway server that allows you to connect to multiple upstream MCP servers and aggregate their tools, resources, and prompts.

## Features

- **Dynamic Upstream Management**: Add, edit, and remove upstream MCP servers via REST API
- **SQLite Database**: Persistent storage for upstream server configurations
- **WebSocket & HTTP Support**: Connect to upstream servers via WebSocket or HTTP
- **Tool/Resource/Prompt Aggregation**: Combine capabilities from multiple upstream servers
- **Admin Interface**: Web-based administration panel
- **Health Monitoring**: Track connection status and server health
- **Prefix Support**: Namespace tools/resources from different servers

## Quick Start

1. **Start the Gateway**:
   ```bash
   ./mcp-gateway.exe
   ```

2. **Access Admin Panel**:
   Open `http://localhost:8080/admin` in your browser

3. **Add Upstream Servers** via API:
   ```bash
   curl -X POST http://localhost:8080/api/upstream-servers \
     -H "Content-Type: application/json" \
     -d '{
       "name": "test-server",
       "url": "ws://localhost:8081/mcp",
       "type": "websocket",
       "enabled": true,
       "prefix": "test",
       "timeout": "30s"
     }'
   ```

## API Documentation

See the [API Documentation](API.md) for complete details on all endpoints and usage examples.
