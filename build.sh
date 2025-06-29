#!/bin/bash
echo "Building MCP Gateway executables..."

echo "Building main gateway server..."
go build -o mcp-gateway ./main.go
if [ $? -ne 0 ]; then
    echo "Failed to build main gateway server"
    exit 1
fi

echo "Building local MCP server..."
go build -o mcp-local ./cmd/mcp-local/main.go
if [ $? -ne 0 ]; then
    echo "Failed to build local MCP server"
    exit 1
fi

echo "Build completed successfully!"
echo ""
echo "Executables created:"
echo "- mcp-gateway (main gateway server)"
echo "- mcp-local (local MCP server with STDIO transport)"
echo ""
echo "Usage examples:"
echo "  ./mcp-gateway -config config.yaml"
echo "  ./mcp-local -config local-config.yaml -gateway http://localhost:8080"
