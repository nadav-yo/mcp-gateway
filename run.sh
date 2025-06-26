#!/bin/bash

# Build and run the MCP server

echo "Building MCP Gateway..."
go build -o mcp-gateway main.go

echo "Starting MCP Gateway server..."
./mcp-gateway -config config.yaml
