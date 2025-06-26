@echo off
REM Build and run the MCP server

echo Building MCP Gateway...
go build -o mcp-gateway.exe main.go

echo Starting MCP Gateway server...
mcp-gateway.exe -config config.yaml
