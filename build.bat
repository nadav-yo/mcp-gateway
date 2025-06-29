@echo off
echo Building MCP Gateway executables...

echo Building main gateway server...
go build -o mcp-gateway.exe ./main.go
if %errorlevel% neq 0 (
    echo Failed to build main gateway server
    exit /b 1
)

echo Building local MCP server...
go build -o mcp-local.exe ./cmd/mcp-local/main.go
if %errorlevel% neq 0 (
    echo Failed to build local MCP server
    exit /b 1
)

echo Build completed successfully!
echo.
echo Executables created:
echo - mcp-gateway.exe (main gateway server)
echo - mcp-local.exe (local MCP server with STDIO transport)
echo.
echo Usage examples:
echo   mcp-gateway.exe -config config.yaml
echo   mcp-local.exe -config local-config.yaml -gateway http://localhost:8080
