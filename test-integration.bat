@echo off
echo MCP Gateway ^& Local Server Integration Test
echo ============================================

REM Check if executables exist
if not exist "mcp-gateway.exe" (
    echo Building executables...
    call build.bat
)
if not exist "mcp-local.exe" (
    echo Building executables...
    call build.bat
)

echo.
echo 1. Starting MCP Gateway in background...
start /B mcp-gateway.exe -config config.yaml

REM Wait for gateway to start
timeout /t 3 /nobreak >nul

echo.
echo 2. Testing Gateway health...
curl -s http://localhost:8080/health

echo.
echo 3. Testing Local Server standalone...
echo {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}} | mcp-local.exe -config local-config.yaml

echo.
echo 4. Testing Local Server tools list...
echo {"jsonrpc": "2.0", "id": 2, "method": "tools/list"} | mcp-local.exe -config local-config.yaml

echo.
echo 5. Testing Local Server resources list...
echo {"jsonrpc": "2.0", "id": 3, "method": "resources/list"} | mcp-local.exe -config local-config.yaml

echo.
echo 6. Testing Local Server with Gateway integration...
echo {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}} | mcp-local.exe -config local-config.yaml -gateway http://localhost:8080

echo.
echo 7. Stopping Gateway...
taskkill /f /im mcp-gateway.exe >nul 2>&1

echo.
echo Integration test completed!
echo.
echo Next steps for full integration:
echo - Implement authentication between local server and gateway
echo - Add server approval/discovery workflow  
echo - Implement tool execution in local server
echo - Add resource reading in local server
echo - Create circle of trust mechanisms
