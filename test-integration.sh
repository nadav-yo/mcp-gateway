#!/bin/bash

echo "MCP Gateway & Local Server Integration Test"
echo "============================================"

# Check if executables exist
if [ ! -f "./mcp-gateway" ] || [ ! -f "./mcp-local" ]; then
    echo "Building executables..."
    ./build.sh
fi

echo ""
echo "1. Starting MCP Gateway in background..."
./mcp-gateway -config config.yaml &
GATEWAY_PID=$!

# Wait for gateway to start
sleep 3

echo ""
echo "2. Testing Gateway health..."
curl -s http://localhost:8080/health | jq .

echo ""
echo "3. Testing Local Server standalone..."
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}' | ./mcp-local -config local-config.yaml | jq .

echo ""
echo "4. Testing Local Server tools list..."
echo '{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}' | ./mcp-local -config local-config.yaml | jq .

echo ""
echo "5. Testing Local Server resources list..."
echo '{"jsonrpc": "2.0", "id": 3, "method": "resources/list"}' | ./mcp-local -config local-config.yaml | jq .

echo ""
echo "6. Testing Local Server with Gateway integration..."
echo '{"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}' | ./mcp-local -config local-config.yaml -gateway http://localhost:8080 | jq .

echo ""
echo "7. Stopping Gateway..."
kill $GATEWAY_PID
wait $GATEWAY_PID 2>/dev/null

echo ""
echo "Integration test completed!"
echo ""
echo "Next steps for full integration:"
echo "- Implement authentication between local server and gateway"
echo "- Add server approval/discovery workflow"
echo "- Implement tool execution in local server"
echo "- Add resource reading in local server"
echo "- Create circle of trust mechanisms"
