#!/bin/bash

# Test script for curated servers API

BASE_URL="http://localhost:8080"
API_URL="$BASE_URL/api"

echo "Testing Curated Servers API..."

# Test 1: List curated servers (should work without auth for public endpoint)
echo -e "\n1. Testing GET /gateway/curation (public endpoint)..."
curl -s "$BASE_URL/gateway/curation" | jq .

# Test 2: List curated servers via admin API (requires auth)
echo -e "\n2. Testing GET /api/curated-servers (admin endpoint)..."
curl -s "$API_URL/curated-servers" | jq .

# Test 3: Create a new curated server (requires auth)
echo -e "\n3. Testing POST /api/curated-servers..."
curl -X POST -H "Content-Type: application/json" \
  -d '{
    "name": "test-server",
    "type": "stdio",
    "command": "echo",
    "args": ["hello"],
    "description": "Test server for validation"
  }' \
  "$API_URL/curated-servers" | jq .

# Test 4: Get specific curated server
echo -e "\n4. Testing GET /api/curated-servers/1..."
curl -s "$API_URL/curated-servers/1" | jq .

echo -e "\nAPI testing complete!"
