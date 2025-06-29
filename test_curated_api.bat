@echo off
echo Testing Curated Servers API...

echo.
echo 1. Testing GET /gateway/curation (public endpoint)...
curl -s "http://localhost:8080/gateway/curation"

echo.
echo.
echo 2. Testing GET /api/curated-servers (admin endpoint)...
curl -s "http://localhost:8080/api/curated-servers"

echo.
echo.
echo 3. Testing POST /api/curated-servers...
curl -X POST -H "Content-Type: application/json" -d "{\"name\":\"test-server\",\"type\":\"stdio\",\"command\":\"echo\",\"args\":[\"hello\"],\"description\":\"Test server for validation\"}" "http://localhost:8080/api/curated-servers"

echo.
echo.
echo 4. Testing GET /api/curated-servers/1...
curl -s "http://localhost:8080/api/curated-servers/1"

echo.
echo.
echo API testing complete!
pause
