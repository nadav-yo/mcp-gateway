package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Simple client for testing the MCP server
func main() {
	baseURL := "http://localhost:8080"
	
	// Test health endpoint
	fmt.Println("Testing health endpoint...")
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Health: %s\n", string(body))
	resp.Body.Close()

	// Test info endpoint
	fmt.Println("\nTesting info endpoint...")
	resp, err = http.Get(baseURL + "/info")
	if err != nil {
		fmt.Printf("Info request failed: %v\n", err)
		return
	}
	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("Info: %s\n", string(body))
	resp.Body.Close()

	// Test MCP initialize
	fmt.Println("\nTesting MCP initialize...")
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}
	
	resp, err = sendMCPRequest(baseURL+"/mcp/http", initReq)
	if err != nil {
		fmt.Printf("Initialize failed: %v\n", err)
		return
	}
	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("Initialize response: %s\n", string(body))
	resp.Body.Close()

	// Test tools list
	fmt.Println("\nTesting tools/list...")
	toolsReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	
	resp, err = sendMCPRequest(baseURL+"/mcp/http", toolsReq)
	if err != nil {
		fmt.Printf("Tools list failed: %v\n", err)
		return
	}
	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("Tools list response: %s\n", string(body))
	resp.Body.Close()

	// Test tool call
	fmt.Println("\nTesting tools/call...")
	callReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "echo",
			"arguments": map[string]interface{}{
				"text": "Hello from MCP client!",
			},
		},
	}
	
	resp, err = sendMCPRequest(baseURL+"/mcp/http", callReq)
	if err != nil {
		fmt.Printf("Tool call failed: %v\n", err)
		return
	}
	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("Tool call response: %s\n", string(body))
	resp.Body.Close()
}

func sendMCPRequest(url string, req map[string]interface{}) (*http.Response, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Post(url, "application/json", bytes.NewBuffer(jsonData))
}
