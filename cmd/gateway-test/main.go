package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	baseURL := "http://localhost:8080"
	
	fmt.Println("=== MCP Gateway Test Client ===")
	
	// Test health endpoint
	fmt.Println("\n1. Testing health endpoint...")
	if err := testHealth(baseURL); err != nil {
		fmt.Printf("Health check failed: %v\n", err)
	}
	
	// Test gateway status
	fmt.Println("\n2. Testing gateway status...")
	if err := testGatewayStatus(baseURL); err != nil {
		fmt.Printf("Gateway status failed: %v\n", err)
	}
	
	// Test initialize
	fmt.Println("\n3. Testing MCP initialize...")
	if err := testInitialize(baseURL); err != nil {
		fmt.Printf("Initialize failed: %v\n", err)
	}
	
	// Test tools list
	fmt.Println("\n4. Testing tools/list...")
	if err := testToolsList(baseURL); err != nil {
		fmt.Printf("Tools list failed: %v\n", err)
	}
	
	// Test tool call
	fmt.Println("\n5. Testing tools/call...")
	if err := testToolCall(baseURL); err != nil {
		fmt.Printf("Tool call failed: %v\n", err)
	}
	
	// Test resources list
	fmt.Println("\n6. Testing resources/list...")
	if err := testResourcesList(baseURL); err != nil {
		fmt.Printf("Resources list failed: %v\n", err)
	}
	
	// Test prompts list
	fmt.Println("\n7. Testing prompts/list...")
	if err := testPromptsList(baseURL); err != nil {
		fmt.Printf("Prompts list failed: %v\n", err)
	}

	fmt.Println("\n=== Test completed ===")
}

func testHealth(baseURL string) error {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	fmt.Printf("Health response: %s\n", string(body))
	return nil
}

func testGatewayStatus(baseURL string) error {
	resp, err := http.Get(baseURL + "/gateway/status")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	fmt.Printf("Gateway status: %s\n", string(body))
	return nil
}

func sendMCPRequest(baseURL, method string, params interface{}) (*MCPResponse, error) {
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	
	httpReq, err := http.NewRequest("POST", baseURL+"/mcp/http", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, err
	}
	
	return &mcpResp, nil
}

func testInitialize(baseURL string) error {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"experimental": map[string]interface{}{},
		},
		"clientInfo": map[string]interface{}{
			"name":    "test-client",
			"version": "1.0.0",
		},
	}
	
	resp, err := sendMCPRequest(baseURL, "initialize", params)
	if err != nil {
		return err
	}
	
	if resp.Error != nil {
		return fmt.Errorf("MCP error: %s", resp.Error.Message)
	}
	
	result, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Printf("Initialize result: %s\n", string(result))
	return nil
}

func testToolsList(baseURL string) error {
	resp, err := sendMCPRequest(baseURL, "tools/list", nil)
	if err != nil {
		return err
	}
	
	if resp.Error != nil {
		return fmt.Errorf("MCP error: %s", resp.Error.Message)
	}
	
	result, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Printf("Tools list result: %s\n", string(result))
	return nil
}

func testToolCall(baseURL string) error {
	params := map[string]interface{}{
		"name": "echo",
		"arguments": map[string]interface{}{
			"text": "Hello from MCP Gateway!",
		},
	}
	
	resp, err := sendMCPRequest(baseURL, "tools/call", params)
	if err != nil {
		return err
	}
	
	if resp.Error != nil {
		return fmt.Errorf("MCP error: %s", resp.Error.Message)
	}
	
	result, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Printf("Tool call result: %s\n", string(result))
	return nil
}

func testResourcesList(baseURL string) error {
	resp, err := sendMCPRequest(baseURL, "resources/list", nil)
	if err != nil {
		return err
	}
	
	if resp.Error != nil {
		return fmt.Errorf("MCP error: %s", resp.Error.Message)
	}
	
	result, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Printf("Resources list result: %s\n", string(result))
	return nil
}

func testPromptsList(baseURL string) error {
	resp, err := sendMCPRequest(baseURL, "prompts/list", nil)
	if err != nil {
		return err
	}
	
	if resp.Error != nil {
		return fmt.Errorf("MCP error: %s", resp.Error.Message)
	}
	
	result, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Printf("Prompts list result: %s\n", string(result))
	return nil
}
