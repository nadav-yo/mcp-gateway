#!/bin/bash

# Default config file
CONFIG_FILE="config.yaml"

# Check if config file path is provided as argument
if [ $# -eq 1 ]; then
    CONFIG_FILE="$1"
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file '$CONFIG_FILE' not found!"
    echo "Usage: $0 [config_file_path]"
    echo "Default config file: config.yaml"
    exit 1
fi

echo "Starting MCP Gateway server with config: $CONFIG_FILE"
./mcp-gateway -config "$CONFIG_FILE"
