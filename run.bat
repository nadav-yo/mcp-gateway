@echo off
REM Build and run the MCP server

REM Default config file
set CONFIG_FILE=config.yaml

REM Check if config file path is provided as argument
if not "%1"=="" (
    set CONFIG_FILE=%1
)

REM Check if config file exists
if not exist "%CONFIG_FILE%" (
    echo Error: Config file '%CONFIG_FILE%' not found!
    echo Usage: %0 [config_file_path]
    echo Default config file: config.yaml
    exit /b 1
)

echo Starting MCP Gateway server with config: %CONFIG_FILE%
mcp-gateway.exe -config "%CONFIG_FILE%"
