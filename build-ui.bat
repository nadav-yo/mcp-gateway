@echo off
setlocal EnableDelayedExpansion

echo Building React UI...

REM Check if ui-react directory exists
if not exist "ui-react" (
    echo Error: ui-react directory not found!
    exit /b 1
)

REM Change to ui-react directory
pushd ui-react

echo Installing dependencies...
call npm install
if !errorlevel! neq 0 (
    echo Error: npm install failed!
    popd
    exit /b 1
)

echo Building the application...
call npm run build
if !errorlevel! neq 0 (
    echo Error: npm run build failed!
    popd
    exit /b 1
)

echo Build completed successfully!
popd