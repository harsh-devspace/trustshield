# TrustShield Setup Script (Windows PowerShell)
# Run from the trustshield/ project root

$ErrorActionPreference = "Stop"

Write-Host "=== TrustShield Setup ===" -ForegroundColor Cyan

# Check Python
try {
    $pyver = python --version 2>&1
    Write-Host "Found: $pyver" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Install Python 3.12+ from https://python.org" -ForegroundColor Red
    exit 1
}

# Create venv if missing
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
& ".\venv\Scripts\pip" install -r backend\requirements.txt --quiet

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host "Run the backend with:  scripts\start.ps1"
Write-Host "Run tests with:        .\venv\Scripts\pytest tests\ -v"
