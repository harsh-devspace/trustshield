# TrustShield Backend Start Script (Windows PowerShell)
# Run from the trustshield/ project root

Write-Host "Starting TrustShield API on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Write-Host "Swagger docs: http://127.0.0.1:8000/docs" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

& ".\venv\Scripts\uvicorn" backend.app.main:app --host 127.0.0.1 --port 8000 --log-level info
