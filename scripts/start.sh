#!/bin/bash
# TrustShield Backend Start Script (bash)
# Run from the trustshield/ project root

echo "Starting TrustShield API on http://127.0.0.1:8000 ..."
echo "Swagger docs: http://127.0.0.1:8000/docs"
echo "Press Ctrl+C to stop."
echo ""

./venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --log-level info
