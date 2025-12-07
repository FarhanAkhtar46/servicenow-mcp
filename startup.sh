#!/bin/bash
# Azure App Service startup script for ServiceNow MCP API

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI application
gunicorn mcp_server_servicenow.api_server:app --bind 0.0.0.0:8000 --workers 4 --worker-class uvicorn.workers.UvicornWorker --timeout 120