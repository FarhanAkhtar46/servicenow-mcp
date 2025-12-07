"""
REST API Server for ServiceNow MCP
This module provides HTTP REST endpoints for Microsoft Copilot Studio integration
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
from dotenv import load_dotenv

from mcp_server_servicenow.server import (
    ServiceNowMCP, 
    create_basic_auth, 
    create_token_auth, 
    create_oauth_auth,
    IncidentCreate,
    IncidentUpdate
)

# Load environment variables
load_dotenv()

app = FastAPI(
    title="ServiceNow MCP API",
    description="REST API for ServiceNow MCP Server - Microsoft Copilot Studio Integration",
    version="1.0.0"
)

# Enable CORS for Copilot Studio
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to Copilot Studio domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global server instance (will be initialized on startup)
server: Optional[ServiceNowMCP] = None

# Request/Response Models
class NaturalLanguageSearchRequest(BaseModel):
    query: str = Field(..., description="Natural language search query")
    
class NaturalLanguageUpdateRequest(BaseModel):
    command: str = Field(..., description="Natural language update command")
    
class SearchRecordsRequest(BaseModel):
    query: str = Field(..., description="Text query to search for")
    table: str = Field(default="incident", description="Table to search in")
    limit: int = Field(default=10, description="Maximum number of results")
    
class GetRecordRequest(BaseModel):
    table: str = Field(..., description="Table name")
    sys_id: str = Field(..., description="System ID of the record")
    
class CreateIncidentRequest(BaseModel):
    short_description: str = Field(..., description="Short description of the incident")
    description: str = Field(..., description="Detailed description")
    caller_id: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    urgency: Optional[int] = None
    impact: Optional[int] = None
    assignment_group: Optional[str] = None
    assigned_to: Optional[str] = None
    
class UpdateIncidentRequest(BaseModel):
    number: str = Field(..., description="Incident number (e.g., INC0010001)")
    short_description: Optional[str] = None
    description: Optional[str] = None
    state: Optional[int] = None
    work_notes: Optional[str] = None
    comments: Optional[str] = None
    
class PerformQueryRequest(BaseModel):
    table: str = Field(..., description="Table to query")
    query: str = Field(default="", description="ServiceNow encoded query string")
    limit: int = Field(default=10, description="Maximum number of results")
    offset: int = Field(default=0, description="Number of records to skip")
    fields: Optional[list[str]] = None

@app.on_event("startup")
async def startup_event():
    """Initialize the ServiceNow MCP server on startup"""
    global server
    
    instance_url = os.environ.get("SERVICENOW_INSTANCE_URL")
    if not instance_url:
        raise ValueError("SERVICENOW_INSTANCE_URL environment variable is required")
    
    # Determine authentication method
    auth = None
    if os.environ.get("SERVICENOW_TOKEN"):
        auth = create_token_auth(os.environ.get("SERVICENOW_TOKEN"))
    elif (os.environ.get("SERVICENOW_CLIENT_ID") and 
          os.environ.get("SERVICENOW_CLIENT_SECRET") and
          os.environ.get("SERVICENOW_USERNAME") and
          os.environ.get("SERVICENOW_PASSWORD")):
        auth = create_oauth_auth(
            os.environ.get("SERVICENOW_CLIENT_ID"),
            os.environ.get("SERVICENOW_CLIENT_SECRET"),
            os.environ.get("SERVICENOW_USERNAME"),
            os.environ.get("SERVICENOW_PASSWORD"),
            instance_url
        )
    elif os.environ.get("SERVICENOW_USERNAME") and os.environ.get("SERVICENOW_PASSWORD"):
        auth = create_basic_auth(
            os.environ.get("SERVICENOW_USERNAME"),
            os.environ.get("SERVICENOW_PASSWORD")
        )
    else:
        raise ValueError("Authentication credentials required")
    
    server = ServiceNowMCP(instance_url=instance_url, auth=auth)
    print("ServiceNow MCP Server initialized successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    global server
    if server:
        await server.close()

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ServiceNow MCP API",
        "version": "1.0.0"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/api/v1/search/natural-language")
async def natural_language_search(request: NaturalLanguageSearchRequest):
    """
    Search for records using natural language
    
    Example: "find all incidents about email"
    """
    try:
        result = await server.natural_language_search(query=request.query)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/update/natural-language")
async def natural_language_update(request: NaturalLanguageUpdateRequest):
    """
    Update records using natural language
    
    Example: "Update incident INC0010001 saying I'm working on it"
    """
    try:
        result = await server.natural_language_update(command=request.command)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/search/records")
async def search_records(request: SearchRecordsRequest):
    """Search for records using text query"""
    try:
        result = await server.search_records(
            query=request.query,
            table=request.table,
            limit=request.limit
        )
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/records/get")
async def get_record(request: GetRecordRequest):
    """Get a specific record by sys_id"""
    try:
        result = await server.get_record(
            table=request.table,
            sys_id=request.sys_id
        )
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/incidents/create")
async def create_incident(request: CreateIncidentRequest):
    """Create a new incident"""
    try:
        incident_data = IncidentCreate(
            short_description=request.short_description,
            description=request.description,
            caller_id=request.caller_id,
            category=request.category,
            subcategory=request.subcategory,
            urgency=request.urgency,
            impact=request.impact,
            assignment_group=request.assignment_group,
            assigned_to=request.assigned_to
        )
        result = await server.create_incident(incident=incident_data)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/incidents/update")
async def update_incident(request: UpdateIncidentRequest):
    """Update an existing incident"""
    try:
        update_data = IncidentUpdate(
            short_description=request.short_description,
            description=request.description,
            state=request.state,
            work_notes=request.work_notes,
            comments=request.comments
        )
        result = await server.update_incident(
            number=request.number,
            updates=update_data
        )
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/query/perform")
async def perform_query(request: PerformQueryRequest):
    """Perform a query against ServiceNow"""
    try:
        result = await server.perform_query(
            table=request.table,
            query=request.query,
            limit=request.limit,
            offset=request.offset,
            fields=request.fields
        )
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/incidents/{incident_number}")
async def get_incident_by_number(incident_number: str):
    """Get an incident by its number"""
    try:
        result = await server.get_incident(number=incident_number)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/incidents")
async def list_incidents():
    """List recent incidents"""
    try:
        result = await server.list_incidents()
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def main():
    """Run the API server"""
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    uvicorn.run(
        "mcp_server_servicenow.api_server:app",
        host=host,
        port=port,
        reload=False
    )

if __name__ == "__main__":
    main()