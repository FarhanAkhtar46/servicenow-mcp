"""
REST API Server for ServiceNow MCP
This module provides HTTP REST endpoints for Microsoft Copilot Studio integration
"""

import os
import json
from typing import Optional, Any, Dict, List

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from mcp_server_servicenow.authz import get_current_user, UserContext
from mcp_server_servicenow.server import (
    ServiceNowMCP,
    create_basic_auth,
    create_token_auth,
    create_oauth_auth,
    IncidentCreate,
    IncidentUpdate,
)

# Load environment variables
load_dotenv()

app = FastAPI(
    title="ServiceNow MCP API",
    description="REST API for ServiceNow MCP Server - Microsoft Copilot Studio Integration",
    version="1.0.0",
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


# ----------------------------
# Models
# ----------------------------
class NaturalLanguageSearchRequest(BaseModel):
    query: str = Field(..., description="Natural language search query")


class NaturalLanguageUpdateRequest(BaseModel):
    command: str = Field(..., description="Natural language update command")


class CloseIncidentRequest(BaseModel):
    number: str = Field(..., description="Incident number (e.g., INC0010001)")
    close_code: str = Field(
        ...,
        description="Close code (e.g., Resolved by request, Duplicate, Resolved by caller, Resolved by change, Resolved by problem, Solution provided)",
    )
    close_notes: str = Field(..., description="Close notes")


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
    caller_id: Optional[str] = None  # sys_id (preferred). We will override for end-users.
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
    close_code: Optional[str] = None
    close_notes: Optional[str] = None


class PerformQueryRequest(BaseModel):
    table: str = Field(..., description="Table to query")
    query: str = Field(default="", description="ServiceNow encoded query string")
    limit: int = Field(default=10, description="Maximum number of results")
    offset: int = Field(default=0, description="Number of records to skip")
    fields: Optional[List[str]] = None


# ----------------------------
# Auth helper
# ----------------------------
async def get_user_or_dev(request: Request) -> UserContext:
    """
    Local dev convenience:
      - If DEV_USER_EMAIL is set, bypass auth and use that identity.
      - Otherwise use real auth via get_current_user().
    """
    dev_email = "rameshmahto@M365B257947.onmicrosoft.com"
    if dev_email:
        roles = [r.strip() for r in os.getenv("DEV_ROLES", "").split(",") if r.strip()]
        is_agent = os.getenv("DEV_IS_AGENT", "false").lower() == "true"
        return UserContext(email=dev_email.lower(), roles=roles, is_agent=is_agent)
    return await get_current_user(request)


def require_server() -> ServiceNowMCP:
    if not server:
        raise HTTPException(
            status_code=500,
            detail="Server not initialized. Check environment variables / Azure Application Settings.",
        )
    return server


def require_agent(user: UserContext):
    if not user.is_agent:
        raise HTTPException(status_code=403, detail="Not allowed (agent role required).")


# ----------------------------
# Startup / Shutdown
# ----------------------------
@app.on_event("startup")
async def startup_event():
    """Initialize the ServiceNow MCP server on startup"""
    global server

    instance_url = os.environ.get("SERVICENOW_INSTANCE_URL")
    if not instance_url:
        raise ValueError("SERVICENOW_INSTANCE_URL environment variable is required")

    auth = None
    if os.environ.get("SERVICENOW_TOKEN"):
        auth = create_token_auth(os.environ.get("SERVICENOW_TOKEN"))
    elif (
        os.environ.get("SERVICENOW_CLIENT_ID")
        and os.environ.get("SERVICENOW_CLIENT_SECRET")
        and os.environ.get("SERVICENOW_USERNAME")
        and os.environ.get("SERVICENOW_PASSWORD")
    ):
        auth = create_oauth_auth(
            os.environ.get("SERVICENOW_CLIENT_ID"),
            os.environ.get("SERVICENOW_CLIENT_SECRET"),
            os.environ.get("SERVICENOW_USERNAME"),
            os.environ.get("SERVICENOW_PASSWORD"),
            instance_url,
        )
    elif os.environ.get("SERVICENOW_USERNAME") and os.environ.get("SERVICENOW_PASSWORD"):
        auth = create_basic_auth(
            os.environ.get("SERVICENOW_USERNAME"),
            os.environ.get("SERVICENOW_PASSWORD"),
        )
    else:
        raise ValueError("Authentication credentials required")

    server = ServiceNowMCP(instance_url=instance_url, auth=auth)
    print("ServiceNow MCP Server initialized successfully")


@app.on_event("shutdown")
async def shutdown_event():
    global server
    if server:
        await server.close()


# ----------------------------
# Public endpoints
# ----------------------------
@app.get("/")
async def root():
    return {"status": "healthy", "service": "ServiceNow MCP API", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


# ----------------------------
# Secure: Incidents (User-scoped)
# These three endpoints are the ones you asked about.
# ----------------------------
@app.get("/api/v1/incidents")
async def list_incidents(user: UserContext = Depends(get_user_or_dev)):
    """
    List recent incidents.

    End-user: returns ONLY incidents where caller_id == signed-in user
    Agent: can return broader results (depends on server implementation)
    """
    srv = require_server()
    try:
        # IMPORTANT: use scoped method, NOT the MCP resource handler
        result_str = await srv.list_incidents_scoped(
            user_email=user.email,
            is_agent=user.is_agent,
            limit=10,
        )
        return JSONResponse(content=json.loads(result_str))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/incidents/{incident_number}")
async def get_incident_by_number(incident_number: str, user: UserContext = Depends(get_user_or_dev)):
    """
    Get incident by number.

    End-user: can only fetch their own incident (otherwise 404)
    Agent: can fetch incident based on server policy
    """
    srv = require_server()
    try:
        result_str = await srv.get_incident_scoped(
            number=incident_number,
            user_email=user.email,
            is_agent=user.is_agent,
        )
        payload = json.loads(result_str)

        if payload.get("status") == "failure":
            raise HTTPException(status_code=404, detail="Incident not found")

        return JSONResponse(content=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/incidents/update")
async def update_incident(request: UpdateIncidentRequest, user: UserContext = Depends(get_user_or_dev)):
    """
    Update an incident.

    End-user: can only update their own incident (otherwise 404)
    Agent: can update per server policy
    """
    srv = require_server()
    try:
        update_data = IncidentUpdate(
            short_description=request.short_description,
            description=request.description,
            state=request.state,
            work_notes=request.work_notes,
            comments=request.comments,
            close_code=request.close_code,
            close_notes=request.close_notes,
        )

        result_str = await srv.update_incident_scoped(
            number=request.number,
            updates=update_data,
            user_email=user.email,
            is_agent=user.is_agent,
        )

        payload = json.loads(result_str)
        if payload.get("status") == "failure":
            raise HTTPException(status_code=404, detail="Incident not found")

        return JSONResponse(content=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/incidents/close")
async def close_incident(request: CloseIncidentRequest, user: UserContext = Depends(get_user_or_dev)):
    """
    Resolve/Close an incident.

    Default: only agents can close (unless ALLOW_ENDUSER_CLOSE=true).
    End-user can never close someone else's incident.
    """
    srv = require_server()

    allow_enduser_close = os.getenv("ALLOW_ENDUSER_CLOSE", "false").lower() == "true"
    if not user.is_agent and not allow_enduser_close:
        raise HTTPException(status_code=403, detail="Only agents can close incidents")

    try:
        update_data = IncidentUpdate(
            state=7,  # Closed (make env-driven if needed)
            close_code=request.close_code,
            close_notes=request.close_notes,
        )

        result_str = await srv.update_incident_scoped(
            number=request.number,
            updates=update_data,
            user_email=user.email,
            is_agent=user.is_agent,
        )

        payload = json.loads(result_str)
        if payload.get("status") == "failure":
            raise HTTPException(status_code=404, detail="Incident not found")

        return JSONResponse(content=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------
# Optional: Create incident (scoped caller)
# ----------------------------
@app.post("/api/v1/incidents/create")
async def create_incident(request: CreateIncidentRequest, user: UserContext = Depends(get_user_or_dev)):
    """
    Create a new incident.

    End-user: caller_id is forced to signed-in user's sys_id (looked up by email) if possible.
    Agent: may pass caller_id if your org allows.
    """
    srv = require_server()
    try:
        caller_id = request.caller_id

        if not user.is_agent:
            # Force caller to current user (best-effort: email -> sys_user sys_id)
            caller_id = None
            try:
                if hasattr(srv, "client") and hasattr(srv.client, "get_user_sys_id_by_email"):
                    caller_id = await srv.client.get_user_sys_id_by_email(user.email)
            except Exception:
                caller_id = None  # still allow creation; SN will default based on integration account behavior

        incident_data = IncidentCreate(
            short_description=request.short_description,
            description=request.description,
            caller_id=caller_id,
            category=request.category,
            subcategory=request.subcategory,
            urgency=request.urgency,
            impact=request.impact,
            assignment_group=request.assignment_group,
            assigned_to=request.assigned_to,
        )

        result = await srv.create_incident(incident=incident_data)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------
# Admin/Agent-only endpoints (recommended)
# ----------------------------
@app.post("/api/v1/update/natural-language")
async def natural_language_update(request: NaturalLanguageUpdateRequest, user: UserContext = Depends(get_user_or_dev)):
    """
    Update records using natural language.

    IMPORTANT: Make this agent-only to prevent bypassing incident scoping.
    """
    srv = require_server()
    require_agent(user)

    try:
        result = await srv.natural_language_update(command=request.command)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/search/natural-language")
async def natural_language_search(request: NaturalLanguageSearchRequest, user: UserContext = Depends(get_user_or_dev)):
    """
    Search for records using natural language.

    Recommended agent-only unless you fully scope what tables/fields are searchable.
    """
    srv = require_server()
    require_agent(user)

    try:
        result = await srv.natural_language_search(query=request.query)

        if not result:
            raise HTTPException(status_code=500, detail="Empty response from ServiceNow")

        if isinstance(result, str):
            result_dict = json.loads(result)
        elif isinstance(result, dict):
            result_dict = result
        else:
            raise HTTPException(status_code=500, detail=f"Unexpected response type: {type(result)}")

        return JSONResponse(content=result_dict)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")


@app.post("/api/v1/search/records")
async def search_records(request: SearchRecordsRequest, user: UserContext = Depends(get_user_or_dev)):
    srv = require_server()
    require_agent(user)
    try:
        result = await srv.search_records(query=request.query, table=request.table, limit=request.limit)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/records/get")
async def get_record(request: GetRecordRequest, user: UserContext = Depends(get_user_or_dev)):
    srv = require_server()
    require_agent(user)
    try:
        result = await srv.get_record(table=request.table, sys_id=request.sys_id)
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/query/perform")
async def perform_query(request: PerformQueryRequest, user: UserContext = Depends(get_user_or_dev)):
    srv = require_server()
    require_agent(user)
    try:
        result = await srv.perform_query(
            table=request.table,
            query=request.query,
            limit=request.limit,
            offset=request.offset,
            fields=request.fields,
        )
        return JSONResponse(content=json.loads(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------
# Debug endpoints (optional)
# ----------------------------
@app.get("/api/v1/debug/info")
async def debug_info():
    try:
        return {
            "server_initialized": server is not None,
            "server_client_initialized": server.client is not None if server else False,
            "instance_url": os.environ.get("SERVICENOW_INSTANCE_URL", "NOT SET"),
            "username_set": bool(os.environ.get("SERVICENOW_USERNAME")),
            "password_set": bool(os.environ.get("SERVICENOW_PASSWORD")),
            "dev_user_email_set": bool(os.getenv("DEV_USER_EMAIL")),
            "dev_is_agent": os.getenv("DEV_IS_AGENT", "false"),
        }
    except Exception as e:
        return {"error": str(e)}


# ----------------------------
# Main
# ----------------------------
def main():
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")

    uvicorn.run(
        "mcp_server_servicenow.api_server:app",
        host=host,
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()
