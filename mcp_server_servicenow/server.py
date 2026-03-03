"""
ServiceNow MCP Server

This module provides a Model Context Protocol (MCP) server that interfaces with ServiceNow.
It allows AI agents to access and manipulate ServiceNow data through a secure API.

IMPORTANT (for your RBAC + "my incidents only"):
- MCP *resource* handlers MUST match URI params exactly:
  - servicenow://incidents            -> list_incidents(self)
  - servicenow://incidents/{number}   -> get_incident(self, number)

- For your REST API RBAC, use the scoped methods:
  - list_incidents_scoped(user_email, is_agent, limit)
  - get_incident_scoped(number, user_email, is_agent)
  - update_incident_scoped(number, updates, user_email, is_agent)
"""

import json
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Literal

import httpx
from pydantic import BaseModel, Field, field_validator

from mcp_server_servicenow.nlp import NLPProcessor

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------
# Models / Enums
# ---------------------------------------------------------------------
class IncidentState(int, Enum):
    NEW = 1
    IN_PROGRESS = 2
    ON_HOLD = 3
    RESOLVED = 6
    CLOSED = 7
    CANCELED = 8


class IncidentUrgency(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class IncidentImpact(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class IncidentCreate(BaseModel):
    """Model for creating a new incident"""

    short_description: str = Field(..., description="A brief description of the incident")
    description: str = Field(..., description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(IncidentUrgency.MEDIUM, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(IncidentImpact.MEDIUM, description="The impact of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")


class IncidentUpdate(BaseModel):
    """Model for updating an existing incident"""

    short_description: Optional[str] = Field(None, description="A brief description of the incident")
    description: Optional[str] = Field(None, description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(None, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(None, description="The impact of the incident")
    state: Optional[IncidentState] = Field(None, description="The state of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")
    work_notes: Optional[str] = Field(None, description="Work notes to add to the incident (internal)")
    comments: Optional[str] = Field(None, description="Customer visible comments to add to the incident")
    close_code: Optional[str] = Field(None, description="Resolution/close code for the incident")
    close_notes: Optional[str] = Field(None, description="Resolution/close notes for the incident")

    @field_validator("work_notes", "comments")
    @classmethod
    def validate_not_empty(cls, v):
        if v is not None and v.strip() == "":
            raise ValueError("Cannot be an empty string")
        return v

    class Config:
        use_enum_values = True


class QueryOptions(BaseModel):
    """Options for querying ServiceNow records"""

    limit: int = Field(10, description="Maximum number of records to return", ge=1, le=1000)
    offset: int = Field(0, description="Number of records to skip", ge=0)
    fields: Optional[List[str]] = Field(None, description="List of fields to return")
    query: Optional[str] = Field(None, description="ServiceNow encoded query string")
    order_by: Optional[str] = Field(None, description="Field to order results by")
    order_direction: Optional[Literal["asc", "desc"]] = Field("desc", description="Order direction")


class ScriptUpdateModel(BaseModel):
    """Model for updating a ServiceNow script"""

    name: str = Field(..., description="The name of the script")
    script: str = Field(..., description="The script content")
    type: str = Field(..., description="The type of script (e.g., sys_script_include)")
    description: Optional[str] = Field(None, description="Description of the script")


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------
class Authentication:
    async def get_headers(self) -> Dict[str, str]:
        raise NotImplementedError("Subclasses must implement this method")


class BasicAuth(Authentication):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    async def get_headers(self) -> Dict[str, str]:
        return {}

    def get_auth(self) -> tuple:
        return (self.username, self.password)


class TokenAuth(Authentication):
    def __init__(self, token: str):
        self.token = token

    async def get_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get_auth(self) -> None:
        return None


class OAuthAuth(Authentication):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        instance_url: str,
        token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_expiry: Optional[datetime] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.instance_url = instance_url.rstrip("/")
        self.token = token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry  # datetime

    async def get_headers(self) -> Dict[str, str]:
        if self.token is None or (self.token_expiry and datetime.now() > self.token_expiry):
            await self.refresh()
        return {"Authorization": f"Bearer {self.token}"}

    def get_auth(self) -> None:
        return None

    async def refresh(self):
        if self.refresh_token:
            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }
        else:
            data = {
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password,
            }

        token_url = f"{self.instance_url}/oauth_token.do"
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            result = response.json()

            self.token = result["access_token"]
            self.refresh_token = result.get("refresh_token")
            expires_in = int(result.get("expires_in", 1800))  # default 30 minutes
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in)


# ---------------------------------------------------------------------
# ServiceNow Client
# ---------------------------------------------------------------------
class ServiceNowClient:
    """Client for interacting with ServiceNow API"""

    def __init__(self, instance_url: str, auth: Authentication):
        self.instance_url = instance_url.rstrip("/")
        self.auth = auth
        self.client = httpx.AsyncClient()
        self._user_sysid_cache: Dict[str, Optional[str]] = {}
        self._user_cache_lock = asyncio.Lock()

    async def close(self):
        await self.client.aclose()

    async def get_user_sys_id_by_email(self, email: str) -> Optional[str]:
        email = (email or "").strip().lower()
        if not email:
            return None

        async with self._user_cache_lock:
            if email in self._user_sysid_cache:
                return self._user_sysid_cache[email]

        res = await self.request(
            "GET",
            "/api/now/table/sys_user",
            params={
                "sysparm_query": f"email={email}",
                "sysparm_fields": "sys_id,email,user_name,name",
                "sysparm_limit": 1,
            },
        )

        sys_id = None
        if res.get("result"):
            sys_id = res["result"][0].get("sys_id")

        async with self._user_cache_lock:
            self._user_sysid_cache[email] = sys_id

        return sys_id

    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.instance_url}{path}"
        headers = await self.auth.get_headers()
        headers["Accept"] = "application/json"

        auth = self.auth.get_auth() if isinstance(self.auth, BasicAuth) else None

        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                auth=auth,
            )
            response.raise_for_status()

            response_text = (response.text or "").strip()
            if not response_text:
                logger.warning(f"Empty response body from ServiceNow: {method} {url}")
                return {"result": []}

            try:
                return response.json()
            except ValueError as json_err:
                logger.error(f"JSON decode error from ServiceNow: {str(json_err)}")
                logger.error(f"Response status: {response.status_code}")
                logger.error(f"Response headers: {dict(response.headers)}")
                logger.error(f"Response content (first 500 chars): {response_text[:500]}")
                return {"result": []}

        except httpx.HTTPStatusError as e:
            error_text = e.response.text if e.response else "No response text"
            logger.error(f"ServiceNow API HTTP error {e.response.status_code}: {error_text}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in ServiceNow request: {str(e)}")
            raise

    async def get_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        # Allow passing INC number accidentally
        if table == "incident" and sys_id.startswith("INC"):
            incident = await self.get_incident_by_number(sys_id)
            if incident:
                return {"result": incident}
            raise ValueError(f"Incident not found: {sys_id}")
        return await self.request("GET", f"/api/now/table/{table}/{sys_id}")

    async def get_records(self, table: str, options: Optional[QueryOptions] = None) -> Dict[str, Any]:
        if options is None:
            options = QueryOptions()

        params: Dict[str, Any] = {
            "sysparm_limit": options.limit,
            "sysparm_offset": options.offset,
        }

        if options.fields:
            params["sysparm_fields"] = ",".join(options.fields)

        if options.query:
            params["sysparm_query"] = options.query

        # Optional ordering: easiest to put ORDERBY in sysparm_query
        # If you want to keep this, ensure your SN instance supports sysparm_order_by.
        if options.order_by:
            direction = "DESC" if options.order_direction == "desc" else "ASC"
            if params.get("sysparm_query"):
                params["sysparm_query"] += f"^ORDERBY{direction}{options.order_by}"
            else:
                params["sysparm_query"] = f"ORDERBY{direction}{options.order_by}"

        return await self.request("GET", f"/api/now/table/{table}", params=params)

    async def create_record(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.request("POST", f"/api/now/table/{table}", json_data=data)

    async def update_record(self, table: str, sys_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.request("PUT", f"/api/now/table/{table}/{sys_id}", json_data=data)

    async def delete_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        return await self.request("DELETE", f"/api/now/table/{table}/{sys_id}")

    async def get_incident_by_number(self, number: str, caller_sys_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        q = f"number={number}"
        if caller_sys_id:
            q += f"^caller_id={caller_sys_id}"

        result = await self.request(
            "GET",
            "/api/now/table/incident",
            params={"sysparm_query": q, "sysparm_limit": 1},
        )

        if result.get("result") and len(result["result"]) > 0:
            return result["result"][0]
        return None

    async def search(self, query: str, table: str = "incident", limit: int = 10) -> Dict[str, Any]:
        return await self.request(
            "GET",
            f"/api/now/table/{table}",
            params={"sysparm_query": f"123TEXTQUERY321={query}", "sysparm_limit": limit},
        )

    async def get_available_tables(self) -> List[str]:
        result = await self.request(
            "GET",
            "/api/now/table/sys_db_object",
            params={"sysparm_fields": "name,label", "sysparm_limit": 100},
        )
        return result.get("result", [])

    async def get_table_schema(self, table: str) -> Dict[str, Any]:
        return await self.request("GET", f"/api/now/ui/meta/{table}")


# ---------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------
class ServiceNowMCP:
    """ServiceNow MCP Server"""

    def __init__(self, instance_url: str, auth: Authentication, name: str = "ServiceNow MCP"):
        self.client = ServiceNowClient(instance_url, auth)
        self.mcp = FastMCP(name, dependencies=["httpx", "pydantic"])

        # -------------------------
        # Resources (STRICT signatures)
        # -------------------------
        self.mcp.resource("servicenow://incidents")(self.list_incidents)
        self.mcp.resource("servicenow://incidents/{number}")(self.get_incident)
        self.mcp.resource("servicenow://users")(self.list_users)
        self.mcp.resource("servicenow://knowledge")(self.list_knowledge)
        self.mcp.resource("servicenow://tables")(self.get_tables)
        self.mcp.resource("servicenow://tables/{table}")(self.get_table_records)
        self.mcp.resource("servicenow://schema/{table}")(self.get_table_schema)

        # -------------------------
        # Tools
        # -------------------------
        self.mcp.tool(name="create_incident")(self.create_incident)
        self.mcp.tool(name="update_incident")(self.update_incident)
        self.mcp.tool(name="search_records")(self.search_records)
        self.mcp.tool(name="get_record")(self.get_record)
        self.mcp.tool(name="perform_query")(self.perform_query)
        self.mcp.tool(name="add_comment")(self.add_comment)
        self.mcp.tool(name="add_work_notes")(self.add_work_notes)

        # Natural language tools
        self.mcp.tool(name="natural_language_search")(self.natural_language_search)
        self.mcp.tool(name="natural_language_update")(self.natural_language_update)
        self.mcp.tool(name="update_script")(self.update_script)

        # Prompts
        self.mcp.prompt(name="analyze_incident")(self.incident_analysis_prompt)
        self.mcp.prompt(name="create_incident_prompt")(self.create_incident_prompt)

    async def close(self):
        await self.client.close()

    def run(self, transport: str = "stdio"):
        try:
            self.mcp.run(transport=transport)
        finally:
            asyncio.run(self.close())

    # -----------------------------------------------------------------
    # Resource handlers (MUST match URI parameters)
    # -----------------------------------------------------------------
    async def list_incidents(self) -> str:
        options = QueryOptions(limit=10)
        result = await self.client.get_records("incident", options)
        return json.dumps(result, indent=2)

    async def get_incident(self, number: str) -> str:
        try:
            incident = await self.client.get_incident_by_number(number)
            if incident:
                return json.dumps({"result": incident}, indent=2)

            return json.dumps(
                {"error": {"message": "No Record found", "detail": "Not found"}, "status": "failure"}
            )
        except Exception as e:
            logger.error(f"Error getting incident {number}: {str(e)}")
            return json.dumps({"error": {"message": "Error retrieving record"}, "status": "failure"})

    async def list_users(self) -> str:
        options = QueryOptions(limit=10)
        result = await self.client.get_records("sys_user", options)
        return json.dumps(result, indent=2)

    async def list_knowledge(self) -> str:
        options = QueryOptions(limit=10)
        result = await self.client.get_records("kb_knowledge", options)
        return json.dumps(result, indent=2)

    async def get_tables(self) -> str:
        result = await self.client.get_available_tables()
        return json.dumps({"result": result}, indent=2)

    async def get_table_records(self, table: str) -> str:
        options = QueryOptions(limit=10)
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)

    async def get_table_schema(self, table: str) -> str:
        result = await self.client.get_table_schema(table)
        return json.dumps(result, indent=2)

    # -----------------------------------------------------------------
    # SCOPED helpers for your REST API (RBAC / "my incidents only")
    # -----------------------------------------------------------------
    async def list_incidents_scoped(self, user_email: Optional[str], is_agent: bool, limit: int = 10) -> str:
        options = QueryOptions(limit=limit)

        if user_email and not is_agent:
            caller_sys_id = await self.client.get_user_sys_id_by_email(user_email)
            if not caller_sys_id:
                return json.dumps({"result": []}, indent=2)
            options.query = f"caller_id={caller_sys_id}^ORDERBYDESCsys_created_on"

        result = await self.client.get_records("incident", options)
        return json.dumps(result, indent=2)

    async def get_incident_scoped(self, number: str, user_email: Optional[str], is_agent: bool) -> str:
        caller_sys_id = None
        if user_email and not is_agent:
            caller_sys_id = await self.client.get_user_sys_id_by_email(user_email)
            if not caller_sys_id:
                return json.dumps({"error": {"message": "No Record found"}, "status": "failure"})

        incident = await self.client.get_incident_by_number(number, caller_sys_id=caller_sys_id)
        if incident:
            return json.dumps({"result": incident}, indent=2)

        return json.dumps({"error": {"message": "No Record found"}, "status": "failure"})

    async def update_incident_scoped(
        self,
        number: str,
        updates: IncidentUpdate,
        user_email: Optional[str],
        is_agent: bool,
        ctx: Context = None,
    ) -> str:
        caller_sys_id = None
        if user_email and not is_agent:
            caller_sys_id = await self.client.get_user_sys_id_by_email(user_email)

        # IMPORTANT: check ownership BEFORE updating
        incident = await self.client.get_incident_by_number(number, caller_sys_id=caller_sys_id)
        if not incident:
            return json.dumps({"error": {"message": "No Record found"}, "status": "failure"})

        sys_id = incident["sys_id"]
        data = updates.dict(exclude_none=True)

        if ctx:
            await ctx.info(f"Updating incident (scoped): {number}")

        result = await self.client.update_record("incident", sys_id, data)
        return json.dumps(result, indent=2)

    # -----------------------------------------------------------------
    # Tool handlers
    # -----------------------------------------------------------------
    async def create_incident(self, incident, ctx: Context = None) -> str:
        """
        Create a new incident in ServiceNow
        incident can be:
        - str: treated as description (short_description auto-generated)
        - dict: used directly
        - IncidentCreate: used directly
        """
        if isinstance(incident, str):
            short_desc = incident[:50] + ("..." if len(incident) > 50 else "")
            incident_data = {"short_description": short_desc, "description": incident}
            logger.info(f"Creating incident from string description: {short_desc}")
        elif isinstance(incident, dict):
            incident_data = incident
            logger.info(f"Creating incident from dictionary: {incident.get('short_description', 'No short description')}")
        elif isinstance(incident, IncidentCreate):
            incident_data = incident.dict(exclude_none=True)
            logger.info(f"Creating incident from IncidentCreate: {incident.short_description}")
        else:
            error_message = f"Invalid incident type: {type(incident)}. Expected IncidentCreate, dict, or str."
            logger.error(error_message)
            return json.dumps({"error": error_message})

        # Ensure required fields
        if "short_description" not in incident_data:
            desc = incident_data.get("description", "Incident created through API")
            incident_data["short_description"] = desc[:50] + ("..." if len(desc) > 50 else "")

        if "description" not in incident_data:
            incident_data["description"] = incident_data.get("short_description", "No description provided")

        if ctx:
            await ctx.info(f"Creating incident: {incident_data.get('short_description', 'No short description')}")

        try:
            result = await self.client.create_record("incident", incident_data)
            if ctx and result.get("result", {}).get("number"):
                await ctx.info(f"Created incident: {result['result']['number']}")
            return json.dumps(result, indent=2)
        except Exception as e:
            error_message = f"Error creating incident: {str(e)}"
            logger.error(error_message)
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})

    async def update_incident(self, number: str, updates: IncidentUpdate, ctx: Context = None) -> str:
        """
        Unscoped update tool (agent usage). Your REST API should use update_incident_scoped().
        """
        if ctx:
            await ctx.info(f"Looking up incident: {number}")

        incident = await self.client.get_incident_by_number(number)
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})

        sys_id = incident["sys_id"]
        data = updates.dict(exclude_none=True)

        if ctx:
            await ctx.info(f"Updating incident: {number}")

        result = await self.client.update_record("incident", sys_id, data)
        return json.dumps(result, indent=2)

    async def search_records(self, query: str, table: str = "incident", limit: int = 10, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Searching {table} for: {query}")
        result = await self.client.search(query, table, limit)
        return json.dumps(result, indent=2)

    async def get_record(self, table: str, sys_id: str, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Getting {table} record: {sys_id}")
        result = await self.client.get_record(table, sys_id)
        return json.dumps(result, indent=2)

    async def perform_query(
        self,
        table: str,
        query: str = "",
        limit: int = 10,
        offset: int = 0,
        fields: Optional[List[str]] = None,
        ctx: Context = None,
    ) -> str:
        if ctx:
            await ctx.info(f"Querying {table} with: {query}")

        options = QueryOptions(limit=limit, offset=offset, fields=fields, query=query)
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)

    async def add_comment(self, number: str, comment: str, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Adding comment to incident: {number}")

        incident = await self.client.get_incident_by_number(number)
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})

        sys_id = incident["sys_id"]
        result = await self.client.update_record("incident", sys_id, {"comments": comment})
        return json.dumps(result, indent=2)

    async def add_work_notes(self, number: str, work_notes: str, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Adding work notes to incident: {number}")

        incident = await self.client.get_incident_by_number(number)
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})

        sys_id = incident["sys_id"]
        result = await self.client.update_record("incident", sys_id, {"work_notes": work_notes})
        return json.dumps(result, indent=2)

    # -----------------------------------------------------------------
    # Natural language tools
    # -----------------------------------------------------------------
    async def natural_language_search(self, query: str, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Processing natural language query: {query}")

        search_params = NLPProcessor.parse_search_query(query)

        if ctx:
            await ctx.info(f"Searching {search_params['table']} with query: {search_params['query']}")

        options = QueryOptions(limit=search_params["limit"], query=search_params["query"])
        result = await self.client.get_records(search_params["table"], options)
        return json.dumps(result, indent=2)

    async def natural_language_update(self, command: str, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Processing natural language update: {command}")

        try:
            record_number, updates = NLPProcessor.parse_update_command(command)

            if record_number.startswith("INC"):
                incident = await self.client.get_incident_by_number(record_number)
                if not incident:
                    error_message = f"Incident {record_number} not found"
                    if ctx:
                        await ctx.error(error_message)
                    return json.dumps({"error": error_message})

                sys_id = incident["sys_id"]
                table = "incident"
            else:
                error_message = f"Record type not supported: {record_number}"
                if ctx:
                    await ctx.error(error_message)
                return json.dumps({"error": error_message})

            incident_update = IncidentUpdate(
                short_description=updates.get("short_description"),
                description=updates.get("description"),
                caller_id=updates.get("caller_id"),
                category=updates.get("category"),
                subcategory=updates.get("subcategory"),
                urgency=updates.get("urgency"),
                impact=updates.get("impact"),
                state=updates.get("state"),
                assignment_group=updates.get("assignment_group"),
                assigned_to=updates.get("assigned_to"),
                work_notes=updates.get("work_notes"),
                comments=updates.get("comments"),
                close_code=updates.get("close_code"),
                close_notes=updates.get("close_notes"),
            )

            data = incident_update.dict(exclude_none=True)
            result = await self.client.update_record(table, sys_id, data)
            return json.dumps(result, indent=2)

        except ValueError as e:
            error_message = str(e)
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})

    async def update_script(self, script_update: ScriptUpdateModel, ctx: Context = None) -> str:
        if ctx:
            await ctx.info(f"Updating script: {script_update.name}")

        table = script_update.type
        query = f"name={script_update.name}"

        options = QueryOptions(limit=1, query=query)
        result = await self.client.get_records(table, options)

        if not result.get("result") or len(result["result"]) == 0:
            if ctx:
                await ctx.info(f"Script not found, creating new script: {script_update.name}")
            data = {"name": script_update.name, "script": script_update.script}
            if script_update.description:
                data["description"] = script_update.description
            result = await self.client.create_record(table, data)
        else:
            script = result["result"][0]
            sys_id = script["sys_id"]

            if ctx:
                await ctx.info(f"Updating existing script: {script_update.name} ({sys_id})")

            data = {"script": script_update.script}
            if script_update.description:
                data["description"] = script_update.description
            result = await self.client.update_record(table, sys_id, data)

        return json.dumps(result, indent=2)

    # -----------------------------------------------------------------
    # Prompts
    # -----------------------------------------------------------------
    def incident_analysis_prompt(self, incident_number: str) -> str:
        return f"""
Please analyze the following ServiceNow incident {incident_number}.

First, call the appropriate tool to fetch the incident details using get_incident.

Then, provide a comprehensive analysis with the following sections:

1. Summary: A brief overview of the incident
2. Impact Assessment: Analysis of the impact based on the severity, priority, and affected users
3. Root Cause Analysis: Potential causes based on available information
4. Resolution Recommendations: Suggested next steps to resolve the incident
5. SLA Status: Whether the incident is at risk of breaching SLAs

Use a professional and clear tone appropriate for IT service management.
"""

    def create_incident_prompt(self) -> str:
        return """
I'll help you create a new ServiceNow incident. Please provide the following information:

1. Short Description: A brief title for the incident (required)
2. Detailed Description: A thorough explanation of the issue (required)
3. Caller: The person reporting the issue (optional)
4. Category and Subcategory: The type of issue (optional)
5. Impact (1-High, 2-Medium, 3-Low): How broadly this affects users (optional)
6. Urgency (1-High, 2-Medium, 3-Low): How time-sensitive this issue is (optional)

After collecting this information, I'll use the create_incident tool to submit the incident to ServiceNow.
"""


# ---------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------
def create_basic_auth(username: str, password: str) -> BasicAuth:
    return BasicAuth(username, password)


def create_token_auth(token: str) -> TokenAuth:
    return TokenAuth(token)


def create_oauth_auth(client_id: str, client_secret: str, username: str, password: str, instance_url: str) -> OAuthAuth:
    return OAuthAuth(client_id, client_secret, username, password, instance_url)
