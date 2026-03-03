# mcp_server_servicenow/authz.py
import os
import base64
import json
from typing import Dict, List, Optional

from fastapi import HTTPException, Request
from pydantic import BaseModel
import jwt
from jwt import PyJWKClient


class UserContext(BaseModel):
    email: str
    name: Optional[str] = None
    roles: List[str] = []
    claims: Dict[str, List[str]] = {}
    is_agent: bool = False


def _split_csv(env_value: str) -> List[str]:
    return [x.strip() for x in (env_value or "").split(",") if x.strip()]


def _claims_multimap(claims_list) -> Dict[str, List[str]]:
    mm: Dict[str, List[str]] = {}
    for c in claims_list or []:
        typ = c.get("typ")
        val = c.get("val")
        if not typ or val is None:
            continue
        mm.setdefault(typ, []).append(val)
    return mm


def _extract_from_easy_auth(request: Request) -> Optional[UserContext]:
    # If you enable App Service Authentication, this header is present for authenticated users
    principal_b64 = request.headers.get("x-ms-client-principal")
    if not principal_b64:
        return None

    try:
        decoded = base64.b64decode(principal_b64).decode("utf-8")
        principal = json.loads(decoded)
        claims_mm = _claims_multimap(principal.get("claims", []))

        # common claim keys
        email = (
            (claims_mm.get("preferred_username") or [None])[0]
            or (claims_mm.get("upn") or [None])[0]
            or (claims_mm.get("email") or [None])[0]
        )
        if not email:
            return None

        # roles may appear in different claim types
        roles = []
        roles += claims_mm.get("roles", [])
        roles += claims_mm.get("role", [])
        roles += claims_mm.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", [])

        user = UserContext(
            email=email.lower(),
            name=principal.get("name"),
            roles=roles,
            claims=claims_mm,
        )
        user.is_agent = user_is_agent(user)
        return user
    except Exception:
        return None


def _extract_from_bearer_jwt(request: Request) -> Optional[UserContext]:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None

    token = auth.split(" ", 1)[1].strip()

    tenant_id = os.getenv("AAD_TENANT_ID")
    audience = os.getenv("AAD_AUDIENCE")  # e.g. api://<app-id> OR <client-id>
    if not tenant_id or not audience:
        # If you use EasyAuth, you can skip this path.
        raise HTTPException(
            status_code=500,
            detail="AAD_TENANT_ID and AAD_AUDIENCE must be set for JWT validation.",
        )

    jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    jwk_client = PyJWKClient(jwks_url)
    signing_key = jwk_client.get_signing_key_from_jwt(token).key

    # issuer for v2 tokens
    issuer = os.getenv("AAD_ISSUER") or f"https://login.microsoftonline.com/{tenant_id}/v2.0"

    claims = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )

    email = (claims.get("preferred_username") or claims.get("upn") or claims.get("email"))
    if not email:
        return None

    roles = claims.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]

    user = UserContext(
        email=email.lower(),
        name=claims.get("name"),
        roles=roles,
        claims={k: ([v] if not isinstance(v, list) else v) for k, v in claims.items()},
    )
    user.is_agent = user_is_agent(user)
    return user


def user_is_agent(user: UserContext) -> bool:
    # Role based (AAD App Roles / roles claim) OR allowlist email
    agent_roles = set(_split_csv(os.getenv("AGENT_ROLES", "SN_AGENT,SN_ADMIN")))
    agent_emails = set(e.lower() for e in _split_csv(os.getenv("AGENT_EMAILS", "")))

    if user.email in agent_emails:
        return True
    if any(r in agent_roles for r in (user.roles or [])):
        return True
    return False


async def get_current_user(request: Request) -> UserContext:
    # Prefer EasyAuth header if present, else validate Bearer token
    user = _extract_from_easy_auth(request)
    if user:
        return user

    user = _extract_from_bearer_jwt(request)
    if user:
        return user

    raise HTTPException(status_code=401, detail="Unauthorized")
