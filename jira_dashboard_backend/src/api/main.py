import os
import requests
import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional, List

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Request,
    Response,
    Cookie
)
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from pydantic import BaseModel, Field, EmailStr, validator

import jwt
from datetime import datetime, timedelta

# == Settings ==
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required and must be set to a secure random string")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 60 * 6  # token valid for 6 hours

JIRA_API_BASE_TEMPLATE = "https://{domain}/rest/api/3"
JIRA_API_PROJECTS_ENDPOINT = "/project/search"

COOKIE_NAME = "jira_dashboard_token"
COOKIE_SECURE = True  # Should be True in production (HTTPS)

# CORS Configuration - Environment-based origins for security
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
if ENVIRONMENT == "production":
    # TODO: Replace with actual production domain(s)
    ALLOWED_ORIGINS = ["https://your-production-domain.com"]
else:
    # Development: Only allow React dev server
    ALLOWED_ORIGINS = ["http://localhost:3000"]

# == FastAPI Setup & Metadata ==
tags_metadata = [
    {
        "name": "auth",
        "description": "Operations related to authentication and session management",
    },
    {
        "name": "jira",
        "description": "Operations for fetching data from Jira (projects etc.)",
    },
]

app = FastAPI(
    title="Jira Dashboard Backend API",
    description="""
    REST API for securely handling Jira login/authentication, credential validation, session management, and project data fetching for the Secure Jira Dashboard app.
    """,
    version="1.0.0",
    openapi_tags=tags_metadata
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# == SECURITY VALIDATION FUNCTIONS ==

# PUBLIC_INTERFACE
def validate_jira_domain(domain: str) -> str:
    """
    Validate Jira domain to prevent SSRF attacks and ensure only legitimate Atlassian domains.
    
    Args:
        domain: The domain to validate
        
    Returns:
        str: The validated domain
        
    Raises:
        ValueError: If domain is invalid or potentially malicious
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string")
    
    # Remove any protocol if provided
    domain = domain.replace("https://", "").replace("http://", "").strip()
    
    # Remove trailing slash
    domain = domain.rstrip("/")
    
    # Basic format validation - must be a valid domain format
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    if not domain_pattern.match(domain):
        raise ValueError("Invalid domain format")
    
    # Domain length validation
    if len(domain) > 253:
        raise ValueError("Domain name too long")
    
    # Must end with .atlassian.net for legitimate Jira Cloud instances
    if not domain.endswith('.atlassian.net'):
        raise ValueError("Only Atlassian Cloud domains (.atlassian.net) are allowed")
    
    # Additional validation: ensure it's a proper subdomain of atlassian.net
    parts = domain.split('.')
    if len(parts) < 3:  # Should be at least subdomain.atlassian.net
        raise ValueError("Invalid Atlassian domain format")
    
    # Validate subdomain part (first part before .atlassian.net)
    subdomain = parts[0]
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$', subdomain) and len(subdomain) > 1:
        if not re.match(r'^[a-zA-Z0-9]$', subdomain):  # Single character subdomains
            raise ValueError("Invalid subdomain format")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        'localhost', '127.', '10.', '172.', '192.168.', 
        'internal', 'admin', 'test', 'staging'
    ]
    
    for pattern in suspicious_patterns:
        if pattern in domain.lower():
            raise ValueError(f"Suspicious domain pattern detected: {pattern}")
    
    # Perform DNS resolution to validate the domain exists and is not pointing to internal IPs
    try:
        # Resolve domain to IP addresses
        ip_addresses = socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        for addr_info in ip_addresses:
            ip_str = addr_info[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Block private/internal IP ranges (SSRF protection)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                raise ValueError(f"Domain resolves to private/internal IP address: {ip_str}")
            
            # Block multicast and reserved ranges
            if ip_obj.is_multicast or ip_obj.is_reserved:
                raise ValueError(f"Domain resolves to reserved IP address: {ip_str}")
                
    except socket.gaierror:
        raise ValueError("Domain could not be resolved - DNS lookup failed")
    except Exception as e:
        if "private/internal IP" in str(e) or "reserved IP" in str(e):
            raise e
        raise ValueError("Failed to validate domain - DNS resolution error")
    
    return domain


# == Pydantic Models ==

class LoginRequest(BaseModel):
    jira_email: EmailStr = Field(..., description="Jira account email.")
    jira_domain: str = Field(..., description="Your Jira instance domain (e.g. 'your-domain.atlassian.net').")
    jira_api_token: str = Field(..., description="Jira API token generated from your Atlassian account.")
    
    @validator('jira_domain')
    def validate_domain(cls, v):
        """Validate Jira domain for security and format compliance."""
        return validate_jira_domain(v)
    
    @validator('jira_api_token')
    def validate_api_token(cls, v):
        """Validate API token format and length."""
        if not v or not isinstance(v, str):
            raise ValueError("API token is required")
        
        # Jira API tokens are typically 24 characters long
        if len(v.strip()) < 20:
            raise ValueError("API token appears to be too short")
        
        # Basic format validation - should be alphanumeric
        if not re.match(r'^[A-Za-z0-9]+$', v.strip()):
            raise ValueError("API token contains invalid characters")
        
        return v.strip()

class LoginResponse(BaseModel):
    message: str = Field(..., description="Success or error message")
    user_email: EmailStr = Field(..., description="Authenticated Jira email")
    token_expires_at: datetime = Field(..., description="JWT expiration timestamp (UTC)")

class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error explanation message.")

class ProjectLead(BaseModel):
    displayName: str = Field(..., description="Name of the project lead.")
    accountId: Optional[str] = Field(None, description="Account ID of the lead.")

class Project(BaseModel):
    id: str
    key: str
    name: str
    projectTypeKey: str
    lead: Optional[ProjectLead]
    avatarUrls: Optional[dict]
    lastUpdated: Optional[str]
    archived: Optional[bool]


class ProjectsResponse(BaseModel):
    projects: List[Project]


# == JWT UTILS ==
# PUBLIC_INTERFACE
def create_jwt(email: str, domain: str, api_token: str) -> str:
    """Create a JWT session token."""
    exp = datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)
    payload = {
        "jira_email": email,
        "jira_domain": domain,
        "jira_api_token": api_token,
        "exp": exp,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

# PUBLIC_INTERFACE
def decode_jwt(token: str) -> Optional[dict]:
    """Decode and validate JWT. Returns claims if valid, else None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session token.")
    return payload

# PUBLIC_INTERFACE
def get_current_session(
    token: Optional[str] = Cookie(None, alias=COOKIE_NAME)
) -> dict:
    """Dependency to retrieve session from JWT cookie or raise error."""
    if not token:
        raise HTTPException(status_code=401, detail="Login required: no session cookie")
    return decode_jwt(token)


# == JIRA HELPERS ==
def jira_auth_headers(email: str, api_token: str):
    import base64
    # Construct the Basic Auth header (email:token base64)
    basic_token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    return {"Authorization": f"Basic {basic_token}", "Accept": "application/json"}


# PUBLIC_INTERFACE
def make_secure_jira_request(url: str, headers: dict, timeout: int = 10) -> requests.Response:
    """
    Make a secure HTTP request to Jira API with additional security checks.
    
    Args:
        url: The URL to request
        headers: HTTP headers to include
        timeout: Request timeout in seconds
        
    Returns:
        requests.Response: The HTTP response
        
    Raises:
        HTTPException: If request fails or security checks fail
    """
    # Parse and validate the URL
    try:
        parsed_url = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Ensure HTTPS only
    if parsed_url.scheme != 'https':
        raise HTTPException(status_code=400, detail="Only HTTPS URLs are allowed")
    
    # Validate hostname is Atlassian domain
    hostname = parsed_url.hostname
    if not hostname or not hostname.endswith('.atlassian.net'):
        raise HTTPException(status_code=400, detail="Only Atlassian domains are allowed")
    
    # Perform additional DNS validation for the hostname
    try:
        validate_jira_domain(hostname)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Domain validation failed: {str(e)}")
    
    # Make the request with security headers and timeout
    try:
        response = requests.get(
            url, 
            headers=headers, 
            timeout=timeout,
            allow_redirects=False,  # Prevent redirect-based SSRF
            verify=True  # Ensure SSL certificate verification
        )
        return response
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=408, detail="Request timeout - Jira API did not respond in time")
    except requests.exceptions.SSLError:
        raise HTTPException(status_code=400, detail="SSL certificate verification failed")
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Failed to connect to Jira API")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")


# == ROUTES ==

@app.get("/", tags=["health"], summary="Health Check", description="Service health check endpoint.")
def health_check():
    """Check backend service health."""
    return {"status": "healthy"}


# PUBLIC_INTERFACE
@app.post(
    "/auth/login",
    summary="Authenticate to Jira and start session",
    description="""
    Validate provided Jira credentials (email, domain, API token) by authenticating against the Jira API and establish a secure session using a JWT cookie.
    
    TODO: Implement rate limiting to prevent brute force attacks on authentication endpoints.
    Consider implementing:
    - Rate limiting per IP address (e.g., 5 attempts per minute)
    - Rate limiting per email address (e.g., 10 attempts per hour)
    - Progressive delays for failed attempts
    - Account lockout mechanisms for repeated failures
    """,
    tags=["auth"],
    response_model=LoginResponse,
    responses={
        200: {"model": LoginResponse, "description": "Login successful."},
        401: {"model": ErrorResponse, "description": "Bad credentials / authentication failed."}
    }
)
def login(
    payload: LoginRequest,
    response: Response
):
    """
    Authenticate user with Jira API using provided email/domain/token.
    If valid, return response with JWT session cookie.
    On failure, return clear error message.
    
    Domain validation and SSRF protection are automatically applied via the LoginRequest model.
    """
    # Build URL with validated domain (validation happened in Pydantic model)
    base_url = JIRA_API_BASE_TEMPLATE.format(domain=payload.jira_domain)
    test_url = base_url + "/myself"
    headers = jira_auth_headers(payload.jira_email, payload.jira_api_token)

    # Use secure request function with additional security checks
    r = make_secure_jira_request(test_url, headers, timeout=15)
    
    if r.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail="Login failed: Jira authentication unsuccessful. Please check your credentials, API token, or domain."
        )

    # Create session
    token = create_jwt(payload.jira_email, payload.jira_domain, payload.jira_api_token)
    exp = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])["exp"]
    exp_dt = datetime.utcfromtimestamp(exp)

    # Set cookie (HttpOnly, Secure if HTTPS)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=JWT_EXPIRY_MINUTES * 60
    )

    return LoginResponse(
        message="Login successful.",
        user_email=payload.jira_email,
        token_expires_at=exp_dt
    )


# PUBLIC_INTERFACE
@app.post(
    "/auth/logout",
    summary="Log out and remove session",
    description="Invalidate the current session by removing the session cookie. This does NOT affect the Jira API token itself.",
    tags=["auth"],
    responses={
        200: {"description": "Successfully logged out"},
    }
)
def logout(response: Response):
    """
    Logs out user by deleting the JWT cookie from the browser.
    """
    response.delete_cookie(COOKIE_NAME)
    return {"message": "Logged out."}


# PUBLIC_INTERFACE
@app.get(
    "/auth/session",
    summary="Check login/session status",
    description="Checks if JWT session cookie exists and is valid.",
    tags=["auth"],
    responses={
        200: {"description": "Session is valid."},
        401: {"model": ErrorResponse, "description": "Session invalid or expired."}
    }
)
def session_status(session=Depends(get_current_session)):
    """
    Returns session info if authenticated, else error.
    """
    return {
        "jira_email": session["jira_email"],
        "jira_domain": session["jira_domain"],
        "expires_at": datetime.utcfromtimestamp(session["exp"])
    }


# PUBLIC_INTERFACE
@app.get(
    "/jira/projects",
    summary="Fetch Jira projects for the authenticated user",
    description="""
    Returns all Jira projects visible to the authenticated user, with fields like project name, key, type, issues, lead, status, icon, and last updated.
    """,
    tags=["jira"],
    response_model=ProjectsResponse,
    responses={
        200: {"model": ProjectsResponse},
        401: {"model": ErrorResponse, "description": "Session invalid or expired."},
        500: {"model": ErrorResponse, "description": "Failed to fetch Jira projects."}
    }
)
def get_projects(session=Depends(get_current_session)):
    """
    Calls Jira's REST API using credentials from current session/JWT and returns the projects list.
    Domain validation and SSRF protection are applied via secure request function.
    """
    jira_email = session["jira_email"]
    jira_domain = session["jira_domain"]
    jira_api_token = session["jira_api_token"]

    # Re-validate domain from session for additional security
    try:
        validated_domain = validate_jira_domain(jira_domain)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain in session: {str(e)}"
        )

    base_url = JIRA_API_BASE_TEMPLATE.format(domain=validated_domain)
    url = base_url + JIRA_API_PROJECTS_ENDPOINT

    headers = jira_auth_headers(jira_email, jira_api_token)

    # Use secure request function with additional security checks
    r = make_secure_jira_request(url, headers, timeout=15)
    
    if r.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve Jira projects. Verify Jira token access rights."
        )

    data = r.json()
    projects = []
    for p in data.get("values", []):
        # Map fields for frontend compatibility
        projects.append(Project(
            id=p.get("id"),
            key=p.get("key"),
            name=p.get("name"),
            projectTypeKey=p.get("projectTypeKey"),
            lead=ProjectLead(**p["lead"]) if p.get("lead") else None,
            avatarUrls=p.get("avatarUrls"),
            lastUpdated=p.get("lastUpdated") or p.get("lastIssueUpdatedTime") or None,
            archived=p.get("archived")
        ))
    return ProjectsResponse(projects=projects)


# == ERROR HANDLING ==

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    status_code = exc.status_code
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail}
    )


# == SECURITY HEADERS (Best practice) ==
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    return response
