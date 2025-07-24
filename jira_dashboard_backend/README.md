# Jira Dashboard Backend

A secure FastAPI backend for handling Jira authentication, session management, and API proxy functionality.

## Security Configuration

### JWT Secret (Required)

The application requires a secure JWT secret for session token signing. This **must** be configured via environment variable:

```bash
export JWT_SECRET="your-secure-random-string-here"
```

**Important Security Notes:**
- The JWT_SECRET must be a cryptographically secure random string (minimum 32 characters recommended)
- Never use default or predictable values like "secret", "testsecret", etc.
- Generate a secure secret using: `openssl rand -hex 32` or `python -c "import secrets; print(secrets.token_hex(32))"`
- Keep this secret confidential and never commit it to version control

### Environment Variables

Create a `.env` file in the backend root directory:

```env
JWT_SECRET=your-secure-random-jwt-secret-here
```

## Installation & Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment variables (see Security Configuration above)

3. Run the application:
```bash
uvicorn src.api.main:app --reload
```

## API Documentation

Once running, access the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

## Security Features

- Secure JWT-based session management
- HTTP-only cookies for session tokens
- CORS protection with configurable origins
- Security headers middleware
- Input validation with Pydantic models
- Secure credential handling for Jira API integration

## Production Deployment

For production deployments:
1. Set `COOKIE_SECURE = True` (requires HTTPS)
2. Configure `ALLOWED_ORIGINS` to specific domains (remove "*")
3. Use a strong, unique JWT_SECRET
4. Enable HTTPS/TLS encryption
5. Consider additional security measures like rate limiting
