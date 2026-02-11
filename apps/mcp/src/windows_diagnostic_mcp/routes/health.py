"""Health check and status endpoints."""

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import time


async def health_check(request: Request) -> JSONResponse:
    """Basic health check endpoint."""
    return JSONResponse({
        "status": "healthy",
        "timestamp": time.time(),
        "service": "windows-diagnostic-mcp"
    })


async def auth_status(request: Request) -> JSONResponse:
    """Check authentication status."""
    user = getattr(request, 'user', None)
    
    if user and user.is_authenticated:
        return JSONResponse({
            "authenticated": True,
            "username": user.display_name,
            "scopes": getattr(user, 'scopes', []),
            "timestamp": time.time()
        })
    else:
        return JSONResponse({
            "authenticated": False,
            "timestamp": time.time()
        }, status_code=401)


# Route definitions
health_routes = [
    Route("/health", health_check, methods=["GET"]),
    Route("/auth/status", auth_status, methods=["GET"]),
] 