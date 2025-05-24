from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from app.core.config import settings

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware para adicionar cabeçalhos de segurança a todas as respostas
    """
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # Content-Security-Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "block-all-mixed-content; "
            "upgrade-insecure-requests;"
        )
        
        # Strict-Transport-Security
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # X-Content-Type-Options
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-Frame-Options
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-XSS-Protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy (anteriormente Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )
        
        # Cache-Control para conteúdo não estático
        if (
            request.url.path.startswith(f"{settings.API_V1_STR}/") and
            "text/html" not in response.headers.get("Content-Type", "")
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        return response 