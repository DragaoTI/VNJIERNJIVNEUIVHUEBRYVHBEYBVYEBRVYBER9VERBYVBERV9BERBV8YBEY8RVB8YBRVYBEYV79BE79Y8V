from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pathlib import Path
import os
import secrets
import time
import uuid

from app.core.config import settings
from app.routers import (
    auth_router, 
    admin_router, 
    admin_panel_router,
    two_factor_router,
    security_router,
    stats_router
)
from app.utils.rate_limiter import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from contextlib import asynccontextmanager
from app.auth.dependencies import get_current_active_user
from app.models.user import User as UserModel
from app.core.logging_middleware import ApiLoggingMiddleware
from app.core.security_scanner import SecurityScannerMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.services.supabase_service import supabase_service
from starlette.middleware.sessions import SessionMiddleware
from app.core.cors_manager import setup_cors

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_ADMIN_DIR = BASE_DIR / "admin_frontend"

# Gerar nonce para CSP
CSP_NONCE = secrets.token_hex(16)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"INFO:     Aplicação '{settings.APP_NAME}' iniciando...")
    # Verificar serviços essenciais
    from app.services import supabase_service, admin_service_instance
    if not supabase_service or not supabase_service.client:
        raise RuntimeError("Supabase service não inicializado corretamente!")
    if not admin_service_instance:
        raise RuntimeError("Admin service não inicializado corretamente!")
    yield
    print(f"INFO:     Aplicação '{settings.APP_NAME}' finalizando...")

app = FastAPI(
    title=settings.APP_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
    docs_url=None if settings.ENVIRONMENT == "production" else "/docs",
    redoc_url=None if settings.ENVIRONMENT == "production" else "/redoc",
)

# Adiciona middleware de segurança (ANTES de outros middlewares)
app.add_middleware(SecurityScannerMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Configuração de CORS segura
setup_cors(app)

# Ordem dos Middlewares é importante:
# 1. Error handling (implícito ou explícito)
# 2. CORS
# 3. Outros middlewares (como o de logging, segurança de headers)
# 4. Middleware de Autenticação (se não for por dependência)

# Adicionado primeiro o middleware de logging para capturar o máximo possível.
# No entanto, se um middleware anterior (como CORS) rejeitar a requisição,
# o middleware de logging pode não capturar a resposta final.
# Considere a ordem baseada no que você quer logar.
# Se o logging vier depois do CORS, ele pegará os headers CORS na resposta.
app.add_middleware(ApiLoggingMiddleware)

# Adiciona compressão Gzip
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Adiciona middleware de sessão segura
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    https_only=settings.ENVIRONMENT == "production",
    same_site="strict",
    max_age=settings.SESSION_MAX_AGE,
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Headers de segurança básicos
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # HSTS apenas em HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # CSP com nonce dinâmico
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{CSP_NONCE}' 'strict-dynamic' https://*.supabase.co https://cdn.jsdelivr.net; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"font-src 'self'; "
        f"connect-src 'self' {settings.ALLOWED_ORIGINS}; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"upgrade-insecure-requests;"
    )
    response.headers["Content-Security-Policy"] = csp
    
    # Adiciona nonce ao HTML se for uma resposta HTML
    if "text/html" in response.headers.get("content-type", ""):
        response.body = response.body.replace(b"<script", f'<script nonce="{CSP_NONCE}"'.encode())
    
    return response

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if FRONTEND_ADMIN_DIR.is_dir():
    print(f"INFO:     Montando UI do Admin em /x9A7uQvP2LmZn53BqC de: {FRONTEND_ADMIN_DIR}")
    app.mount("/x9A7uQvP2LmZn53BqC", StaticFiles(directory=FRONTEND_ADMIN_DIR, html=True), name="admin_frontend_static_files") # Nome único

    @app.get("/painel-admin", include_in_schema=False)
    async def redirect_to_admin_login_page_main(): # Nome único para a função
        return RedirectResponse(url="/x9A7uQvP2LmZn53BqC/admin_login.html", status_code=301)
    print("INFO:     Rota de redirecionamento /painel-admin configurada.")
else:
    print(f"AVISO:    Diretório UI do Admin NÃO ENCONTRADO em '{FRONTEND_ADMIN_DIR}'. UI não será servida.")
    print(f"          Caminho base do projeto detectado: {BASE_DIR}")

app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)
app.include_router(admin_panel_router, prefix=settings.API_V1_STR)
app.include_router(two_factor_router, prefix=settings.API_V1_STR)
app.include_router(security_router, prefix=settings.API_V1_STR)
app.include_router(stats_router, prefix=settings.API_V1_STR)

@app.get("/", tags=["Root"])
async def read_root_main(): # Nome único
    return {"message": f"Bem-vindo à API: {settings.APP_NAME}"}

@app.get(f"{settings.API_V1_STR}/protected-data", tags=["Protected"])
async def get_protected_data_main(current_user: UserModel = Depends(get_current_active_user)): # Nome único
    return {
        "message": "Estes são dados protegidos!",
        "user_email": current_user.email,
        "user_id": current_user.id,
        "user_role": current_user.role
    }

@app.get("/health", tags=["Health"], status_code=status.HTTP_200_OK)
async def health_check_main(): # Nome único
    # Verifica serviços essenciais
    services_status = {
        "api": "ok",
        "database": "ok"
    }
    
    # Verifica conexão com Supabase
    try:
        await supabase_service.health_check()
    except Exception as e:
        services_status["database"] = f"error: {str(e)}"
    
    # Status geral
    overall_status = "healthy" if all(v == "ok" for v in services_status.values()) else "degraded"
    
    return {
        "status": overall_status,
        "services": services_status,
        "timestamp": time.time()
    }
