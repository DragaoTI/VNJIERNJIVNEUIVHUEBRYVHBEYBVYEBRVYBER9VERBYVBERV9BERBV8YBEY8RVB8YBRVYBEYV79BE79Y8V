# app/routers/admin_panel_router.py
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response, Cookie
from typing import List, Optional
import uuid
import time
from pydantic import SecretStr
import secrets
import ipaddress
from datetime import datetime, timedelta

from app.schemas.admin_schemas import (
    AdminLoginSchema, AdminToken, AdminResponseSchema, 
    AdminCreateSchema, AdminUpdateSchema
)
from app.schemas.log_schemas import ApiLogResponseSchema
from app.auth.admin_jwt_handler import create_admin_access_token
from app.auth.admin_dependencies import get_current_admin_user, get_current_super_admin_user
from app.models.admin import Administrator
from app.core.config import settings
from app.services import admin_service_instance, supabase_service
from app.utils.rate_limiter import limiter

# Define um router com prefixo aleatório para aumentar a segurança
ADMIN_PANEL_PATH = settings.ADMIN_PANEL_URL or "/admin-panel"
ADMIN_PANEL_SECRET = secrets.token_urlsafe(16)

admin_panel_router = APIRouter(
    prefix=ADMIN_PANEL_PATH,
    tags=["Admin Panel"]
)

# Lista de IPs permitidos para acessar o painel admin (configurável)
ADMIN_ALLOWED_IPS = []
if hasattr(settings, "ALLOWED_ADMIN_IP_RANGES") and settings.ALLOWED_ADMIN_IP_RANGES:
    for ip_range in settings.ALLOWED_ADMIN_IP_RANGES.split(","):
        try:
            ADMIN_ALLOWED_IPS.append(ipaddress.ip_network(ip_range.strip()))
        except ValueError:
            pass

# Middleware para verificar IP e realizar outras verificações de segurança
async def admin_security_middleware(request: Request):
    # Verifica se o IP está na lista de permitidos
    if ADMIN_ALLOWED_IPS:
        client_ip = ipaddress.ip_address(request.client.host)
        allowed = any(client_ip in ip_network for ip_network in ADMIN_ALLOWED_IPS)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso ao painel de administração negado para este IP"
            )
    
    # Verifica cabeçalhos de segurança
    user_agent = request.headers.get("user-agent", "")
    if "bot" in user_agent.lower() or "spider" in user_agent.lower() or "crawl" in user_agent.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso ao painel de administração negado"
        )
    
    # Registra tentativa de acesso
    await supabase_service.log_admin_access_attempt(
        ip=request.client.host,
        user_agent=user_agent,
        path=str(request.url),
        method=request.method
    )

# Verificação CSRF
def generate_csrf_token():
    return secrets.token_hex(32)

def verify_csrf_token(csrf_token: str, stored_token: str):
    if not csrf_token or not stored_token or csrf_token != stored_token:
        return False
    return True

@admin_panel_router.post("/auth/token", response_model=AdminToken, summary="Login do Administrador do Painel")
async def login_for_admin_panel_token(
    request: Request,
    response: Response,
    form_data: AdminLoginSchema
):
    # Aplica middleware de segurança
    await admin_security_middleware(request)
    
    # Verifica rate limit específico para login de admin
    client_ip = request.client.host
    if not await limiter.check_rate_limit(client_ip, "admin_login", max_requests=5, window_seconds=300):
        # Registra tentativa de login com falha
        await supabase_service.log_admin_login_failure(
            ip=client_ip,
            username=form_data.username,
            reason="rate_limit_exceeded"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Tente novamente mais tarde."
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    # Sanitiza inputs
    username = form_data.username.strip().lower()
    password = form_data.password
    client_hwid = form_data.client_hwid_identifier.strip() if form_data.client_hwid_identifier else None
    
    # Tenta autenticar
    admin = await admin_service_instance.authenticate_admin(
        username=username,
        plain_password=password,
        client_hwid_identifier=client_hwid
    )
    
    if not admin:
        # Registra tentativa de login com falha
        await supabase_service.log_admin_login_failure(
            ip=client_ip,
            username=username,
            reason="invalid_credentials"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário, senha ou identificador de dispositivo incorreto.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if admin.status != "active":
        # Registra tentativa de login com falha
        await supabase_service.log_admin_login_failure(
            ip=client_ip,
            username=username,
            reason="inactive_account"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Conta de administrador inativa."
        )
    
    # Registra login bem-sucedido
    admin_service_instance.update_last_login(admin.id)
    await supabase_service.log_admin_login_success(
        ip=client_ip,
        admin_id=admin.id,
        username=username
    )
    
    # Gera token JWT
    access_token_payload = {
        "sub": str(admin.id),
        "role": admin.role,
        "ip": client_ip
    }
    access_token = create_admin_access_token(data=access_token_payload)
    
    # Gera token CSRF
    csrf_token = generate_csrf_token()
    
    # Define cookies seguros
    response.set_cookie(
        key="admin_csrf_token",
        value=csrf_token,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=28800  # 8 horas
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "csrf_token": csrf_token
    }

@admin_panel_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Logout do Administrador")
async def admin_logout(
    response: Response,
    current_admin: Administrator = Depends(get_current_admin_user)
):
    # Limpa cookies
    response.delete_cookie(key="admin_csrf_token")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@admin_panel_router.get("/me", response_model=AdminResponseSchema, summary="Obter Informações do Administrador Logado")
async def read_current_admin(
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Verifica IP no token
    token_ip = getattr(current_admin, "token_ip", None)
    if token_ip and token_ip != request.client.host:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sessão inválida"
        )
    
    return current_admin

@admin_panel_router.get("/administrators", response_model=List[AdminResponseSchema], summary="Listar Todos os Administradores")
async def list_all_administrators(
    request: Request,
    skip: int = Query(0, ge=0), 
    limit: int = Query(20, ge=1, le=100),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_super_admin_user)  # Apenas super admin pode ver todos
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    admins = admin_service_instance.list_admins(skip=skip, limit=limit)
    return admins

@admin_panel_router.get("/administrators/{admin_id}", response_model=AdminResponseSchema, summary="Obter um Administrador por ID")
async def get_administrator_by_id_route(
    admin_id: uuid.UUID,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Apenas super admin pode ver outros admins
    if str(current_admin.id) != str(admin_id) and current_admin.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão negada"
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    admin = await admin_service_instance.get_admin_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Administrador com ID {admin_id} não encontrado."
        )
    
    return admin

@admin_panel_router.post("/administrators", response_model=AdminResponseSchema, status_code=status.HTTP_201_CREATED, summary="Criar Novo Administrador")
async def create_new_admin(
    admin_in: AdminCreateSchema,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_super_admin_user)  # Apenas super admin pode criar
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    # Validações de senha
    password = admin_in.password.get_secret_value()
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A senha deve ter no mínimo 12 caracteres"
        )
    
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A senha deve conter letras maiúsculas, minúsculas e números"
        )
    
    existing_admin = await admin_service_instance.get_admin_by_username(admin_in.username)
    if existing_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Nome de usuário já registrado para um administrador."
        )
    
    # Limite de admins para prevenir abuso
    admins_count = len(admin_service_instance.list_admins(skip=0, limit=100))
    max_admins = getattr(settings, "MAX_ADMINS", 10)
    if admins_count >= max_admins:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Limite de {max_admins} administradores atingido"
        )
    
    new_admin = admin_service_instance.create_admin(admin_in)
    if not new_admin:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Falha ao criar administrador."
        )
    
    # Registra criação de admin
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="create_admin",
        target_id=new_admin.id,
        details=f"Criou administrador: {admin_in.username}"
    )
    
    return new_admin

@admin_panel_router.put("/administrators/{admin_id}", response_model=AdminResponseSchema, summary="Atualizar Administrador Existente")
async def update_existing_admin(
    admin_id: uuid.UUID,
    admin_in: AdminUpdateSchema,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Apenas super admin pode atualizar outros admins
    if str(current_admin.id) != str(admin_id) and current_admin.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão negada"
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    # Validações de senha se estiver atualizando
    if admin_in.password:
        password = admin_in.password.get_secret_value()
        if len(password) < 12:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A senha deve ter no mínimo 12 caracteres"
            )
        
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A senha deve conter letras maiúsculas, minúsculas e números"
            )
    
    updated_admin = admin_service_instance.update_admin(admin_id, admin_in)
    if not updated_admin:
        check_admin_exists = await admin_service_instance.get_admin_by_id(admin_id)
        if not check_admin_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Administrador com ID {admin_id} não encontrado."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail=f"Falha ao atualizar administrador com ID {admin_id}."
            )
    
    # Registra atualização de admin
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="update_admin",
        target_id=admin_id,
        details=f"Atualizou administrador: {updated_admin.username}"
    )
    
    return updated_admin

@admin_panel_router.delete("/administrators/{admin_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Desativar Administrador")
async def delete_administrator(
    admin_id: uuid.UUID,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_super_admin_user)  # Apenas super admin pode excluir
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Não pode excluir a si mesmo
    if str(current_admin.id) == str(admin_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível excluir seu próprio usuário"
        )
    
    if not admin_service_instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço de administração indisponível."
        )
    
    admin = await admin_service_instance.get_admin_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Administrador com ID {admin_id} não encontrado."
        )
    
    # Não exclui realmente, apenas desativa
    success = admin_service_instance.deactivate_admin(admin_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Falha ao desativar administrador com ID {admin_id}."
        )
    
    # Registra desativação de admin
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="deactivate_admin",
        target_id=admin_id,
        details=f"Desativou administrador: {admin.username}"
    )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@admin_panel_router.get("/logs/api", response_model=List[ApiLogResponseSchema], summary="Visualizar Logs da API")
async def get_api_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    method: Optional[str] = Query(None, min_length=3, max_length=10), 
    status_code_filter: Optional[int] = Query(None, alias="status_code", ge=100, le=599),
    path_contains: Optional[str] = Query(None, min_length=1),
    user_id_filter: Optional[uuid.UUID] = Query(None, alias="user_id"),
    admin_id_filter: Optional[uuid.UUID] = Query(None, alias="admin_id"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: Administrator = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    if not supabase_service or not supabase_service.client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Serviço Supabase indisponível para logging."
        )
    
    try:
        query = supabase_service.client.table("api_logs").select("*").order("timestamp", desc=True).offset(skip).limit(limit)
        
        # Aplica filtros
        if method: 
            query = query.eq("method", method.upper())
        if status_code_filter is not None: 
            query = query.eq("status_code", status_code_filter)
        if path_contains: 
            query = query.ilike("path", f"%{path_contains}%")
        if user_id_filter: 
            query = query.eq("user_id", str(user_id_filter))
        if admin_id_filter: 
            query = query.eq("admin_id", str(admin_id_filter))
        if start_date:
            query = query.gte("timestamp", start_date.isoformat())
        if end_date:
            query = query.lte("timestamp", end_date.isoformat())
        
        response = query.execute()
        
        # Registra visualização de logs
        await supabase_service.log_admin_activity(
            admin_id=current_admin.id,
            action="view_logs",
            details=f"Visualizou {len(response.data or [])} logs da API"
        )
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Erro ao buscar logs da API: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Falha ao buscar logs da API."
        )
