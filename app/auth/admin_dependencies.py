# app/auth/admin_dependencies.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import uuid
import time
from datetime import datetime, timedelta

from app.auth.admin_jwt_handler import verify_admin_token
from app.schemas.admin_schemas import AdminTokenData
# Precisa da instância do AdminService
# from app.services import admin_service_instance # Assumindo que você criou a instância
from app.models.admin import Administrator
from app.core.config import settings # Para o tokenUrl
from app.services import admin_service_instance
from app.utils.rate_limiter import limiter


# Este é o URL onde o admin faz login para obter o token
# Ajuste o prefixo do router de admin se for diferente
ADMIN_PANEL_TOKEN_URL = f"{settings.API_V1_STR}{settings.ADMIN_PANEL_URL}/auth/token" 

oauth2_scheme_admin_panel = OAuth2PasswordBearer(tokenUrl=ADMIN_PANEL_TOKEN_URL, auto_error=True)

# Função para verificar se há tentativas de ataque de força bruta
async def check_brute_force_attempts(request: Request):
    client_ip = request.client.host
    if not await limiter.check_rate_limit(client_ip, "admin_auth", max_requests=10, window_seconds=60):
        # Registra tentativa de ataque
        try:
            await admin_service_instance.log_security_event(
                event_type="brute_force_attempt",
                ip=client_ip,
                details="Múltiplas tentativas de autenticação administrativa",
                severity="high"
            )
        except:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de autenticação. Tente novamente mais tarde.",
            headers={"Retry-After": "300"}  # Sugere esperar 5 minutos
        )

# Verifica IP do cliente
async def verify_client_ip(request: Request, token_ip: Optional[str]):
    if token_ip and token_ip != request.client.host:
        # Possível roubo de token - IP diferente
        try:
            await admin_service_instance.log_security_event(
                event_type="token_ip_mismatch",
                ip=request.client.host,
                token_ip=token_ip,
                details="IP do cliente diferente do IP armazenado no token",
                severity="critical"
            )
        except:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido - possível sequestro de sessão",
            headers={"WWW-Authenticate": "Bearer"}
        )

async def get_current_admin_user(
    request: Request,
    token: str = Depends(oauth2_scheme_admin_panel)
) -> Administrator:
    # Verifica tentativas de força bruta
    await check_brute_force_attempts(request)
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais de administrador",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Verifica token
    token_data: Optional[AdminTokenData] = verify_admin_token(token, credentials_exception)
    if not token_data or not token_data.admin_id:
        # Registra falha de autenticação
        try:
            await admin_service_instance.log_security_event(
                event_type="invalid_admin_token",
                ip=request.client.host,
                details="Token de administrador inválido",
                severity="medium"
            )
        except:
            pass
        
        raise credentials_exception
    
    # Verifica IP do cliente comparado com o IP armazenado no token
    if hasattr(token_data, "ip"):
        await verify_client_ip(request, token_data.ip)
    
    # Obtém o administrador
    try:
        admin_id_uuid = uuid.UUID(token_data.admin_id)
        admin = await admin_service_instance.get_admin_by_id(admin_id_uuid)
    except (ValueError, Exception):
        # Registra falha de autenticação
        try:
            await admin_service_instance.log_security_event(
                event_type="admin_id_error",
                ip=request.client.host,
                admin_id=token_data.admin_id,
                details="ID de administrador inválido ou erro ao buscar administrador",
                severity="medium"
            )
        except:
            pass
            
        raise credentials_exception
    
    if admin is None:
        # Registra falha de autenticação
        try:
            await admin_service_instance.log_security_event(
                event_type="admin_not_found",
                ip=request.client.host,
                admin_id=token_data.admin_id,
                details="Administrador não encontrado com o ID fornecido",
                severity="medium"
            )
        except:
            pass
            
        raise credentials_exception
    
    if admin.status != "active":
        # Registra falha de autenticação
        try:
            await admin_service_instance.log_security_event(
                event_type="inactive_admin_access",
                ip=request.client.host,
                admin_id=str(admin.id),
                username=admin.username,
                details="Tentativa de acesso com conta de administrador inativa",
                severity="high"
            )
        except:
            pass
            
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Conta de administrador inativa."
        )
    
    # Verifica se a última atividade foi há muito tempo
    if admin.last_login:
        last_login_time = admin.last_login
        if isinstance(last_login_time, str):
            try:
                last_login_time = datetime.fromisoformat(last_login_time.replace('Z', '+00:00'))
            except:
                last_login_time = None
        
        if last_login_time:
            inactive_time = datetime.now() - last_login_time
            max_inactivity = timedelta(days=getattr(settings, "ADMIN_MAX_INACTIVITY_DAYS", 30))
            
            if inactive_time > max_inactivity:
                # Desativa administrador inativo
                try:
                    admin_service_instance.deactivate_admin(admin.id)
                    await admin_service_instance.log_security_event(
                        event_type="admin_auto_deactivated",
                        ip=request.client.host,
                        admin_id=str(admin.id),
                        username=admin.username,
                        details=f"Administrador desativado automaticamente após {max_inactivity.days} dias de inatividade",
                        severity="medium"
                    )
                except:
                    pass
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Conta de administrador desativada por inatividade."
                )
    
    # Adiciona IP do token ao objeto admin para verificação posterior
    if hasattr(token_data, "ip"):
        setattr(admin, "token_ip", token_data.ip)
    
    # Atualiza último acesso
    try:
        admin_service_instance.update_last_access(admin.id)
    except:
        pass
        
    return admin

async def get_current_super_admin_user(
    request: Request,
    current_admin: Administrator = Depends(get_current_admin_user)
) -> Administrator:
    if current_admin.role != "super_admin":
        # Registra tentativa de acesso não autorizado
        try:
            await admin_service_instance.log_security_event(
                event_type="unauthorized_super_admin_access",
                ip=request.client.host,
                admin_id=str(current_admin.id),
                username=current_admin.username,
                details=f"Tentativa de acesso a recurso de super administrador por usuário com role '{current_admin.role}'",
                severity="high"
            )
        except:
            pass
            
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão de super administrador necessária para esta operação."
        )
    
    return current_admin
