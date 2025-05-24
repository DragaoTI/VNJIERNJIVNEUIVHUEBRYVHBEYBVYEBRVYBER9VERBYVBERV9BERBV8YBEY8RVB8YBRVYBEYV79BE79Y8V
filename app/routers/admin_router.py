from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, Response, Cookie
from app.auth.dependencies import get_current_admin_user, get_current_super_admin_user
from app.models.user import User
from app.services.supabase_service import supabase_service
from app.schemas.geo_log_schemas import GeoLogResponse
from app.schemas.user_schemas import UserResponse
from typing import List, Optional
import secrets
import uuid
from datetime import datetime, timedelta

# Geração de um path aleatório para aumentar a segurança
ADMIN_PATH_PREFIX = secrets.token_urlsafe(16)

router = APIRouter(
    prefix=f"/{ADMIN_PATH_PREFIX}_admin", 
    tags=["Admin"], 
    dependencies=[Depends(get_current_admin_user)]
)

# Função para verificar CSRF token
def verify_csrf_token(csrf_token: str, stored_token: str):
    if not csrf_token or not stored_token or csrf_token != stored_token:
        return False
    return True

@router.get(f"/{ADMIN_PATH_PREFIX}", summary="Painel de Admin Simples")
async def admin_dashboard(
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Registra acesso ao painel
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="dashboard_access",
        details="Acesso ao painel de administração"
    )
    
    return {
        "message": f"Bem-vindo ao painel de admin, {current_admin.email}!",
        "role": current_admin.role,
        "access_time": datetime.now().isoformat(),
        "admin_id": str(current_admin.id)
    }

@router.get("/geologs", response_model=List[GeoLogResponse], summary="Listar Logs de GeoIP")
async def list_geo_logs(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    ip_contains: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    filters = {}
    
    if start_date:
        filters['start_date'] = start_date.isoformat()
    
    if end_date:
        filters['end_date'] = end_date.isoformat()
    
    if ip_contains:
        filters['ip_contains'] = ip_contains
        
    if country_code:
        filters['country_code'] = country_code
    
    logs = await supabase_service.get_all_geo_logs(limit=limit, offset=offset, filters=filters)
    
    # Registra visualização de logs
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_geo_logs",
        details=f"Visualizou {len(logs)} logs de geolocalização"
    )
    
    return logs

@router.get("/users", response_model=List[UserResponse], summary="Listar Usuários")
async def list_users(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    email_contains: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    filters = {}
    
    if email_contains:
        filters['email_contains'] = email_contains
        
    if status:
        filters['status'] = status
        
    if role:
        filters['role'] = role
    
    users = await supabase_service.get_all_users(limit=limit, offset=offset, filters=filters)
    
    # Registra visualização de usuários
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_users",
        details=f"Visualizou {len(users)} usuários"
    )
    
    return users

@router.get("/users/{user_id}", response_model=UserResponse, summary="Obter Usuário por ID")
async def get_user(
    user_id: uuid.UUID,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    user = await supabase_service.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {user_id} não encontrado"
        )
    
    # Registra visualização de usuário
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_user",
        target_id=user_id,
        details=f"Visualizou usuário {user.email}"
    )
    
    return user

@router.put("/users/{user_id}/status", summary="Atualizar Status do Usuário")
async def update_user_status(
    user_id: uuid.UUID,
    status: str,
    request: Request,
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_super_admin_user)  # Apenas super admin pode atualizar status
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Valida status
    valid_statuses = ["active", "inactive", "banned", "pending"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Status inválido. Deve ser um dos seguintes: {', '.join(valid_statuses)}"
        )
    
    # Verifica se usuário existe
    user = await supabase_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {user_id} não encontrado"
        )
    
    # Atualiza status
    success = await supabase_service.update_user_status(user_id, status)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao atualizar status do usuário"
        )
    
    # Registra atualização de status
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="update_user_status",
        target_id=user_id,
        details=f"Alterou status do usuário {user.email} para {status}"
    )
    
    return {"message": f"Status do usuário atualizado para {status}"}

@router.get("/system/stats", summary="Estatísticas do Sistema")
async def system_stats(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_admin_user)
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    # Calcula data de início
    start_date = datetime.now() - timedelta(days=days)
    
    # Obtém estatísticas
    stats = await supabase_service.get_system_stats(start_date)
    
    # Registra visualização de estatísticas
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_system_stats",
        details=f"Visualizou estatísticas do sistema dos últimos {days} dias"
    )
    
    return stats

@router.get("/security/logs", summary="Logs de Segurança")
async def security_logs(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    csrf_token: str = Cookie(None),
    admin_csrf_token: str = Cookie(None),
    current_admin: User = Depends(get_current_super_admin_user)  # Apenas super admin pode ver logs de segurança
):
    # Verifica CSRF token
    if not verify_csrf_token(csrf_token, admin_csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token CSRF inválido"
        )
    
    filters = {}
    
    if severity:
        filters['severity'] = severity
        
    if event_type:
        filters['event_type'] = event_type
        
    if start_date:
        filters['start_date'] = start_date.isoformat()
        
    if end_date:
        filters['end_date'] = end_date.isoformat()
    
    logs = await supabase_service.get_security_logs(limit=limit, offset=offset, filters=filters)
    
    # Registra visualização de logs de segurança
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_security_logs",
        details=f"Visualizou {len(logs)} logs de segurança"
    )
    
    return logs

# Você pode adicionar outras rotas aqui:
# - Listar usuários (cuidado com a paginação e dados sensíveis)
# - Banir/ativar usuários
# - Mudar role de usuário (com muita cautela)
