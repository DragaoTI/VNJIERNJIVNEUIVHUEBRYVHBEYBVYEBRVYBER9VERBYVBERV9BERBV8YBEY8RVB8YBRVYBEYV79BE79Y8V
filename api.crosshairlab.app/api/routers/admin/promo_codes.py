from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from ...repositories.promo_code_repository import PromoCodeRepository
from ...schemas.promo_code import (
    PromoCodeCreate,
    PromoCodeUpdate,
    PromoCodeResponse,
    PromoCodeDetailResponse,
    PromoCodeUseResponse,
    AdminActionLog
)
from ...security.auth import get_current_user
from ...models.user import User
from .router import verify_admin_access

# Cria o router para códigos promocionais com um caminho mais complexo
router = APIRouter(
    prefix="/promotion-management",
    tags=["admin", "promo-codes"],
    responses={404: {"description": "Not found"}},
)

@router.get("/codes", response_model=List[PromoCodeResponse])
async def list_promo_codes(
    search: Optional[str] = None,
    reward_type: Optional[str] = None,
    active_only: bool = False,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: dict = Depends(verify_admin_access)
):
    """
    Lista todos os códigos promocionais.
    Suporta busca por termo, filtragem por tipo de recompensa e status.
    """
    if search:
        promo_codes = await PromoCodeRepository.search(search, active_only, limit, offset)
    elif reward_type:
        promo_codes = await PromoCodeRepository.filter_by_reward_type(reward_type, active_only, limit, offset)
    else:
        promo_codes = await PromoCodeRepository.get_all(active_only, limit, offset)
    
    return [pc.to_dict() for pc in promo_codes]

@router.get("/codes/{promo_code_id}", response_model=PromoCodeDetailResponse)
async def get_promo_code(
    promo_code_id: UUID,
    admin: dict = Depends(verify_admin_access)
):
    """
    Obtém detalhes de um código promocional específico.
    """
    promo_code = await PromoCodeRepository.get_by_id(promo_code_id)
    
    if not promo_code:
        raise HTTPException(status_code=404, detail="Código promocional não encontrado")
    
    # Aqui poderíamos adicionar mais detalhes como o nome do administrador que criou o código
    promo_code_dict = promo_code.to_dict()
    
    # Você pode adicionar lógica para buscar o nome de usuário do criador
    # Por exemplo:
    # if promo_code.created_by:
    #     creator = await UserRepository.get_by_id(promo_code.created_by)
    #     promo_code_dict["created_by_username"] = creator.username if creator else None
    
    return promo_code_dict

@router.post("/codes", response_model=PromoCodeResponse, status_code=201)
async def create_promo_code(
    promo_code: PromoCodeCreate,
    admin: dict = Depends(verify_admin_access)
):
    """
    Cria um novo código promocional.
    """
    # Verifica se já existe um código com o mesmo nome
    existing_code = await PromoCodeRepository.get_by_code(promo_code.code)
    if existing_code:
        raise HTTPException(status_code=400, detail="Código promocional já existe")
    
    # Prepara os dados para criação
    promo_code_data = promo_code.dict()
    promo_code_data["created_by"] = admin.get("user_id")
    
    # Cria o código promocional
    created_promo_code = await PromoCodeRepository.create(promo_code_data)
    
    # Registra a ação administrativa
    await PromoCodeRepository.log_admin_action(
        admin_id=UUID(admin.get("user_id")),
        action_type="create",
        entity_type="promo_code",
        entity_id=UUID(created_promo_code.id),
        details={"code": created_promo_code.code}
    )
    
    return created_promo_code.to_dict()

@router.post("/codes/generate", response_model=PromoCodeResponse, status_code=201)
async def generate_promo_code(
    prefix: Optional[str] = Query(None, max_length=10),
    reward_type: str = Query(..., min_length=1),
    max_uses: int = Query(1, ge=1),
    is_active: bool = True,
    expires_at: Optional[datetime] = None,
    notes: Optional[str] = None,
    admin: dict = Depends(verify_admin_access)
):
    """
    Gera um código promocional aleatório.
    """
    # Gera um código aleatório
    code = PromoCodeRepository.generate_random_code(prefix)
    
    # Prepara os dados para criação
    promo_code_data = {
        "code": code,
        "reward_type": reward_type,
        "max_uses": max_uses,
        "is_active": is_active,
        "expires_at": expires_at,
        "notes": notes,
        "created_by": admin.get("user_id")
    }
    
    # Cria o código promocional
    created_promo_code = await PromoCodeRepository.create(promo_code_data)
    
    # Registra a ação administrativa
    await PromoCodeRepository.log_admin_action(
        admin_id=UUID(admin.get("user_id")),
        action_type="create",
        entity_type="promo_code",
        entity_id=UUID(created_promo_code.id),
        details={"code": created_promo_code.code, "generated": True}
    )
    
    return created_promo_code.to_dict()

@router.put("/codes/{promo_code_id}", response_model=PromoCodeResponse)
async def update_promo_code(
    promo_code_id: UUID,
    promo_code_update: PromoCodeUpdate,
    admin: dict = Depends(verify_admin_access)
):
    """
    Atualiza um código promocional existente.
    """
    # Verifica se o código existe
    existing_promo_code = await PromoCodeRepository.get_by_id(promo_code_id)
    if not existing_promo_code:
        raise HTTPException(status_code=404, detail="Código promocional não encontrado")
    
    # Se estiver atualizando o código, verifica se o novo código já existe
    if promo_code_update.code and promo_code_update.code.upper() != existing_promo_code.code:
        code_check = await PromoCodeRepository.get_by_code(promo_code_update.code)
        if code_check:
            raise HTTPException(status_code=400, detail="Código promocional já existe")
    
    # Prepara os dados para atualização
    promo_code_data = promo_code_update.dict(exclude_unset=True)
    
    # Atualiza o código promocional
    updated_promo_code = await PromoCodeRepository.update(promo_code_id, promo_code_data)
    
    # Registra a ação administrativa
    await PromoCodeRepository.log_admin_action(
        admin_id=UUID(admin.get("user_id")),
        action_type="update",
        entity_type="promo_code",
        entity_id=promo_code_id,
        details=promo_code_data
    )
    
    return updated_promo_code.to_dict()

@router.delete("/codes/{promo_code_id}", status_code=204)
async def delete_promo_code(
    promo_code_id: UUID,
    admin: dict = Depends(verify_admin_access)
):
    """
    Remove um código promocional.
    """
    # Verifica se o código existe
    existing_promo_code = await PromoCodeRepository.get_by_id(promo_code_id)
    if not existing_promo_code:
        raise HTTPException(status_code=404, detail="Código promocional não encontrado")
    
    # Remove o código promocional
    success = await PromoCodeRepository.delete(promo_code_id)
    
    if not success:
        raise HTTPException(status_code=500, detail="Erro ao remover código promocional")
    
    # Registra a ação administrativa
    await PromoCodeRepository.log_admin_action(
        admin_id=UUID(admin.get("user_id")),
        action_type="delete",
        entity_type="promo_code",
        entity_id=promo_code_id,
        details={"code": existing_promo_code.code}
    )
    
    return None

@router.get("/codes/{promo_code_id}/uses", response_model=List[PromoCodeUseResponse])
async def get_promo_code_uses(
    promo_code_id: UUID,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: dict = Depends(verify_admin_access)
):
    """
    Obtém o histórico de usos de um código promocional.
    """
    # Verifica se o código existe
    existing_promo_code = await PromoCodeRepository.get_by_id(promo_code_id)
    if not existing_promo_code:
        raise HTTPException(status_code=404, detail="Código promocional não encontrado")
    
    # Busca os usos do código
    uses = await PromoCodeRepository.get_uses_by_promo_code(promo_code_id, limit, offset)
    
    return [use.to_dict() for use in uses]

@router.get("/logs", response_model=List[AdminActionLog])
async def get_admin_action_logs(
    action_type: Optional[str] = None,
    entity_type: Optional[str] = None,
    admin_id: Optional[UUID] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: dict = Depends(verify_admin_access)
):
    """
    Obtém logs de ações administrativas.
    """
    # Aqui você implementaria a lógica para buscar os logs de ações administrativas
    # com base nos filtros fornecidos.
    
    # Este é um exemplo de implementação:
    
    supabase = get_supabase()
    
    query = supabase.table('admin_action_logs').select('*')
    
    if action_type:
        query = query.eq('action_type', action_type)
    if entity_type:
        query = query.eq('entity_type', entity_type)
    if admin_id:
        query = query.eq('admin_id', str(admin_id))
    
    response = query.order('created_at', desc=True).range(offset, offset + limit - 1).execute()
    
    logs = response.data if response.data else []
    
    # Você pode enriquecer os logs com informações adicionais aqui
    # Por exemplo, adicionar nomes de usuários dos administradores
    
    return logs 
