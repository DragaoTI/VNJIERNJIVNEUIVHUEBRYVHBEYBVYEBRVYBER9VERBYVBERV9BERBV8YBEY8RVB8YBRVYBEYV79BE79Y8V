from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, Security
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import json

from ..database import get_db
from ..schemas.user import CrosshairCreate, CrosshairRead, CrosshairUpdate, MessageResponse
from ..repositories import crosshair_repository
from ..security.auth import get_current_user

router = APIRouter(
    prefix="/crosshairs",
    tags=["crosshairs"],
    responses={401: {"description": "Não autorizado"}},
)

@router.post("/", response_model=CrosshairRead)
async def create_crosshair(
    crosshair_data: CrosshairCreate,
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Cria uma nova mira para o usuário atual.
    """
    try:
        crosshair = crosshair_repository.create_crosshair(
            db=db,
            owner_id=current_user.user_id,
            name=crosshair_data.name,
            data=crosshair_data.data,
            is_public=crosshair_data.is_public
        )
        
        # Converte o JSON armazenado para dicionário
        crosshair_dict = {
            "id": crosshair.id,
            "name": crosshair.name,
            "data": json.loads(crosshair.data),
            "is_public": crosshair.is_public,
            "created_at": crosshair.created_at,
            "updated_at": crosshair.updated_at,
            "owner_id": crosshair.owner_id
        }
        
        return crosshair_dict
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não foi possível criar a mira: {str(e)}"
        )

@router.get("/", response_model=List[CrosshairRead])
async def get_user_crosshairs(
    skip: int = 0,
    limit: int = 100,
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Obtém todas as miras do usuário atual.
    """
    crosshairs = crosshair_repository.get_user_crosshairs(
        db=db,
        user_id=current_user.user_id,
        skip=skip,
        limit=limit
    )
    
    # Converte os objetos para o formato esperado
    result = []
    for crosshair in crosshairs:
        result.append({
            "id": crosshair.id,
            "name": crosshair.name,
            "data": json.loads(crosshair.data),
            "is_public": crosshair.is_public,
            "created_at": crosshair.created_at,
            "updated_at": crosshair.updated_at,
            "owner_id": crosshair.owner_id
        })
    
    return result

@router.get("/public", response_model=List[CrosshairRead])
async def get_public_crosshairs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Obtém miras públicas.
    """
    crosshairs = crosshair_repository.get_public_crosshairs(
        db=db,
        skip=skip,
        limit=limit
    )
    
    # Converte os objetos para o formato esperado
    result = []
    for crosshair in crosshairs:
        result.append({
            "id": crosshair.id,
            "name": crosshair.name,
            "data": json.loads(crosshair.data),
            "is_public": crosshair.is_public,
            "created_at": crosshair.created_at,
            "updated_at": crosshair.updated_at,
            "owner_id": crosshair.owner_id
        })
    
    return result

@router.get("/search", response_model=List[CrosshairRead])
async def search_crosshairs(
    query: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Busca miras públicas pelo nome.
    """
    crosshairs = crosshair_repository.search_crosshairs(
        db=db,
        query=query,
        skip=skip,
        limit=limit
    )
    
    # Converte os objetos para o formato esperado
    result = []
    for crosshair in crosshairs:
        result.append({
            "id": crosshair.id,
            "name": crosshair.name,
            "data": json.loads(crosshair.data),
            "is_public": crosshair.is_public,
            "created_at": crosshair.created_at,
            "updated_at": crosshair.updated_at,
            "owner_id": crosshair.owner_id
        })
    
    return result

@router.get("/{crosshair_id}", response_model=Dict[str, Any])
async def get_crosshair(
    crosshair_id: str = Path(..., title="ID da mira a ser obtida"),
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Obtém uma mira específica pelo ID.
    """
    # Busca a mira
    crosshair_with_owner = crosshair_repository.get_crosshair_with_owner(db, crosshair_id)
    
    if not crosshair_with_owner:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mira não encontrada"
        )
    
    # Verifica se a mira é pública ou pertence ao usuário atual
    if not crosshair_with_owner["is_public"] and crosshair_with_owner["owner_id"] != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para acessar esta mira"
        )
    
    return crosshair_with_owner

@router.put("/{crosshair_id}", response_model=CrosshairRead)
async def update_crosshair(
    crosshair_data: CrosshairUpdate,
    crosshair_id: str = Path(..., title="ID da mira a ser atualizada"),
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Atualiza uma mira específica pelo ID.
    """
    # Busca a mira
    crosshair = crosshair_repository.get_crosshair_by_id(db, crosshair_id)
    
    if not crosshair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mira não encontrada"
        )
    
    # Verifica se a mira pertence ao usuário atual
    if crosshair.owner_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para atualizar esta mira"
        )
    
    # Atualiza a mira
    crosshair_dict = {}
    if crosshair_data.name is not None:
        crosshair_dict["name"] = crosshair_data.name
    if crosshair_data.data is not None:
        crosshair_dict["data"] = crosshair_data.data
    if crosshair_data.is_public is not None:
        crosshair_dict["is_public"] = crosshair_data.is_public
    
    updated_crosshair = crosshair_repository.update_crosshair(
        db=db,
        crosshair_id=crosshair_id,
        crosshair_data=crosshair_dict
    )
    
    # Converte o JSON armazenado para dicionário
    result = {
        "id": updated_crosshair.id,
        "name": updated_crosshair.name,
        "data": json.loads(updated_crosshair.data),
        "is_public": updated_crosshair.is_public,
        "created_at": updated_crosshair.created_at,
        "updated_at": updated_crosshair.updated_at,
        "owner_id": updated_crosshair.owner_id
    }
    
    return result

@router.delete("/{crosshair_id}", response_model=MessageResponse)
async def delete_crosshair(
    crosshair_id: str = Path(..., title="ID da mira a ser excluída"),
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Exclui uma mira específica pelo ID.
    """
    # Busca a mira
    crosshair = crosshair_repository.get_crosshair_by_id(db, crosshair_id)
    
    if not crosshair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mira não encontrada"
        )
    
    # Verifica se a mira pertence ao usuário atual
    if crosshair.owner_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para excluir esta mira"
        )
    
    # Exclui a mira
    crosshair_repository.delete_crosshair(db, crosshair_id)
    
    return {
        "message": "Mira excluída com sucesso"
    } 
