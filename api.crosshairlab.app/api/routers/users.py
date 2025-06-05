from fastapi import APIRouter, Depends, HTTPException, status, Path, Body, Security
from sqlalchemy.orm import Session
from typing import Dict, Any

from ..database import get_db
from ..schemas.user import UserRead, UserUpdate, UserProfileRead, UserProfileUpdate, MessageResponse
from ..repositories import user_repository
from ..security.auth import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={401: {"description": "Não autorizado"}},
)

@router.get("/me", response_model=UserRead)
async def get_current_user_info(
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Obtém as informações do usuário atual.
    """
    user = user_repository.get_user_by_id(db, current_user.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    return user

@router.put("/me", response_model=UserRead)
async def update_current_user(
    user_data: UserUpdate,
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Atualiza as informações do usuário atual.
    """
    user = user_repository.update_user(
        db=db,
        user_id=current_user.user_id,
        user_data=user_data.dict(exclude_unset=True)
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    return user

@router.delete("/me", response_model=MessageResponse)
async def delete_current_user(
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Exclui o usuário atual.
    """
    success = user_repository.delete_user(db, current_user.user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    return {
        "message": "Usuário excluído com sucesso"
    }

@router.put("/me/password", response_model=MessageResponse)
async def update_current_user_password(
    old_password: str = Body(..., embed=True),
    new_password: str = Body(..., embed=True),
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Atualiza a senha do usuário atual.
    """
    from ..security.auth import verify_password
    
    # Busca o usuário
    user = user_repository.get_user_by_id(db, current_user.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Verifica se a senha atual está correta
    if not verify_password(old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Senha atual incorreta"
        )
    
    # Atualiza a senha
    success = user_repository.update_user_password(db, current_user.user_id, new_password)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível atualizar a senha"
        )
    
    return {
        "message": "Senha atualizada com sucesso"
    }

@router.get("/me/profile", response_model=UserProfileRead)
async def get_current_user_profile(
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Obtém o perfil do usuário atual.
    """
    profile = user_repository.get_user_profile(db, current_user.user_id)
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil não encontrado"
        )
    
    return profile

@router.put("/me/profile", response_model=UserProfileRead)
async def update_current_user_profile(
    profile_data: UserProfileUpdate,
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Atualiza o perfil do usuário atual.
    """
    profile = user_repository.update_user_profile(
        db=db,
        user_id=current_user.user_id,
        profile_data=profile_data.dict(exclude_unset=True)
    )
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil não encontrado"
        )
    
    return profile

@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: str = Path(..., title="ID do usuário a ser obtido"),
    current_user = Security(get_current_user, scopes=["user"]),
    db: Session = Depends(get_db)
):
    """
    Obtém informações de um usuário específico pelo ID.
    """
    user = user_repository.get_user_by_id(db, user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    return user 
