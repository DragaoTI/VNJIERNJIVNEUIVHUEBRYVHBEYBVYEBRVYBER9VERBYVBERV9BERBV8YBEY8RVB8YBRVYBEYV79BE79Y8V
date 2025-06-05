from fastapi import APIRouter, Depends, HTTPException, status, Body, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from datetime import timedelta
import json

from ..database import get_db
from ..schemas.user import UserCreate, UserLogin, UserRead, Token, TwoFactorSetup, TwoFactorVerify, MessageResponse
from ..repositories import user_repository
from ..security.auth import (
    verify_password, create_access_token, create_refresh_token,
    generate_2fa_secret, generate_2fa_qrcode, verify_2fa_code
)

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
    responses={401: {"description": "Não autorizado"}},
)

@router.post("/register", response_model=UserRead)
async def register(
    user_data: UserCreate, 
    db: Session = Depends(get_db)
):
    """
    Registra um novo usuário.
    """
    # Verifica se já existe um usuário com o mesmo email ou username
    existing_user = user_repository.get_user_by_email_or_username(
        db, email=user_data.email, username=user_data.username
    )
    
    if existing_user:
        if existing_user.email == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já cadastrado"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nome de usuário já cadastrado"
            )
    
    # Cria o usuário
    try:
        user = user_repository.create_user(
            db=db,
            email=user_data.email,
            username=user_data.username,
            password=user_data.password
        )
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Obtém um token de acesso usando email/username e senha.
    """
    # Busca o usuário pelo email
    user = user_repository.get_user_by_email(db, email=form_data.username)
    
    # Se não encontrou pelo email, tenta pelo username
    if not user:
        user = user_repository.get_user_by_username(db, username=form_data.username)
    
    # Se não encontrou de nenhuma forma ou a senha está incorreta, retorna erro
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica se o usuário está ativo
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo"
        )
    
    # Verifica se o 2FA está habilitado
    if user.is_2fa_enabled:
        # Em vez de retornar o token, retorna uma indicação de que o 2FA é necessário
        return {
            "access_token": "",
            "token_type": "bearer",
            "requires_2fa": True,
            "user_id": user.id
        }
    
    # Cria o token de acesso
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.id, "scopes": ["user"]},
        expires_delta=access_token_expires
    )
    
    # Cria o token de atualização
    refresh_token = create_refresh_token(
        data={"sub": user.id, "scopes": ["user"]}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }

@router.post("/verify-2fa", response_model=Token)
async def verify_2fa_and_login(
    verification_data: TwoFactorVerify,
    user_id: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    Verifica o código 2FA e retorna o token de acesso se correto.
    """
    # Busca o usuário
    user = user_repository.get_user_by_id(db, user_id)
    if not user or not user.is_2fa_enabled or not user.twofa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário não encontrado ou 2FA não habilitado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user.twofa_secret, verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Cria o token de acesso
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.id, "scopes": ["user"]},
        expires_delta=access_token_expires
    )
    
    # Cria o token de atualização
    refresh_token = create_refresh_token(
        data={"sub": user.id, "scopes": ["user"]}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }

@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    refresh_token: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """
    Atualiza o token de acesso usando um token de atualização válido.
    """
    try:
        from jose import jwt
        import os
        
        # Decodifica o token de atualização
        payload = jwt.decode(
            refresh_token, 
            os.getenv("JWT_SECRET_KEY", "DEFAULT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"), 
            algorithms=[os.getenv("JWT_ALGORITHM", "HS256")]
        )
        
        # Verifica se é um token de atualização
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token de atualização inválido"
            )
        
        # Obtém o ID do usuário
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token de atualização inválido"
            )
        
        # Busca o usuário
        user = user_repository.get_user_by_id(db, user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Usuário não encontrado ou inativo"
            )
        
        # Cria um novo token de acesso
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(
            data={"sub": user.id, "scopes": ["user"]},
            expires_delta=access_token_expires
        )
        
        # Cria um novo token de atualização
        new_refresh_token = create_refresh_token(
            data={"sub": user.id, "scopes": ["user"]}
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "refresh_token": new_refresh_token
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Não foi possível atualizar o token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/setup-2fa", response_model=TwoFactorSetup)
async def setup_2fa(
    user_id: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """
    Configura a autenticação de dois fatores para um usuário.
    """
    # Busca o usuário
    user = user_repository.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Gera um segredo 2FA
    secret = generate_2fa_secret()
    
    # Gera o QR code
    qr_code = generate_2fa_qrcode(user.username, secret)
    
    # Armazena o segredo no banco de dados (ainda não habilitado)
    user_repository.update_user_2fa_status(db, user.id, False, secret)
    
    return {
        "secret": secret,
        "qr_code": qr_code
    }

@router.post("/enable-2fa", response_model=MessageResponse)
async def enable_2fa(
    verification_data: TwoFactorVerify,
    user_id: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """
    Habilita a autenticação de dois fatores para um usuário após a verificação do código.
    """
    # Busca o usuário
    user = user_repository.get_user_by_id(db, user_id)
    if not user or not user.twofa_secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado ou 2FA não configurado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user.twofa_secret, verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Habilita o 2FA
    user_repository.update_user_2fa_status(db, user.id, True)
    
    return {
        "message": "Autenticação de dois fatores habilitada com sucesso"
    }

@router.post("/disable-2fa", response_model=MessageResponse)
async def disable_2fa(
    verification_data: TwoFactorVerify,
    user_id: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    """
    Desabilita a autenticação de dois fatores para um usuário.
    """
    # Busca o usuário
    user = user_repository.get_user_by_id(db, user_id)
    if not user or not user.is_2fa_enabled or not user.twofa_secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado ou 2FA não habilitado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user.twofa_secret, verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Desabilita o 2FA
    user_repository.update_user_2fa_status(db, user.id, False, None)
    
    return {
        "message": "Autenticação de dois fatores desabilitada com sucesso"
    } 
