from fastapi import APIRouter, Depends, HTTPException, status, Body, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import Dict, Any, Optional
from datetime import timedelta
import json

from ..schemas.user import UserCreate, UserLogin, UserRead, Token, TwoFactorSetup, TwoFactorVerify, MessageResponse
from ..repositories import user_repository_supabase as user_repo
from ..security import auth_supabase as auth_service
from ..security.auth import generate_2fa_secret, generate_2fa_qrcode, verify_2fa_code

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
    responses={401: {"description": "Não autorizado"}},
)

@router.post("/register", response_model=UserRead)
async def register(user_data: UserCreate):
    """
    Registra um novo usuário.
    """
    # Verifica se já existe um usuário com o mesmo email
    existing_user = await user_repo.get_user_by_email(user_data.email)
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já cadastrado"
        )
    
    # Verifica se já existe um usuário com o mesmo username
    existing_user = await user_repo.get_user_by_username(user_data.username)
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome de usuário já cadastrado"
        )
    
    # Cria o usuário
    try:
        user = await user_repo.create_user(
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
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Obtém um token de acesso usando email/username e senha.
    """
    # Tenta autenticar com o email fornecido
    try:
        auth_result = await auth_service.authenticate_user(form_data.username, form_data.password)
        
        # Busca o usuário para verificar 2FA
        user = await user_repo.get_user_by_id(auth_result["user_id"])
        
        # Verifica se o 2FA está habilitado
        if user and user.get("is_2fa_enabled", False):
            # Em vez de retornar o token, retorna uma indicação de que o 2FA é necessário
            return {
                "access_token": "",
                "token_type": "bearer",
                "requires_2fa": True,
                "user_id": user["id"]
            }
        
        # Retorna os tokens de acesso e refresh
        return {
            "access_token": auth_result["access_token"],
            "token_type": "bearer",
            "refresh_token": auth_result["refresh_token"]
        }
    except HTTPException:
        # Se falhar com o email, tenta obter o usuário pelo username
        try:
            user = await user_repo.get_user_by_username(form_data.username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Credenciais inválidas",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Tenta autenticar com o email do usuário encontrado
            auth_result = await auth_service.authenticate_user(user["email"], form_data.password)
            
            # Verifica se o 2FA está habilitado
            if user.get("is_2fa_enabled", False):
                # Em vez de retornar o token, retorna uma indicação de que o 2FA é necessário
                return {
                    "access_token": "",
                    "token_type": "bearer",
                    "requires_2fa": True,
                    "user_id": user["id"]
                }
            
            # Retorna os tokens de acesso e refresh
            return {
                "access_token": auth_result["access_token"],
                "token_type": "bearer",
                "refresh_token": auth_result["refresh_token"]
            }
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas",
                headers={"WWW-Authenticate": "Bearer"},
            )

@router.post("/verify-2fa", response_model=Token)
async def verify_2fa_and_login(
    verification_data: TwoFactorVerify,
    user_id: str = Query(...)
):
    """
    Verifica o código 2FA e retorna o token de acesso se correto.
    """
    # Busca o usuário
    user = await user_repo.get_user_by_id(user_id)
    if not user or not user.get("is_2fa_enabled") or not user.get("twofa_secret"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário não encontrado ou 2FA não habilitado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user["twofa_secret"], verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Realiza login após verificação do 2FA
    try:
        # Aqui precisamos obter novamente o token do Supabase
        # Isso normalmente exigiria senha, mas como já verificamos o 2FA, 
        # podemos usar uma abordagem diferente, como um token especial para isso
        
        # Este é um exemplo simplificado - em produção, seria necessário implementar
        # uma solução mais segura para gerar tokens após 2FA
        supabase = auth_service.get_supabase()
        admin_auth = supabase.auth.admin
        
        # Cria uma sessão para o usuário verificado
        session = admin_auth.create_session({
            "user_id": user_id,
            "properties": {
                "scopes": ["user"],
                "verified_2fa": True
            }
        })
        
        return {
            "access_token": session.access_token,
            "token_type": "bearer",
            "refresh_token": session.refresh_token
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao gerar token após 2FA: {str(e)}"
        )

@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    refresh_token: str = Body(..., embed=True)
):
    """
    Atualiza o token de acesso usando um token de atualização válido.
    """
    try:
        result = await auth_service.refresh_token_supabase(refresh_token)
        
        return {
            "access_token": result["access_token"],
            "token_type": "bearer",
            "refresh_token": result["refresh_token"]
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Não foi possível atualizar o token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/setup-2fa", response_model=TwoFactorSetup)
async def setup_2fa(
    user_id: str = Body(..., embed=True)
):
    """
    Configura a autenticação de dois fatores para um usuário.
    """
    # Busca o usuário
    user = await user_repo.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Gera um segredo 2FA
    secret = generate_2fa_secret()
    
    # Gera o QR code
    qr_code = generate_2fa_qrcode(user["username"], secret)
    
    # Armazena o segredo no banco de dados (ainda não habilitado)
    await user_repo.update_user_2fa_status(user["id"], False, secret)
    
    return {
        "secret": secret,
        "qr_code": qr_code
    }

@router.post("/enable-2fa", response_model=MessageResponse)
async def enable_2fa(
    verification_data: TwoFactorVerify,
    user_id: str = Body(..., embed=True)
):
    """
    Habilita a autenticação de dois fatores para um usuário após a verificação do código.
    """
    # Busca o usuário
    user = await user_repo.get_user_by_id(user_id)
    if not user or not user.get("twofa_secret"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado ou 2FA não configurado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user["twofa_secret"], verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Habilita o 2FA
    await user_repo.update_user_2fa_status(user["id"], True)
    
    return {
        "message": "Autenticação de dois fatores habilitada com sucesso"
    }

@router.post("/disable-2fa", response_model=MessageResponse)
async def disable_2fa(
    verification_data: TwoFactorVerify,
    user_id: str = Body(..., embed=True)
):
    """
    Desabilita a autenticação de dois fatores para um usuário.
    """
    # Busca o usuário
    user = await user_repo.get_user_by_id(user_id)
    if not user or not user.get("is_2fa_enabled") or not user.get("twofa_secret"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado ou 2FA não habilitado"
        )
    
    # Verifica o código 2FA
    if not verify_2fa_code(user["twofa_secret"], verification_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Desabilita o 2FA
    await user_repo.update_user_2fa_status(user["id"], False, None)
    
    return {
        "message": "Autenticação de dois fatores desabilitada com sucesso"
    }

@router.post("/logout", response_model=MessageResponse)
async def logout():
    """
    Encerra a sessão do usuário.
    """
    try:
        await auth_service.sign_out_supabase()
        return {
            "message": "Sessão encerrada com sucesso"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao encerrar sessão: {str(e)}"
        ) 
