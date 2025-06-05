from fastapi import APIRouter, Depends, HTTPException, Request, Header, Cookie, Security
from ...security.auth import get_current_user
from .promo_codes import router as promo_codes_router
import os
import secrets
from typing import Optional
import time
import hashlib
from uuid import UUID

# Utiliza um prefixo complexo e difícil de adivinhar para a área administrativa
# Obtém do ambiente ou gera um valor padrão seguro para desenvolvimento
ADMIN_SECRET_PATH = os.environ.get("ADMIN_SECRET_PATH", "secure_admin_panel_8a7b6c5d4e3f")

# Cria o router para a área administrativa com o prefixo secreto
router = APIRouter(
    prefix=f"/{ADMIN_SECRET_PATH}",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

# Lista de tokens de acesso administrativo (em produção, deve usar um banco de dados)
ADMIN_ACCESS_TOKENS = {}

# Tempo de expiração do token em segundos (4 horas)
TOKEN_EXPIRATION = 14400

# Função para gerar um token de acesso administrativo
def generate_admin_token(admin_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expiration = time.time() + TOKEN_EXPIRATION
    ADMIN_ACCESS_TOKENS[token] = {"admin_id": admin_id, "expiration": expiration}
    return token

# Helper para verificar se o usuário é administrador
async def verify_admin_access(
    current_user: dict = Depends(get_current_user),
    x_admin_token: Optional[str] = Header(None),
    admin_token: Optional[str] = Cookie(None)
):
    # Verifica se o usuário é administrador
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Acesso negado. Permissões de administrador necessárias.")
    
    # Verifica o token administrativo (pode estar no header ou cookie)
    token = x_admin_token or admin_token
    
    if not token or token not in ADMIN_ACCESS_TOKENS:
        raise HTTPException(status_code=401, detail="Token administrativo inválido ou expirado")
    
    # Verifica a expiração do token
    token_data = ADMIN_ACCESS_TOKENS[token]
    if time.time() > token_data["expiration"]:
        # Remove o token expirado
        ADMIN_ACCESS_TOKENS.pop(token, None)
        raise HTTPException(status_code=401, detail="Token administrativo expirado")
    
    # Verifica se o ID do usuário corresponde ao token
    if token_data["admin_id"] != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Token administrativo não corresponde ao usuário atual")
    
    # Adiciona informações do token ao usuário
    current_user["admin_token"] = token
    
    return current_user

@router.get("/")
async def admin_home(admin: dict = Depends(verify_admin_access)):
    """
    Ponto de entrada da API administrativa.
    """
    return {
        "message": "Bem-vindo à API de administração do CrosshairLab",
        "admin_id": admin.get("user_id"),
        "admin_username": admin.get("username")
    }

@router.post("/auth")
async def admin_auth(current_user: dict = Depends(get_current_user)):
    """
    Autentica um usuário como administrador e retorna um token de acesso.
    """
    # Verifica se o usuário é administrador
    if not current_user.get("is_admin", False):
        # Usa um atraso para dificultar ataques de força bruta
        time.sleep(2)
        raise HTTPException(status_code=403, detail="Acesso negado. Permissões de administrador necessárias.")
    
    # Gera um token de acesso administrativo
    token = generate_admin_token(current_user.get("user_id"))
    
    return {
        "message": "Autenticação administrativa bem-sucedida",
        "admin_token": token,
        "expires_in": TOKEN_EXPIRATION
    }

# Inclui o router de códigos promocionais
router.include_router(promo_codes_router) 
