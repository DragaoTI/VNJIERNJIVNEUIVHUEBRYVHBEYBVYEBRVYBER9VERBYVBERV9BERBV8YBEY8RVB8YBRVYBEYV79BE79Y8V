from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os

from ..supabase_client import get_supabase

# Configuração de segurança
security = HTTPBearer()
JWT_SECRET = os.environ.get("JWT_SECRET", "seu_segredo_super_secreto_aqui")  # Deve ser configurado no ambiente
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 semana

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token JWT para autenticação.
    
    Args:
        data: Dados a serem codificados no token
        expires_delta: Tempo de expiração opcional
        
    Returns:
        str: Token JWT assinado
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return encoded_jwt

def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodifica um token JWT.
    
    Args:
        token: Token JWT a ser decodificado
        
    Returns:
        Dict[str, Any]: Dados decodificados do token
        
    Raises:
        HTTPException: Se o token for inválido ou expirado
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Obtém o usuário autenticado a partir do token JWT.
    
    Args:
        credentials: Credenciais HTTP do tipo Bearer
        
    Returns:
        Dict[str, Any]: Dados do usuário autenticado
        
    Raises:
        HTTPException: Se o token for inválido ou expirado
    """
    token = credentials.credentials
    
    # Verificar no Supabase se o token é válido
    try:
        supabase = get_supabase()
        
        # Verificar o token usando a API do Supabase
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido ou expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Extrair dados do usuário
        user_data = {
            "user_id": user.id,
            "email": user.email,
            "username": user.email.split('@')[0] if user.email else None,  # Uso básico do e-mail como username
            "is_admin": user.email in await get_admin_emails()  # Verificar se é admin
        }
        
        return user_data
        
    except Exception as e:
        # Fallback para decodificação local do token se a verificação Supabase falhar
        try:
            payload = decode_token(token)
            
            # Verificar se o token tem os campos necessários
            if "sub" not in payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token inválido",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            # Construir dados do usuário a partir do payload
            user_data = {
                "user_id": payload.get("sub"),
                "email": payload.get("email"),
                "username": payload.get("username") or payload.get("email", "").split('@')[0],
                "is_admin": payload.get("email") in await get_admin_emails()  # Verificar se é admin
            }
            
            return user_data
            
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas",
                headers={"WWW-Authenticate": "Bearer"},
            )

async def get_admin_emails() -> list:
    """
    Obtém a lista de e-mails de administradores do banco de dados.
    
    Returns:
        list: Lista de e-mails de administradores
    """
    try:
        supabase = get_supabase()
        response = supabase.table('admin_emails').select('email').execute()
        
        if response.data:
            return [item['email'] for item in response.data]
        return []
    except Exception as e:
        print(f"Erro ao obter e-mails de administradores: {e}")
        return []

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se uma senha em texto plano corresponde à senha hash.
    
    Args:
        plain_password: Senha em texto plano
        hashed_password: Senha hash armazenada
        
    Returns:
        bool: True se a senha corresponder, False caso contrário
    """
    # No Supabase, a verificação de senha é feita pelo serviço de autenticação
    # Esta função é um placeholder para compatibilidade
    return True

async def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Autentica um usuário com e-mail e senha.
    
    Args:
        email: E-mail do usuário
        password: Senha do usuário
        
    Returns:
        Optional[Dict[str, Any]]: Dados do usuário se autenticado, None caso contrário
    """
    try:
        supabase = get_supabase()
        
        # Tentar fazer login com Supabase
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        user = auth_response.user
        session = auth_response.session
        
        if user and session:
            # Construir dados do usuário
            user_data = {
                "user_id": user.id,
                "email": user.email,
                "username": user.email.split('@')[0] if user.email else None,
                "is_admin": user.email in await get_admin_emails(),
                "access_token": session.access_token,
                "refresh_token": session.refresh_token
            }
            
            return user_data
        
        return None
    except Exception as e:
        print(f"Erro na autenticação: {e}")
        return None 
