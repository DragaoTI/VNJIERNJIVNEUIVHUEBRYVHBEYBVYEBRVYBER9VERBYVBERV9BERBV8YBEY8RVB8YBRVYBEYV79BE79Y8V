# app/auth/admin_jwt_handler.py
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Dict, Union
from jose import jwt, JWTError, jws
from jose.constants import ALGORITHMS
import secrets
import hashlib
import time
from fastapi import HTTPException, status

from app.core.config import settings
from app.schemas.admin_schemas import AdminTokenData

# Configurações de segurança
ADMIN_JWT_ALGORITHM = settings.JWT_ALGORITHM
ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, "ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 8)  # 8 horas por padrão
ADMIN_JWT_TOKEN_TYPE = "admin_access"

# Cache de tokens revogados (memory-based)
REVOKED_TOKENS = {}
REVOKED_TOKENS_TTL = 24 * 60 * 60  # 24 horas em segundos

def create_admin_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token JWT para administradores com segurança aprimorada
    """
    to_encode = data.copy()
    
    # Adiciona timestamp de emissão
    now = datetime.now(timezone.utc)
    
    # Define expiração
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Adiciona JTI (JWT ID) para possibilitar revogação de tokens específicos
    jti = secrets.token_hex(16)
    
    # Adiciona dados ao payload
    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,  # Not Before
        "jti": jti,  # JWT ID único
        "type": ADMIN_JWT_TOKEN_TYPE,  # Tipo específico para token de admin
        "iss": "crosshairlab-api",  # Emissor
        "aud": "admin-panel"  # Público
    })
    
    # Usa RS256 para assinatura (mais seguro que HS256)
    if ADMIN_JWT_ALGORITHM == "RS256":
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_PRIVATE_KEY_CONTENT, 
            algorithm=ADMIN_JWT_ALGORITHM
        )
    else:
        # Fallback para outros algoritmos
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_PRIVATE_KEY_CONTENT, 
            algorithm=ADMIN_JWT_ALGORITHM
        )
    
    # Hash do token para verificação de integridade
    token_hash = hashlib.sha256(encoded_jwt.encode()).hexdigest()
    
    return encoded_jwt

def verify_admin_token(token: str, credentials_exception: Union[HTTPException, Exception]) -> Optional[AdminTokenData]:
    """
    Verifica um token JWT de administrador com segurança aprimorada
    """
    try:
        # Verifica integridade do JWT
        try:
            jws.verify(
                token,
                settings.JWT_PUBLIC_KEY_CONTENT,
                algorithms=[ADMIN_JWT_ALGORITHM]
            )
        except:
            raise credentials_exception
        
        # Decodifica o token
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY_CONTENT,
            algorithms=[ADMIN_JWT_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iat": True,
                "verify_exp": True,
                "verify_nbf": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": True
            },
            audience="admin-panel",
            issuer="crosshairlab-api"
        )
        
        # Extrai dados do payload
        admin_id_str: Optional[str] = payload.get("sub")  # admin_id como 'subject'
        token_type: Optional[str] = payload.get("type")
        jti: Optional[str] = payload.get("jti")
        
        # Verifica se token foi revogado
        if jti in REVOKED_TOKENS:
            raise credentials_exception
        
        # Verifica tipo do token
        if not admin_id_str or token_type != ADMIN_JWT_TOKEN_TYPE:
            raise credentials_exception
        
        # Cria objeto TokenData com informações do token
        token_data = AdminTokenData(admin_id=admin_id_str)
        
        # Adiciona IP armazenado no token (se existir)
        if "ip" in payload:
            token_data.ip = payload.get("ip")
        
        # Adiciona outras informações relevantes do token
        if "role" in payload:
            token_data.role = payload.get("role")
        
        return token_data
    except JWTError as e:
        print(f"JWT Error: {str(e)}")
        raise credentials_exception
    except Exception as e:
        print(f"Unexpected error verifying token: {str(e)}")
        raise credentials_exception

def revoke_admin_token(token: str) -> bool:
    """
    Revoga um token JWT de administrador
    """
    try:
        # Decodifica sem verificar expiração
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY_CONTENT,
            algorithms=[ADMIN_JWT_ALGORITHM],
            options={"verify_exp": False}
        )
        
        jti = payload.get("jti")
        if not jti:
            return False
        
        # Adiciona ao cache de tokens revogados
        REVOKED_TOKENS[jti] = time.time() + REVOKED_TOKENS_TTL
        
        # Limpa tokens expirados do cache
        _cleanup_revoked_tokens()
        
        return True
    except:
        return False

def _cleanup_revoked_tokens() -> None:
    """
    Remove tokens revogados expirados do cache
    """
    now = time.time()
    expired_jtis = [jti for jti, exp_time in REVOKED_TOKENS.items() if now > exp_time]
    for jti in expired_jtis:
        REVOKED_TOKENS.pop(jti, None)
