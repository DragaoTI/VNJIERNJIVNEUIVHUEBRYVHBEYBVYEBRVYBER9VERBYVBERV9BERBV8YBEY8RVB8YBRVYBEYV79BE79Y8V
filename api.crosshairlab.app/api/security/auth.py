from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from pydantic import ValidationError, BaseModel
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union
import os
import pyotp
import qrcode
import base64
from io import BytesIO
import uuid

from ..schemas.user import TokenData

# Importar funções do auth_supabase
from .auth_supabase import (
    get_current_user as supabase_get_current_user,
    create_access_token as supabase_create_access_token,
    decode_token as supabase_decode_token,
    authenticate_user as supabase_authenticate_user,
    verify_password as supabase_verify_password
)

# Configuração do OAuth2
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/token",
    scopes={
        "user": "Acesso básico de usuário",
        "admin": "Acesso administrativo",
    },
)

# Configuração do contexto de hashing de senha
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# Configurações JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "DEFAULT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Funções auxiliares de autenticação
def get_password_hash(password):
    """Cria um hash seguro da senha."""
    return pwd_context.hash(password)

def create_refresh_token(data: dict):
    """
    Cria um token JWT de atualização com os dados fornecidos.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Funções para 2FA
def generate_2fa_secret():
    """Gera um segredo para autenticação de dois fatores."""
    return pyotp.random_base32()

def generate_2fa_qrcode(username: str, secret: str):
    """Gera um QR code para configuração de 2FA."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="CrosshairLab")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_2fa_code(secret: str, code: str):
    """Verifica se o código 2FA fornecido é válido."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# Exportar funções do auth_supabase
get_current_user = supabase_get_current_user
create_access_token = supabase_create_access_token
decode_token = supabase_decode_token
authenticate_user = supabase_authenticate_user
verify_password = supabase_verify_password

# Exportar todas as funções importantes
__all__ = [
    "get_current_user",
    "create_access_token",
    "decode_token",
    "authenticate_user",
    "verify_password",
    "create_refresh_token",
    "get_password_hash",
    "generate_2fa_secret",
    "generate_2fa_qrcode",
    "verify_2fa_code"
]
