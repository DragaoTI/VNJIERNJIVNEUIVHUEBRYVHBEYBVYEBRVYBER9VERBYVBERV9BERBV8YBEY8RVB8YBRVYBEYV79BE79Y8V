from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from passlib.context import CryptContext
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
from ..database import get_db
from sqlalchemy.orm import Session
from .auth_supabase import (
    get_current_user,
    create_access_token,
    decode_token,
    authenticate_user,
    verify_password
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
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# Configurações JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "DEFAULT_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Funções auxiliares de autenticação
def verify_password(plain_password, hashed_password):
    """Verifica se a senha em texto plano corresponde ao hash armazenado."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Cria um hash seguro da senha."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Cria um token JWT de acesso com os dados fornecidos.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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

async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Obtém o usuário atual com base no token JWT.
    """
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
        
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": authenticate_value},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        token_type = payload.get("type")
        if token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de acesso inválido",
                headers={"WWW-Authenticate": authenticate_value},
            )
            
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(user_id=user_id, scopes=token_scopes)
    except (JWTError, ValidationError):
        raise credentials_exception
        
    # Aqui você buscaria o usuário no banco de dados
    # user = get_user_by_id(db, token_data.user_id)
    # if user is None:
    #     raise credentials_exception
    
    # Verificação de escopos
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão insuficiente: {scope} é necessário",
                headers={"WWW-Authenticate": authenticate_value},
            )
    
    # Retorna o usuário encontrado
    # return user
    
    # Temporariamente retornando apenas os dados do token para desenvolvimento
    return token_data

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

# OAuth2 scheme para autenticação via token
oauth2_scheme_token = OAuth2PasswordBearer(tokenUrl="token")

# Segredo para JWT
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("A variável de ambiente JWT_SECRET deve estar definida")

# Tempo de expiração do token (em minutos)
ACCESS_TOKEN_EXPIRE_MINUTES_token = 60 * 24  # 24 horas

class TokenData(BaseModel):
    """Modelo para dados do token JWT."""
    user_id: str
    email: Optional[str] = None
    username: Optional[str] = None
    exp: Optional[int] = None

def create_access_token_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token JWT de acesso.
    
    Args:
        data: Dados a serem codificados no token
        expires_delta: Tempo de expiração do token
        
    Returns:
        str: Token JWT codificado
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES_token)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    
    return encoded_jwt

def decode_token(token: str) -> TokenData:
    """
    Decodifica e valida um token JWT.
    
    Args:
        token: Token JWT a ser decodificado
        
    Returns:
        TokenData: Dados contidos no token
        
    Raises:
        HTTPException: Se o token for inválido ou expirado
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        token_data = TokenData(
            user_id=payload.get("user_id"),
            email=payload.get("email"),
            username=payload.get("username"),
            exp=payload.get("exp")
        )
        return token_data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user_token(token: str = Depends(oauth2_scheme_token)) -> Dict[str, Any]:
    """
    Obtém o usuário atual a partir do token.
    
    Args:
        token: Token JWT de acesso
        
    Returns:
        Dict[str, Any]: Dados do usuário
        
    Raises:
        HTTPException: Se o token for inválido ou o usuário não existir
    """
    token_data = decode_token(token)
    
    if not token_data.user_id:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    # Aqui você pode adicionar lógica para buscar mais informações do usuário no banco de dados
    
    return {
        "user_id": token_data.user_id,
        "email": token_data.email,
        "username": token_data.username
    }

def generate_2fa_secret_token() -> str:
    """
    Gera um segredo para autenticação de dois fatores (2FA).
    
    Returns:
        str: Segredo para 2FA
    """
    return pyotp.random_base32()

def generate_2fa_qrcode_token(secret: str, email: str) -> str:
    """
    Gera um QR code para configuração de 2FA.
    
    Args:
        secret: Segredo 2FA
        email: Email do usuário
        
    Returns:
        str: Imagem do QR code em formato base64
    """
    totp = pyotp.totp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="CrosshairLab")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_2fa_code_token(secret: str, code: str) -> bool:
    """
    Verifica um código 2FA.
    
    Args:
        secret: Segredo 2FA
        code: Código inserido pelo usuário
        
    Returns:
        bool: True se o código for válido, False caso contrário
    """
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code)

# Exportar funções de autenticação
__all__ = [
    "get_current_user",
    "create_access_token",
    "decode_token",
    "authenticate_user",
    "verify_password"
] 
