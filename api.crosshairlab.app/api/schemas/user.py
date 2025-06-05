from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re
from uuid import UUID

# Esquemas para usuário
class UserBase(BaseModel):
    """Esquema base para dados de usuário."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)

    @validator('username')
    def username_valid(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('O nome de usuário deve conter apenas letras, números, underlines e hífens')
        if len(v) < 3:
            raise ValueError('O nome de usuário deve ter pelo menos 3 caracteres')
        return v

class UserCreate(UserBase):
    """Esquema para criação de usuário."""
    password: str = Field(..., min_length=8)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Nome de usuário deve conter apenas letras e números')
        return v

    @validator('password')
    def password_strong(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('A senha deve conter pelo menos uma letra maiúscula')
        if not re.search(r'[a-z]', v):
            raise ValueError('A senha deve conter pelo menos uma letra minúscula')
        if not re.search(r'[0-9]', v):
            raise ValueError('A senha deve conter pelo menos um número')
        return v

class UserLogin(BaseModel):
    """Esquema para login de usuário."""
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    """Esquema para atualização de usuário."""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_pro: Optional[bool] = None
    is_2fa_enabled: Optional[bool] = None
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if v is not None and not v.isalnum():
            raise ValueError('Nome de usuário deve conter apenas letras e números')
        return v

class UserPasswordUpdate(BaseModel):
    """Esquema para atualização de senha."""
    current_password: str
    new_password: str = Field(..., min_length=8)

class UserRead(UserBase):
    id: str
    is_active: bool
    is_verified: bool
    is_pro: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class UserProfileBase(BaseModel):
    """Esquema base para perfil de usuário."""
    full_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None

class UserProfileCreate(UserProfileBase):
    """Esquema para criação de perfil de usuário."""
    user_id: UUID

class UserProfileUpdate(UserProfileBase):
    """Esquema para atualização de perfil de usuário."""
    pass

class UserProfileRead(UserProfileBase):
    id: str
    user_id: str
    
    class Config:
        orm_mode = True

# Esquemas para miras
class CrosshairBase(BaseModel):
    name: str
    data: Dict[str, Any]
    is_public: bool = False

class CrosshairCreate(CrosshairBase):
    pass

class CrosshairUpdate(BaseModel):
    name: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    is_public: Optional[bool] = None

class CrosshairRead(CrosshairBase):
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    owner_id: str
    
    class Config:
        orm_mode = True

# Esquemas para tokens
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    user_id: Optional[str] = None
    scopes: List[str] = []

# Esquema para 2FA
class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str

class TwoFactorVerify(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)

# Esquema para resposta padrão da API
class MessageResponse(BaseModel):
    message: str
    details: Optional[Dict[str, Any]] = None

class TwoFactorLogin(BaseModel):
    """Esquema para login com 2FA."""
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)

class UserResponse(UserBase):
    """Esquema para resposta com dados de usuário."""
    id: UUID
    is_active: bool
    is_verified: bool
    is_pro: bool
    is_2fa_enabled: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class UserProfileResponse(UserProfileBase):
    """Esquema para resposta com dados de perfil de usuário."""
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class TokenResponse(BaseModel):
    """Esquema para resposta de token de acesso."""
    access_token: str
    token_type: str = "bearer"
    
class TwoFactorSetupResponse(BaseModel):
    """Esquema para resposta de configuração de 2FA."""
    secret: str
    qrcode: str 
