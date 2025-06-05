from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator
from datetime import datetime
from uuid import UUID

class PromoCodeBase(BaseModel):
    """Esquema base para dados de código promocional."""
    code: str = Field(..., min_length=3, max_length=50)
    reward_type: str = Field(..., min_length=1, max_length=100)
    max_uses: int = Field(..., ge=1)
    is_active: bool = True
    expires_at: Optional[datetime] = None
    notes: Optional[str] = Field(None, max_length=500)
    
    @validator('code')
    def code_must_be_valid(cls, v):
        """Valida que o código seja composto de caracteres válidos."""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Código deve conter apenas letras, números, hífens e underscores')
        return v.upper()  # Converte o código para maiúsculas

class PromoCodeCreate(PromoCodeBase):
    """Esquema para criação de código promocional."""
    pass

class PromoCodeUpdate(BaseModel):
    """Esquema para atualização de código promocional."""
    code: Optional[str] = Field(None, min_length=3, max_length=50)
    reward_type: Optional[str] = Field(None, min_length=1, max_length=100)
    max_uses: Optional[int] = Field(None, ge=1)
    is_active: Optional[bool] = None
    expires_at: Optional[datetime] = None
    notes: Optional[str] = Field(None, max_length=500)
    
    @validator('code')
    def code_must_be_valid(cls, v):
        """Valida que o código seja composto de caracteres válidos."""
        if v is not None:
            if not v.replace('-', '').replace('_', '').isalnum():
                raise ValueError('Código deve conter apenas letras, números, hífens e underscores')
            return v.upper()  # Converte o código para maiúsculas
        return v

class PromoCodeResponse(PromoCodeBase):
    """Esquema para resposta com dados de código promocional."""
    id: UUID
    remaining_uses: int
    created_by: Optional[UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class PromoCodeDetailResponse(PromoCodeResponse):
    """Esquema para resposta detalhada com dados de código promocional."""
    created_by_username: Optional[str] = None
    
    class Config:
        orm_mode = True

class PromoCodeUseBase(BaseModel):
    """Esquema base para dados de uso de código promocional."""
    promo_code_id: UUID
    user_id: UUID

class PromoCodeUseCreate(PromoCodeUseBase):
    """Esquema para criação de uso de código promocional."""
    pass

class PromoCodeUseResponse(PromoCodeUseBase):
    """Esquema para resposta com dados de uso de código promocional."""
    id: UUID
    used_at: datetime
    
    class Config:
        orm_mode = True

class PromoCodeUseDetailResponse(PromoCodeUseResponse):
    """Esquema para resposta detalhada com dados de uso de código promocional."""
    promo_code: str
    username: str
    
    class Config:
        orm_mode = True

class AdminActionLog(BaseModel):
    """Esquema para log de ações administrativas."""
    id: UUID
    admin_id: UUID
    admin_username: str
    action_type: str
    entity_type: str
    entity_id: UUID
    details: Optional[Dict[str, Any]] = None
    created_at: datetime
    
    class Config:
        orm_mode = True 
