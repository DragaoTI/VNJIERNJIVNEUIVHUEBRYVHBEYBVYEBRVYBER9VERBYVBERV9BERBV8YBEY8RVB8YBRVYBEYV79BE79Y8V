from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID

class CrosshairBase(BaseModel):
    """Esquema base para dados de mira."""
    name: str = Field(..., min_length=1, max_length=100)
    data: Dict[str, Any]
    is_public: bool = False

class CrosshairCreate(CrosshairBase):
    """Esquema para criação de mira."""
    pass

class CrosshairUpdate(BaseModel):
    """Esquema para atualização de mira."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    data: Optional[Dict[str, Any]] = None
    is_public: Optional[bool] = None

class CrosshairResponse(CrosshairBase):
    """Esquema para resposta com dados de mira."""
    id: UUID
    owner_id: Optional[UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class CrosshairResponseWithOwner(CrosshairResponse):
    """Esquema para resposta com dados de mira incluindo informações do proprietário."""
    owner_username: Optional[str] = None
    
    class Config:
        orm_mode = True 
