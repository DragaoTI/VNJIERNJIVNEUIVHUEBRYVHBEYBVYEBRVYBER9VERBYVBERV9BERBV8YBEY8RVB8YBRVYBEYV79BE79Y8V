from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

from ..database import Base

class User(Base):
    """
    Modelo de usuário para autenticação e gerenciamento de contas
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Campo para 2FA
    is_2fa_enabled = Column(Boolean, default=False)
    twofa_secret = Column(String, nullable=True)
    
    # Campos para plano e assinatura
    is_pro = Column(Boolean, default=False)
    subscription_id = Column(String, nullable=True)
    subscription_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relações com outros modelos
    crosshairs = relationship("Crosshair", back_populates="owner", cascade="all, delete-orphan")
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")

class UserProfile(Base):
    """
    Modelo para armazenar informações adicionais do perfil do usuário
    """
    __tablename__ = "user_profiles"
    
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    full_name = Column(String, nullable=True)
    bio = Column(Text, nullable=True)
    avatar_url = Column(String, nullable=True)
    preferences = Column(Text, nullable=True)  # JSON armazenado como texto
    
    # Relações
    user = relationship("User", back_populates="profile")

class Crosshair(Base):
    """
    Modelo para armazenar miras personalizadas dos usuários
    """
    __tablename__ = "crosshairs"
    
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String)
    data = Column(Text)  # JSON com configuração da mira
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    owner_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"))
    
    # Relações
    owner = relationship("User", back_populates="crosshairs")

class User:
    """
    Modelo para representar um usuário no sistema.
    """
    def __init__(
        self,
        id: UUID,
        email: str,
        username: str,
        is_active: bool = True,
        is_verified: bool = False,
        is_pro: bool = False,
        is_2fa_enabled: bool = False,
        twofa_secret: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.email = email
        self.username = username
        self.is_active = is_active
        self.is_verified = is_verified
        self.is_pro = is_pro
        self.is_2fa_enabled = is_2fa_enabled
        self.twofa_secret = twofa_secret
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """
        Cria uma instância de User a partir de um dicionário.
        
        Args:
            data: Dicionário contendo os dados do usuário
            
        Returns:
            User: Nova instância de User
        """
        return cls(
            id=data.get('id'),
            email=data.get('email'),
            username=data.get('username'),
            is_active=data.get('is_active', True),
            is_verified=data.get('is_verified', False),
            is_pro=data.get('is_pro', False),
            is_2fa_enabled=data.get('is_2fa_enabled', False),
            twofa_secret=data.get('twofa_secret'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a instância para um dicionário.
        
        Returns:
            Dict[str, Any]: Dicionário representando o usuário
        """
        return {
            'id': str(self.id),
            'email': self.email,
            'username': self.username,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_pro': self.is_pro,
            'is_2fa_enabled': self.is_2fa_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class UserProfile:
    """
    Modelo para representar o perfil de um usuário no sistema.
    """
    def __init__(
        self,
        id: UUID,
        user_id: UUID,
        full_name: Optional[str] = None,
        bio: Optional[str] = None,
        avatar_url: Optional[str] = None,
        preferences: Optional[Dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.user_id = user_id
        self.full_name = full_name
        self.bio = bio
        self.avatar_url = avatar_url
        self.preferences = preferences or {}
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """
        Cria uma instância de UserProfile a partir de um dicionário.
        
        Args:
            data: Dicionário contendo os dados do perfil
            
        Returns:
            UserProfile: Nova instância de UserProfile
        """
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            full_name=data.get('full_name'),
            bio=data.get('bio'),
            avatar_url=data.get('avatar_url'),
            preferences=data.get('preferences', {}),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a instância para um dicionário.
        
        Returns:
            Dict[str, Any]: Dicionário representando o perfil do usuário
        """
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'full_name': self.full_name,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'preferences': self.preferences,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 
