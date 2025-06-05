from sqlalchemy.orm import Session
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from ..models.user import User, UserProfile, Crosshair
from ..security.auth import get_password_hash
from ..supabase_client import get_supabase

def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Busca um usuário pelo ID."""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Busca um usuário pelo email."""
    return db.query(User).filter(User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Busca um usuário pelo nome de usuário."""
    return db.query(User).filter(User.username == username).first()

def get_user_by_email_or_username(db: Session, email: str, username: str) -> Optional[User]:
    """Busca um usuário pelo email ou nome de usuário."""
    return db.query(User).filter(
        or_(User.email == email, User.username == username)
    ).first()

def create_user(db: Session, email: str, username: str, password: str) -> User:
    """Cria um novo usuário."""
    hashed_password = get_password_hash(password)
    
    # Cria o usuário
    user = User(
        email=email,
        username=username,
        hashed_password=hashed_password
    )
    
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Cria o perfil do usuário
        profile = UserProfile(user_id=user.id)
        db.add(profile)
        db.commit()
        
        return user
    except IntegrityError:
        db.rollback()
        raise ValueError("Usuário com este email ou nome de usuário já existe")

def update_user(db: Session, user_id: str, user_data: Dict[str, Any]) -> Optional[User]:
    """Atualiza um usuário existente."""
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    
    for key, value in user_data.items():
        if hasattr(user, key) and key != "id":
            setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: str) -> bool:
    """Exclui um usuário pelo ID."""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    db.delete(user)
    db.commit()
    return True

def update_user_password(db: Session, user_id: str, new_password: str) -> bool:
    """Atualiza a senha de um usuário."""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    return True

def update_user_2fa_status(db: Session, user_id: str, enabled: bool, secret: Optional[str] = None) -> bool:
    """Atualiza o status de 2FA de um usuário."""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    user.is_2fa_enabled = enabled
    if secret is not None:
        user.twofa_secret = secret
    
    db.commit()
    return True

def update_user_pro_status(db: Session, user_id: str, is_pro: bool, 
                         subscription_id: Optional[str] = None,
                         expires_at: Optional[datetime] = None) -> bool:
    """Atualiza o status PRO de um usuário."""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    user.is_pro = is_pro
    if subscription_id:
        user.subscription_id = subscription_id
    if expires_at:
        user.subscription_expires_at = expires_at
    
    db.commit()
    return True

def get_user_profile(db: Session, user_id: str) -> Optional[UserProfile]:
    """Obtém o perfil de um usuário."""
    return db.query(UserProfile).filter(UserProfile.user_id == user_id).first()

def update_user_profile(db: Session, user_id: str, profile_data: Dict[str, Any]) -> Optional[UserProfile]:
    """Atualiza o perfil de um usuário."""
    profile = get_user_profile(db, user_id)
    if not profile:
        return None
    
    for key, value in profile_data.items():
        if hasattr(profile, key) and key not in ["id", "user_id"]:
            setattr(profile, key, value)
    
    db.commit()
    db.refresh(profile)
    return profile

class UserRepository:
    """
    Repositório para operações com usuários no Supabase.
    """
    
    @staticmethod
    async def get_by_id(user_id: UUID) -> Optional[User]:
        """
        Busca um usuário pelo ID.
        
        Args:
            user_id: ID do usuário
            
        Returns:
            Optional[User]: Usuário encontrado ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('users')
            .select('*')
            .eq('id', str(user_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return User.from_dict(data[0])
    
    @staticmethod
    async def get_by_email(email: str) -> Optional[User]:
        """
        Busca um usuário pelo email.
        
        Args:
            email: Email do usuário
            
        Returns:
            Optional[User]: Usuário encontrado ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('users')
            .select('*')
            .eq('email', email)
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return User.from_dict(data[0])
    
    @staticmethod
    async def get_by_username(username: str) -> Optional[User]:
        """
        Busca um usuário pelo nome de usuário.
        
        Args:
            username: Nome de usuário
            
        Returns:
            Optional[User]: Usuário encontrado ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('users')
            .select('*')
            .eq('username', username)
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return User.from_dict(data[0])
    
    @staticmethod
    async def create(user_data: Dict[str, Any]) -> User:
        """
        Cria um novo usuário.
        
        Args:
            user_data: Dados do usuário
            
        Returns:
            User: Usuário criado
        """
        supabase = get_supabase()
        
        # Gera um UUID para o novo usuário
        user_id = user_data.get('id') or str(uuid4())
        user_data['id'] = user_id
        
        # Define timestamps
        now = datetime.now().isoformat()
        user_data['created_at'] = now
        user_data['updated_at'] = now
        
        # Insere o usuário
        response = (
            supabase.table('users')
            .insert(user_data)
            .execute()
        )
        
        created_user = response.data[0]
        
        return User.from_dict(created_user)
    
    @staticmethod
    async def update(user_id: UUID, user_data: Dict[str, Any]) -> Optional[User]:
        """
        Atualiza um usuário existente.
        
        Args:
            user_id: ID do usuário
            user_data: Dados a serem atualizados
            
        Returns:
            Optional[User]: Usuário atualizado ou None
        """
        supabase = get_supabase()
        
        # Define timestamp de atualização
        user_data['updated_at'] = datetime.now().isoformat()
        
        # Atualiza o usuário
        response = (
            supabase.table('users')
            .update(user_data)
            .eq('id', str(user_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return User.from_dict(data[0])
    
    @staticmethod
    async def delete(user_id: UUID) -> bool:
        """
        Remove um usuário.
        
        Args:
            user_id: ID do usuário
            
        Returns:
            bool: True se removido com sucesso, False caso contrário
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('users')
            .delete()
            .eq('id', str(user_id))
            .execute()
        )
        
        return len(response.data) > 0
    
    @staticmethod
    async def get_profile(user_id: UUID) -> Optional[UserProfile]:
        """
        Busca o perfil de um usuário.
        
        Args:
            user_id: ID do usuário
            
        Returns:
            Optional[UserProfile]: Perfil do usuário ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('user_profiles')
            .select('*')
            .eq('user_id', str(user_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return UserProfile.from_dict(data[0])
    
    @staticmethod
    async def create_profile(profile_data: Dict[str, Any]) -> UserProfile:
        """
        Cria um novo perfil de usuário.
        
        Args:
            profile_data: Dados do perfil
            
        Returns:
            UserProfile: Perfil criado
        """
        supabase = get_supabase()
        
        # Gera um UUID para o novo perfil
        profile_id = profile_data.get('id') or str(uuid4())
        profile_data['id'] = profile_id
        
        # Define timestamps
        now = datetime.now().isoformat()
        profile_data['created_at'] = now
        profile_data['updated_at'] = now
        
        # Insere o perfil
        response = (
            supabase.table('user_profiles')
            .insert(profile_data)
            .execute()
        )
        
        created_profile = response.data[0]
        
        return UserProfile.from_dict(created_profile)
    
    @staticmethod
    async def update_profile(user_id: UUID, profile_data: Dict[str, Any]) -> Optional[UserProfile]:
        """
        Atualiza o perfil de um usuário.
        
        Args:
            user_id: ID do usuário
            profile_data: Dados do perfil a serem atualizados
            
        Returns:
            Optional[UserProfile]: Perfil atualizado ou None
        """
        supabase = get_supabase()
        
        # Define timestamp de atualização
        profile_data['updated_at'] = datetime.now().isoformat()
        
        # Atualiza o perfil
        response = (
            supabase.table('user_profiles')
            .update(profile_data)
            .eq('user_id', str(user_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return UserProfile.from_dict(data[0]) 
