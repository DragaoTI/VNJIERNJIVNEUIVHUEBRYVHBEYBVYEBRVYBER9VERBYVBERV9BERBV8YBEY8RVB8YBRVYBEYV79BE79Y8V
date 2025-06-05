from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List, Optional, Dict, Any
import json
from uuid import UUID, uuid4
from datetime import datetime

from ..models.user import Crosshair, User
from ..supabase_client import get_supabase

def create_crosshair(db: Session, owner_id: str, name: str, data: Dict[str, Any], is_public: bool = False) -> Crosshair:
    """Cria uma nova mira."""
    # Converte o dicionário para JSON
    data_json = json.dumps(data)
    
    crosshair = Crosshair(
        owner_id=owner_id,
        name=name,
        data=data_json,
        is_public=is_public
    )
    
    db.add(crosshair)
    db.commit()
    db.refresh(crosshair)
    return crosshair

def get_crosshair_by_id(db: Session, crosshair_id: str) -> Optional[Crosshair]:
    """Busca uma mira pelo ID."""
    return db.query(Crosshair).filter(Crosshair.id == crosshair_id).first()

def get_user_crosshairs(db: Session, user_id: str, skip: int = 0, limit: int = 100) -> List[Crosshair]:
    """Busca todas as miras de um usuário."""
    return db.query(Crosshair).filter(Crosshair.owner_id == user_id).offset(skip).limit(limit).all()

def get_public_crosshairs(db: Session, skip: int = 0, limit: int = 100) -> List[Crosshair]:
    """Busca miras públicas."""
    return db.query(Crosshair).filter(Crosshair.is_public == True).offset(skip).limit(limit).all()

def update_crosshair(db: Session, crosshair_id: str, crosshair_data: Dict[str, Any]) -> Optional[Crosshair]:
    """Atualiza uma mira existente."""
    crosshair = get_crosshair_by_id(db, crosshair_id)
    if not crosshair:
        return None
    
    # Atualiza os campos permitidos
    if "name" in crosshair_data:
        crosshair.name = crosshair_data["name"]
    
    if "is_public" in crosshair_data:
        crosshair.is_public = crosshair_data["is_public"]
    
    if "data" in crosshair_data:
        # Converte o dicionário para JSON
        data_json = json.dumps(crosshair_data["data"])
        crosshair.data = data_json
    
    db.commit()
    db.refresh(crosshair)
    return crosshair

def delete_crosshair(db: Session, crosshair_id: str) -> bool:
    """Exclui uma mira pelo ID."""
    crosshair = get_crosshair_by_id(db, crosshair_id)
    if not crosshair:
        return False
    
    db.delete(crosshair)
    db.commit()
    return True

def search_crosshairs(db: Session, query: str, skip: int = 0, limit: int = 100) -> List[Crosshair]:
    """Busca miras pelo nome."""
    return db.query(Crosshair).filter(
        Crosshair.name.ilike(f"%{query}%"),
        Crosshair.is_public == True
    ).offset(skip).limit(limit).all()

def get_crosshair_with_owner(db: Session, crosshair_id: str) -> Optional[Dict[str, Any]]:
    """Busca uma mira com informações do proprietário."""
    result = db.query(Crosshair, User.username).join(
        User, User.id == Crosshair.owner_id
    ).filter(Crosshair.id == crosshair_id).first()
    
    if not result:
        return None
    
    crosshair, username = result
    
    # Parse do JSON para dicionário
    data = json.loads(crosshair.data)
    
    return {
        "id": crosshair.id,
        "name": crosshair.name,
        "data": data,
        "is_public": crosshair.is_public,
        "created_at": crosshair.created_at,
        "updated_at": crosshair.updated_at,
        "owner_id": crosshair.owner_id,
        "owner_username": username
    }

class CrosshairRepository:
    """
    Repositório para operações com miras no Supabase.
    """
    
    @staticmethod
    async def get_by_id(crosshair_id: UUID) -> Optional[Crosshair]:
        """
        Busca uma mira pelo ID.
        
        Args:
            crosshair_id: ID da mira
            
        Returns:
            Optional[Crosshair]: Mira encontrada ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('crosshairs')
            .select('*')
            .eq('id', str(crosshair_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return Crosshair.from_dict(data[0])
    
    @staticmethod
    async def get_by_user(user_id: UUID) -> List[Crosshair]:
        """
        Busca todas as miras de um usuário.
        
        Args:
            user_id: ID do usuário
            
        Returns:
            List[Crosshair]: Lista de miras do usuário
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('crosshairs')
            .select('*')
            .eq('owner_id', str(user_id))
            .execute()
        )
        
        data = response.data
        
        return [Crosshair.from_dict(item) for item in data]
    
    @staticmethod
    async def get_public() -> List[Crosshair]:
        """
        Busca todas as miras públicas.
        
        Returns:
            List[Crosshair]: Lista de miras públicas
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('crosshairs')
            .select('*')
            .eq('is_public', True)
            .execute()
        )
        
        data = response.data
        
        return [Crosshair.from_dict(item) for item in data]
    
    @staticmethod
    async def create(crosshair_data: Dict[str, Any]) -> Crosshair:
        """
        Cria uma nova mira.
        
        Args:
            crosshair_data: Dados da mira
            
        Returns:
            Crosshair: Mira criada
        """
        supabase = get_supabase()
        
        # Gera um UUID para a nova mira
        crosshair_id = crosshair_data.get('id') or str(uuid4())
        crosshair_data['id'] = crosshair_id
        
        # Define timestamps
        now = datetime.now().isoformat()
        crosshair_data['created_at'] = now
        crosshair_data['updated_at'] = now
        
        # Insere a mira
        response = (
            supabase.table('crosshairs')
            .insert(crosshair_data)
            .execute()
        )
        
        created_crosshair = response.data[0]
        
        return Crosshair.from_dict(created_crosshair)
    
    @staticmethod
    async def update(crosshair_id: UUID, crosshair_data: Dict[str, Any]) -> Optional[Crosshair]:
        """
        Atualiza uma mira existente.
        
        Args:
            crosshair_id: ID da mira
            crosshair_data: Dados a serem atualizados
            
        Returns:
            Optional[Crosshair]: Mira atualizada ou None
        """
        supabase = get_supabase()
        
        # Define timestamp de atualização
        crosshair_data['updated_at'] = datetime.now().isoformat()
        
        # Atualiza a mira
        response = (
            supabase.table('crosshairs')
            .update(crosshair_data)
            .eq('id', str(crosshair_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return Crosshair.from_dict(data[0])
    
    @staticmethod
    async def delete(crosshair_id: UUID) -> bool:
        """
        Remove uma mira.
        
        Args:
            crosshair_id: ID da mira
            
        Returns:
            bool: True se removida com sucesso, False caso contrário
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('crosshairs')
            .delete()
            .eq('id', str(crosshair_id))
            .execute()
        )
        
        return len(response.data) > 0 
