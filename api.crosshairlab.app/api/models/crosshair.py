from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

class Crosshair:
    """
    Modelo para representar uma mira no sistema.
    """
    def __init__(
        self,
        id: UUID,
        name: str,
        data: Dict[str, Any],
        is_public: bool = False,
        owner_id: Optional[UUID] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.name = name
        self.data = data
        self.is_public = is_public
        self.owner_id = owner_id
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Crosshair':
        """
        Cria uma instância de Crosshair a partir de um dicionário.
        
        Args:
            data: Dicionário contendo os dados da mira
            
        Returns:
            Crosshair: Nova instância de Crosshair
        """
        return cls(
            id=data.get('id'),
            name=data.get('name'),
            data=data.get('data', {}),
            is_public=data.get('is_public', False),
            owner_id=data.get('owner_id'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a instância para um dicionário.
        
        Returns:
            Dict[str, Any]: Dicionário representando a mira
        """
        return {
            'id': str(self.id),
            'name': self.name,
            'data': self.data,
            'is_public': self.is_public,
            'owner_id': str(self.owner_id) if self.owner_id else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 
