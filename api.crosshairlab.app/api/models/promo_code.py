from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

class PromoCode:
    """
    Modelo para representar um código promocional no sistema.
    """
    def __init__(
        self,
        id: UUID,
        code: str,
        reward_type: str,
        max_uses: int,
        remaining_uses: int,
        is_active: bool = True,
        expires_at: Optional[datetime] = None,
        notes: Optional[str] = None,
        created_by: Optional[UUID] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.code = code
        self.reward_type = reward_type
        self.max_uses = max_uses
        self.remaining_uses = remaining_uses
        self.is_active = is_active
        self.expires_at = expires_at
        self.notes = notes
        self.created_by = created_by
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PromoCode':
        """
        Cria uma instância de PromoCode a partir de um dicionário.
        
        Args:
            data: Dicionário contendo os dados do código promocional
            
        Returns:
            PromoCode: Nova instância de PromoCode
        """
        return cls(
            id=data.get('id'),
            code=data.get('code'),
            reward_type=data.get('reward_type'),
            max_uses=data.get('max_uses', 0),
            remaining_uses=data.get('remaining_uses', 0),
            is_active=data.get('is_active', True),
            expires_at=data.get('expires_at'),
            notes=data.get('notes'),
            created_by=data.get('created_by'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a instância para um dicionário.
        
        Returns:
            Dict[str, Any]: Dicionário representando o código promocional
        """
        return {
            'id': str(self.id),
            'code': self.code,
            'reward_type': self.reward_type,
            'max_uses': self.max_uses,
            'remaining_uses': self.remaining_uses,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'notes': self.notes,
            'created_by': str(self.created_by) if self.created_by else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class PromoCodeUse:
    """
    Modelo para representar o uso de um código promocional.
    """
    def __init__(
        self,
        id: UUID,
        promo_code_id: UUID,
        user_id: UUID,
        used_at: Optional[datetime] = None
    ):
        self.id = id
        self.promo_code_id = promo_code_id
        self.user_id = user_id
        self.used_at = used_at or datetime.now()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PromoCodeUse':
        """
        Cria uma instância de PromoCodeUse a partir de um dicionário.
        
        Args:
            data: Dicionário contendo os dados do uso do código promocional
            
        Returns:
            PromoCodeUse: Nova instância de PromoCodeUse
        """
        return cls(
            id=data.get('id'),
            promo_code_id=data.get('promo_code_id'),
            user_id=data.get('user_id'),
            used_at=data.get('used_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a instância para um dicionário.
        
        Returns:
            Dict[str, Any]: Dicionário representando o uso do código promocional
        """
        return {
            'id': str(self.id),
            'promo_code_id': str(self.promo_code_id),
            'user_id': str(self.user_id),
            'used_at': self.used_at.isoformat() if self.used_at else None
        } 
