from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID, uuid4
from datetime import datetime

from ..models import PromoCode, PromoCodeUse
from ..supabase_client import get_supabase
import random
import string

class PromoCodeRepository:
    """
    Repositório para operações com códigos promocionais no Supabase.
    """
    
    @staticmethod
    async def get_by_id(promo_code_id: UUID) -> Optional[PromoCode]:
        """
        Busca um código promocional pelo ID.
        
        Args:
            promo_code_id: ID do código promocional
            
        Returns:
            Optional[PromoCode]: Código promocional encontrado ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('promo_codes')
            .select('*')
            .eq('id', str(promo_code_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return PromoCode.from_dict(data[0])
    
    @staticmethod
    async def get_by_code(code: str) -> Optional[PromoCode]:
        """
        Busca um código promocional pelo código.
        
        Args:
            code: Código promocional
            
        Returns:
            Optional[PromoCode]: Código promocional encontrado ou None
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('promo_codes')
            .select('*')
            .eq('code', code.upper())
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return PromoCode.from_dict(data[0])
    
    @staticmethod
    async def get_all(active_only: bool = False, limit: int = 100, offset: int = 0) -> List[PromoCode]:
        """
        Busca todos os códigos promocionais.
        
        Args:
            active_only: Se True, retorna apenas códigos ativos
            limit: Número máximo de resultados
            offset: Índice inicial para paginação
            
        Returns:
            List[PromoCode]: Lista de códigos promocionais
        """
        supabase = get_supabase()
        
        query = supabase.table('promo_codes').select('*')
        
        if active_only:
            query = query.eq('is_active', True)
            
        response = query.order('created_at', desc=True).range(offset, offset + limit - 1).execute()
        
        data = response.data
        
        return [PromoCode.from_dict(item) for item in data]
    
    @staticmethod
    async def search(search_term: str, active_only: bool = False, limit: int = 100, offset: int = 0) -> List[PromoCode]:
        """
        Busca códigos promocionais por termo de pesquisa.
        
        Args:
            search_term: Termo de pesquisa
            active_only: Se True, retorna apenas códigos ativos
            limit: Número máximo de resultados
            offset: Índice inicial para paginação
            
        Returns:
            List[PromoCode]: Lista de códigos promocionais
        """
        supabase = get_supabase()
        
        query = supabase.table('promo_codes').select('*').ilike('code', f'%{search_term}%')
        
        if active_only:
            query = query.eq('is_active', True)
            
        response = query.order('created_at', desc=True).range(offset, offset + limit - 1).execute()
        
        data = response.data
        
        return [PromoCode.from_dict(item) for item in data]
    
    @staticmethod
    async def filter_by_reward_type(reward_type: str, active_only: bool = False, limit: int = 100, offset: int = 0) -> List[PromoCode]:
        """
        Filtra códigos promocionais por tipo de recompensa.
        
        Args:
            reward_type: Tipo de recompensa
            active_only: Se True, retorna apenas códigos ativos
            limit: Número máximo de resultados
            offset: Índice inicial para paginação
            
        Returns:
            List[PromoCode]: Lista de códigos promocionais
        """
        supabase = get_supabase()
        
        query = supabase.table('promo_codes').select('*').eq('reward_type', reward_type)
        
        if active_only:
            query = query.eq('is_active', True)
            
        response = query.order('created_at', desc=True).range(offset, offset + limit - 1).execute()
        
        data = response.data
        
        return [PromoCode.from_dict(item) for item in data]
    
    @staticmethod
    async def create(promo_code_data: Dict[str, Any]) -> PromoCode:
        """
        Cria um novo código promocional.
        
        Args:
            promo_code_data: Dados do código promocional
            
        Returns:
            PromoCode: Código promocional criado
        """
        supabase = get_supabase()
        
        # Gera um UUID para o novo código promocional
        promo_code_id = promo_code_data.get('id') or str(uuid4())
        promo_code_data['id'] = promo_code_id
        
        # Converte o código para maiúsculas
        if 'code' in promo_code_data:
            promo_code_data['code'] = promo_code_data['code'].upper()
        
        # Define o número de usos restantes igual ao máximo inicialmente
        if 'max_uses' in promo_code_data and 'remaining_uses' not in promo_code_data:
            promo_code_data['remaining_uses'] = promo_code_data['max_uses']
        
        # Define timestamps
        now = datetime.now().isoformat()
        promo_code_data['created_at'] = now
        promo_code_data['updated_at'] = now
        
        # Insere o código promocional
        response = (
            supabase.table('promo_codes')
            .insert(promo_code_data)
            .execute()
        )
        
        created_promo_code = response.data[0]
        
        return PromoCode.from_dict(created_promo_code)
    
    @staticmethod
    async def update(promo_code_id: UUID, promo_code_data: Dict[str, Any]) -> Optional[PromoCode]:
        """
        Atualiza um código promocional existente.
        
        Args:
            promo_code_id: ID do código promocional
            promo_code_data: Dados a serem atualizados
            
        Returns:
            Optional[PromoCode]: Código promocional atualizado ou None
        """
        supabase = get_supabase()
        
        # Define timestamp de atualização
        promo_code_data['updated_at'] = datetime.now().isoformat()
        
        # Converte o código para maiúsculas se estiver presente
        if 'code' in promo_code_data:
            promo_code_data['code'] = promo_code_data['code'].upper()
        
        # Atualiza o código promocional
        response = (
            supabase.table('promo_codes')
            .update(promo_code_data)
            .eq('id', str(promo_code_id))
            .execute()
        )
        
        data = response.data
        
        if not data or len(data) == 0:
            return None
            
        return PromoCode.from_dict(data[0])
    
    @staticmethod
    async def delete(promo_code_id: UUID) -> bool:
        """
        Remove um código promocional.
        
        Args:
            promo_code_id: ID do código promocional
            
        Returns:
            bool: True se removido com sucesso, False caso contrário
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('promo_codes')
            .delete()
            .eq('id', str(promo_code_id))
            .execute()
        )
        
        return len(response.data) > 0
    
    @staticmethod
    async def register_use(promo_code_id: UUID, user_id: UUID) -> Tuple[bool, Optional[PromoCodeUse]]:
        """
        Registra o uso de um código promocional.
        
        Args:
            promo_code_id: ID do código promocional
            user_id: ID do usuário
            
        Returns:
            Tuple[bool, Optional[PromoCodeUse]]: Tupla com sucesso da operação e o uso registrado
        """
        supabase = get_supabase()
        
        # Verifica se o código existe e está ativo
        promo_code = await PromoCodeRepository.get_by_id(promo_code_id)
        if not promo_code or not promo_code.is_active:
            return False, None
        
        # Verifica se ainda há usos disponíveis
        if promo_code.remaining_uses <= 0:
            return False, None
        
        # Verifica se o código não expirou
        if promo_code.expires_at and promo_code.expires_at < datetime.now():
            return False, None
        
        # Verifica se o usuário já usou este código
        response = (
            supabase.table('promo_code_uses')
            .select('*')
            .eq('promo_code_id', str(promo_code_id))
            .eq('user_id', str(user_id))
            .execute()
        )
        
        if response.data and len(response.data) > 0:
            return False, None
        
        # Registra o uso
        use_id = str(uuid4())
        use_data = {
            'id': use_id,
            'promo_code_id': str(promo_code_id),
            'user_id': str(user_id),
            'used_at': datetime.now().isoformat()
        }
        
        use_response = (
            supabase.table('promo_code_uses')
            .insert(use_data)
            .execute()
        )
        
        if not use_response.data or len(use_response.data) == 0:
            return False, None
        
        # Atualiza o número de usos restantes
        update_response = (
            supabase.table('promo_codes')
            .update({'remaining_uses': promo_code.remaining_uses - 1})
            .eq('id', str(promo_code_id))
            .execute()
        )
        
        if not update_response.data or len(update_response.data) == 0:
            # Reverte o uso registrado em caso de falha
            (
                supabase.table('promo_code_uses')
                .delete()
                .eq('id', use_id)
                .execute()
            )
            return False, None
        
        return True, PromoCodeUse.from_dict(use_response.data[0])
    
    @staticmethod
    async def get_uses_by_promo_code(promo_code_id: UUID, limit: int = 100, offset: int = 0) -> List[PromoCodeUse]:
        """
        Busca os usos de um código promocional.
        
        Args:
            promo_code_id: ID do código promocional
            limit: Número máximo de resultados
            offset: Índice inicial para paginação
            
        Returns:
            List[PromoCodeUse]: Lista de usos do código promocional
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('promo_code_uses')
            .select('*')
            .eq('promo_code_id', str(promo_code_id))
            .order('used_at', desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        
        data = response.data
        
        return [PromoCodeUse.from_dict(item) for item in data]
    
    @staticmethod
    async def get_uses_by_user(user_id: UUID, limit: int = 100, offset: int = 0) -> List[PromoCodeUse]:
        """
        Busca os códigos promocionais usados por um usuário.
        
        Args:
            user_id: ID do usuário
            limit: Número máximo de resultados
            offset: Índice inicial para paginação
            
        Returns:
            List[PromoCodeUse]: Lista de usos de códigos promocionais
        """
        supabase = get_supabase()
        
        response = (
            supabase.table('promo_code_uses')
            .select('*')
            .eq('user_id', str(user_id))
            .order('used_at', desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        
        data = response.data
        
        return [PromoCodeUse.from_dict(item) for item in data]
    
    @staticmethod
    def generate_random_code(prefix: str = "", length: int = 8) -> str:
        """
        Gera um código promocional aleatório.
        
        Args:
            prefix: Prefixo para o código (opcional)
            length: Comprimento do código (sem contar o prefixo)
            
        Returns:
            str: Código promocional gerado
        """
        chars = string.ascii_uppercase + string.digits
        random_part = ''.join(random.choice(chars) for _ in range(length))
        
        if prefix:
            return f"{prefix}-{random_part}"
        
        return random_part
    
    @staticmethod
    async def log_admin_action(
        admin_id: UUID,
        action_type: str,
        entity_type: str,
        entity_id: UUID,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Registra uma ação administrativa.
        
        Args:
            admin_id: ID do administrador
            action_type: Tipo de ação (create, update, delete)
            entity_type: Tipo de entidade (promo_code)
            entity_id: ID da entidade
            details: Detalhes adicionais da ação
            
        Returns:
            Dict[str, Any]: Log da ação criada
        """
        supabase = get_supabase()
        
        log_data = {
            'id': str(uuid4()),
            'admin_id': str(admin_id),
            'action_type': action_type,
            'entity_type': entity_type,
            'entity_id': str(entity_id),
            'details': details,
            'created_at': datetime.now().isoformat()
        }
        
        response = (
            supabase.table('admin_action_logs')
            .insert(log_data)
            .execute()
        )
        
        return response.data[0] if response.data else log_data 
