from typing import List, Optional, Dict, Any
import json
from datetime import datetime

from ..supabase_client import get_supabase

async def create_crosshair(owner_id: str, name: str, data: Dict[str, Any], is_public: bool = False) -> Dict[str, Any]:
    """Cria uma nova mira usando o Supabase."""
    try:
        supabase = get_supabase()
        
        # Prepara os dados para inserção
        crosshair_data = {
            'name': name,
            'data': data,  # O Supabase aceita JSON diretamente
            'is_public': is_public,
            'owner_id': owner_id,
            'created_at': datetime.now().isoformat()
        }
        
        # Insere a mira no banco de dados
        response = supabase.table('crosshairs').insert(crosshair_data).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        else:
            raise ValueError("Erro ao criar mira: sem dados retornados")
    except Exception as e:
        raise ValueError(f"Erro ao criar mira: {str(e)}")

async def get_crosshair_by_id(crosshair_id: str) -> Optional[Dict[str, Any]]:
    """Busca uma mira pelo ID usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('crosshairs').select('*').eq('id', crosshair_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Erro ao buscar mira por ID: {str(e)}")
        return None

async def get_user_crosshairs(user_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """Busca todas as miras de um usuário usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('crosshairs').select('*').eq('owner_id', user_id).range(skip, skip + limit - 1).order('created_at', desc=True).execute()
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Erro ao buscar miras do usuário: {str(e)}")
        return []

async def get_public_crosshairs(skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """Busca miras públicas usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('crosshairs').select('*').eq('is_public', True).range(skip, skip + limit - 1).order('created_at', desc=True).execute()
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Erro ao buscar miras públicas: {str(e)}")
        return []

async def update_crosshair(crosshair_id: str, crosshair_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Atualiza uma mira existente usando o Supabase."""
    try:
        supabase = get_supabase()
        
        # Adiciona o timestamp de atualização
        crosshair_data['updated_at'] = datetime.now().isoformat()
        
        response = supabase.table('crosshairs').update(crosshair_data).eq('id', crosshair_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Erro ao atualizar mira: {str(e)}")
        return None

async def delete_crosshair(crosshair_id: str) -> bool:
    """Exclui uma mira pelo ID usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('crosshairs').delete().eq('id', crosshair_id).execute()
        
        return True
    except Exception as e:
        print(f"Erro ao excluir mira: {str(e)}")
        return False

async def search_crosshairs(query: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """Busca miras pelo nome usando o Supabase."""
    try:
        supabase = get_supabase()
        # Usa o operador ilike para busca case-insensitive
        response = supabase.table('crosshairs').select('*').ilike('name', f'%{query}%').eq('is_public', True).range(skip, skip + limit - 1).execute()
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Erro ao buscar miras: {str(e)}")
        return []

async def get_crosshair_with_owner(crosshair_id: str) -> Optional[Dict[str, Any]]:
    """Busca uma mira com informações do proprietário usando o Supabase."""
    try:
        supabase = get_supabase()
        # Busca a mira
        crosshair_response = supabase.table('crosshairs').select('*').eq('id', crosshair_id).execute()
        
        if not crosshair_response.data or len(crosshair_response.data) == 0:
            return None
        
        crosshair = crosshair_response.data[0]
        
        # Busca informações do proprietário
        user_response = supabase.table('users').select('username').eq('id', crosshair['owner_id']).execute()
        
        if user_response.data and len(user_response.data) > 0:
            username = user_response.data[0]['username']
        else:
            username = "Usuário desconhecido"
        
        # Combina as informações
        result = {
            **crosshair,
            "owner_username": username
        }
        
        return result
    except Exception as e:
        print(f"Erro ao buscar mira com proprietário: {str(e)}")
        return None 
