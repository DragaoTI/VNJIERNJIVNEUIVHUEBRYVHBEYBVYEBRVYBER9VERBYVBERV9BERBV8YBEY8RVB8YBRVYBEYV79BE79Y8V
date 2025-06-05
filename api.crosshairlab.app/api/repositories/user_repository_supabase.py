from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta

from ..supabase_client import get_supabase
from ..security.auth_supabase import create_user_with_supabase

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Busca um usuário pelo ID usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        users = response.data
        
        if users and len(users) > 0:
            return users[0]
        return None
    except Exception as e:
        print(f"Erro ao buscar usuário por ID: {str(e)}")
        return None

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Busca um usuário pelo email usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('users').select('*').eq('email', email).execute()
        users = response.data
        
        if users and len(users) > 0:
            return users[0]
        return None
    except Exception as e:
        print(f"Erro ao buscar usuário por email: {str(e)}")
        return None

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Busca um usuário pelo nome de usuário usando o Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('users').select('*').eq('username', username).execute()
        users = response.data
        
        if users and len(users) > 0:
            return users[0]
        return None
    except Exception as e:
        print(f"Erro ao buscar usuário por username: {str(e)}")
        return None

async def create_user(email: str, username: str, password: str) -> Dict[str, Any]:
    """
    Cria um novo usuário usando o Supabase.
    Esta função usa o Auth do Supabase e também insere dados na tabela users.
    """
    # Primeiro, cria o usuário no Auth do Supabase
    auth_user = await create_user_with_supabase(email, password, username)
    
    # Agora, insere o registro na tabela users
    try:
        supabase = get_supabase()
        user_data = {
            'id': auth_user['id'],
            'email': email,
            'username': username,
            'is_active': True,
            'is_verified': False,
            'is_pro': False,
            'created_at': datetime.now().isoformat(),
        }
        
        response = supabase.table('users').insert(user_data).execute()
        
        # Cria também o perfil do usuário
        profile_data = {
            'user_id': auth_user['id'],
            'full_name': None,
            'bio': None,
            'avatar_url': None,
            'preferences': None
        }
        
        supabase.table('user_profiles').insert(profile_data).execute()
        
        return user_data
    except Exception as e:
        # Se der erro, tenta remover o usuário criado no Auth
        try:
            supabase.auth.admin.delete_user(auth_user['id'])
        except:
            pass
        
        raise ValueError(f"Erro ao criar usuário: {str(e)}")

async def update_user(user_id: str, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Atualiza um usuário existente no Supabase."""
    try:
        supabase = get_supabase()
        
        # Adiciona o timestamp de atualização
        user_data['updated_at'] = datetime.now().isoformat()
        
        response = supabase.table('users').update(user_data).eq('id', user_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Erro ao atualizar usuário: {str(e)}")
        return None

async def delete_user(user_id: str) -> bool:
    """Exclui um usuário pelo ID no Supabase."""
    try:
        supabase = get_supabase()
        
        # Exclui o usuário da tabela users (os triggers do Supabase cuidarão das dependências)
        supabase.table('users').delete().eq('id', user_id).execute()
        
        # Também exclui o usuário do Auth do Supabase
        supabase.auth.admin.delete_user(user_id)
        
        return True
    except Exception as e:
        print(f"Erro ao excluir usuário: {str(e)}")
        return False

async def update_user_password(user_id: str, new_password: str) -> bool:
    """Atualiza a senha de um usuário no Auth do Supabase."""
    try:
        supabase = get_supabase()
        
        # Atualiza a senha no Auth do Supabase
        supabase.auth.admin.update_user_by_id(
            user_id,
            {"password": new_password}
        )
        
        return True
    except Exception as e:
        print(f"Erro ao atualizar senha: {str(e)}")
        return False

async def update_user_2fa_status(user_id: str, enabled: bool, secret: Optional[str] = None) -> bool:
    """Atualiza o status de 2FA de um usuário no Supabase."""
    try:
        supabase = get_supabase()
        
        # Prepara os dados para atualização
        update_data = {
            'is_2fa_enabled': enabled,
            'updated_at': datetime.now().isoformat()
        }
        
        if secret is not None:
            update_data['twofa_secret'] = secret
        
        # Atualiza na tabela users
        supabase.table('users').update(update_data).eq('id', user_id).execute()
        
        return True
    except Exception as e:
        print(f"Erro ao atualizar status 2FA: {str(e)}")
        return False

async def get_user_profile(user_id: str) -> Optional[Dict[str, Any]]:
    """Obtém o perfil de um usuário no Supabase."""
    try:
        supabase = get_supabase()
        response = supabase.table('user_profiles').select('*').eq('user_id', user_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Erro ao obter perfil do usuário: {str(e)}")
        return None

async def update_user_profile(user_id: str, profile_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Atualiza o perfil de um usuário no Supabase."""
    try:
        supabase = get_supabase()
        
        response = supabase.table('user_profiles').update(profile_data).eq('user_id', user_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Erro ao atualizar perfil do usuário: {str(e)}")
        return None 
