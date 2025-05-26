# app/services/supabase_service.py
from supabase import create_client, Client
from app.core.config import settings
from app.schemas.user_schemas import UserCreate
from app.models.user import User
from app.schemas.geo_log_schemas import GeoLogCreate
from app.utils.security import hash_token
from typing import Optional, Dict, Any, List
import uuid
from datetime import datetime, timezone, timedelta
import traceback # Para logs de exceção

class SupabaseService:
    def __init__(self):
        self.client: Optional[Client] = None
        print(f"INFO:     Tentando inicializar SupabaseService...")
        print(f"INFO:     Usando SUPABASE_URL: '{settings.SUPABASE_URL[:30] if settings.SUPABASE_URL else 'NÃO DEFINIDA!'}...'")
        print(f"INFO:     Usando SUPABASE_KEY (primeiros 5 chars): '{settings.SUPABASE_KEY[:5] if settings.SUPABASE_KEY else 'NÃO DEFINIDA!'}...'")
        if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
            print("ERRO FATAL: SUPABASE_URL ou SUPABASE_KEY não definidas. Inicialização abortada.")
            return
        try:
            self.client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
            if self.client:
                print(f"INFO:     Supabase client INICIALIZADO COM SUCESSO.")
            else:
                print(f"AVISO CRÍTICO: create_client retornou None/Falsey sem exceção.")
        except Exception as e:
            print(f"ERRO FATAL AO INICIALIZAR O OBJETO SUPABASE CLIENT: {e}")
            traceback.print_exc()

    # Auth admin methods might still be awaitable if they make HTTP calls internally
    # and the gotrue client handles async. We'll keep await for these for now.
    # The primary error was with .table().execute().
    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        if not self.client: print("ERRO: get_user_by_id, self.client é None."); return None
        try:
            user_data_res = self.client.auth.admin.get_user_by_id(str(user_id)) # Assumindo que esta chamada pode ser awaitable ou sync
            if user_data_res and user_data_res.user:
                # ... (lógica de conversão para User model)
                supabase_user = user_data_res.user
                role = supabase_user.user_metadata.get("role", "user") if supabase_user.user_metadata else "user"
                return User(
                    id=supabase_user.id, email=supabase_user.email, is_active=True,
                    role=role, user_metadata=supabase_user.user_metadata or {}
                )
            return None
        except Exception as e: print(f"Erro ao buscar usuário {user_id}: {e}"); return None

    async def get_user_by_email_for_check(self, email: str) -> bool:
        if not self.client: print("ERRO: get_user_by_email_for_check, self.client é None."); return False
        try:
            response = self.client.auth.admin.list_users(email=email, limit=1)
            return bool(response.users)
        except Exception as e: print(f"Erro ao verificar usuário por email {email}: {e}"); return False

    async def create_user(self, user_create: UserCreate) -> Optional[User]:
        if not self.client: print("ERRO: create_user, self.client é None."); return None
        try:
            print(f"[SUPABASE_CREATE] Iniciando criação de usuário: {user_create.email}")
            # ... (lógica de user_metadata)
            user_metadata_with_role = user_create.model_dump(exclude_unset=True).get("user_metadata", {})
            if "role" not in user_metadata_with_role: user_metadata_with_role["role"] = "user"
            
            # Adicionando username nos metadados para garantir que seja passado ao trigger
            if not user_metadata_with_role.get("username") and hasattr(user_create, "username"):
                user_metadata_with_role["username"] = user_create.username
            
            print(f"[SUPABASE_CREATE] Metadados preparados: {user_metadata_with_role}")
            print(f"[SUPABASE_CREATE] Enviando requisição para auth.admin.create_user...")
            
            # Alterando email_confirm para False para seguir o fluxo normal
            response = self.client.auth.admin.create_user(
                email=user_create.email, 
                password=user_create.password,
                email_confirm=False,  # Mudando para FALSE
                user_metadata=user_metadata_with_role
            )
            
            print(f"[SUPABASE_CREATE] Resposta da criação de usuário: {response}")
            
            if response and response.user:
                print(f"[SUPABASE_CREATE] Usuário criado com sucesso. ID: {response.user.id}")
                # Após criar o usuário, garantir que o perfil seja criado manualmente
                try:
                    # Tenta criar o perfil explicitamente usando RPC
                    profile_data = {
                        "user_id": response.user.id,
                        "username": user_metadata_with_role.get("username") or response.user.email.split("@")[0],
                        "email": response.user.email
                    }
                    
                    print(f"[SUPABASE_CREATE] Tentando criar perfil via RPC. Dados: {profile_data}")
                    
                    # Chamar a função RPC que criamos para criar o perfil
                    profile_response = self.client.rpc(
                        "create_profile_for_user",
                        {
                            "user_id": profile_data["user_id"],
                            "user_email": profile_data["email"],
                            "username": profile_data["username"]
                        }
                    ).execute()
                    
                    print(f"[SUPABASE_CREATE] Perfil criado manualmente via RPC: {profile_response}")
                except Exception as profile_error:
                    print(f"[SUPABASE_CREATE] AVISO: Falha ao criar perfil via RPC: {profile_error}")
                    print(f"[SUPABASE_CREATE] Detalhes do erro RPC: {type(profile_error).__name__}")
                    traceback.print_exc()
                    
                    # Vamos tentar inserir diretamente na tabela como fallback
                    try:
                        print(f"[SUPABASE_CREATE] Tentando criar perfil via INSERT direto na tabela profiles")
                        insert_data = {
                            "user_id": response.user.id,
                            "username": user_metadata_with_role.get("username") or response.user.email.split("@")[0],
                            "email": response.user.email,
                            "created_at": datetime.now(timezone.utc).isoformat()
                        }
                        print(f"[SUPABASE_CREATE] Dados para inserção: {insert_data}")
                        
                        insert_response = self.client.table("profiles").insert(insert_data).execute()
                        print(f"[SUPABASE_CREATE] Resposta da inserção direta: {insert_response}")
                        print("[SUPABASE_CREATE] Perfil criado com método alternativo")
                    except Exception as insert_error:
                        print(f"[SUPABASE_CREATE] ERRO secundário ao inserir perfil diretamente: {insert_error}")
                        print(f"[SUPABASE_CREATE] Tipo de erro INSERT: {type(insert_error).__name__}")
                        traceback.print_exc()
                        
                        # Tentar verificar se o perfil já existe
                        try:
                            print(f"[SUPABASE_CREATE] Verificando se o perfil já existe para o usuário {response.user.id}")
                            profile_check = self.client.table("profiles").select("*").eq("user_id", response.user.id).execute()
                            if profile_check.data and len(profile_check.data) > 0:
                                print(f"[SUPABASE_CREATE] Perfil já existe! Dados: {profile_check.data[0]}")
                            else:
                                print(f"[SUPABASE_CREATE] Perfil NÃO existe. Resposta: {profile_check}")
                        except Exception as check_error:
                            print(f"[SUPABASE_CREATE] Erro ao verificar perfil existente: {check_error}")
                
                # ... (lógica de conversão para User model)
                created_user = response.user
                return User(
                    id=created_user.id, email=created_user.email, is_active=True,
                    role=created_user.user_metadata.get("role", "user"),
                    user_metadata=created_user.user_metadata or {}
                )
            
            print(f"[SUPABASE_CREATE] Falha ao criar usuário Supabase. Resposta: {response}")
            if response and hasattr(response, 'error'):
                print(f"[SUPABASE_CREATE] Erro retornado: {response.error}")
            
            return None
        except Exception as e: 
            print(f"[SUPABASE_CREATE] Erro ao criar usuário Supabase: {e}")
            print(f"[SUPABASE_CREATE] Tipo de exceção: {type(e).__name__}")
            print("[SUPABASE_CREATE] Stack trace completa:")
            traceback.print_exc()
            
            # Tenta extrair mais informações do erro se possível
            if hasattr(e, 'response') and e.response:
                print(f"[SUPABASE_CREATE] Resposta da API: {e.response}")
                if hasattr(e.response, 'text'):
                    print(f"[SUPABASE_CREATE] Texto da resposta: {e.response.text}")
                if hasattr(e.response, 'status_code'):
                    print(f"[SUPABASE_CREATE] Status code: {e.response.status_code}")
            
            return None

    async def login_user(self, email: str, password: str) -> Optional[User]:
        if not self.client: print("ERRO: login_user, self.client é None."); return None
        try:
            response = self.client.auth.sign_in_with_password({"email": email, "password": password})
            if response and response.user:
                return await self.get_user_by_id(response.user.id) # Reutiliza get_user_by_id
            return None
        except Exception as e: print(f"Erro ao logar usuário Supabase: {e}"); return None

    # Table operations are now synchronous (no await for .execute())
    def add_geo_log(self, log_data: GeoLogCreate) -> bool: # Removido async
        if not self.client: print("ERRO: add_geo_log, self.client é None."); return False
        try:
            response = self.client.table("geo_login_logs").insert(log_data.model_dump()).execute() # SÍNCRONO
            return bool(response.data and len(response.data) > 0)
        except Exception as e: print(f"Erro ao adicionar geo log: {e}"); return False

    def get_all_geo_logs(self, limit: int = 100, offset: int = 0) -> list: # Removido async
        if not self.client: print("ERRO: get_all_geo_logs, self.client é None."); return []
        try:
            response = self.client.table("geo_login_logs").select("*").order("timestamp", desc=True).limit(limit).offset(offset).execute() # SÍNCRONO
            return response.data if response.data else []
        except Exception as e: print(f"Erro ao buscar geo logs: {e}"); return []

    def store_refresh_token(self, user_id: uuid.UUID, token_str: str, expires_at: datetime, parent_token_str: Optional[str] = None) -> Optional[Dict]: # Removido async
        if not self.client: print("ERRO: store_refresh_token, self.client é None."); return None
        # ... (lógica de hash)
        token_hashed = hash_token(token_str)
        parent_hash = hash_token(parent_token_str) if parent_token_str else None
        data_to_insert = {
            "user_id": str(user_id), "token_hash": token_hashed,
            "expires_at": expires_at.isoformat(), "issued_at": datetime.now(timezone.utc).isoformat()
        }
        if parent_hash: data_to_insert["parent_token_hash"] = parent_hash
        try:
            response = self.client.table("refresh_tokens").insert(data_to_insert).execute() # SÍNCRONO
            return response.data[0] if response.data and len(response.data) > 0 else None
        except Exception as e: print(f"Erro ao armazenar refresh token: {e}"); return None

    def get_refresh_token_data_by_hash(self, token_str: str) -> Optional[Dict]: # Removido async
        if not self.client: print("ERRO: get_refresh_token_data_by_hash, self.client é None."); return None
        token_hashed = hash_token(token_str)
        try:
            response = self.client.table("refresh_tokens").select("*").eq("token_hash", token_hashed).maybe_single().execute() # SÍNCRONO
            return response.data if response.data else None
        except Exception as e: print(f"Erro ao buscar refresh token por hash: {e}"); return None

    def revoke_refresh_token(self, token_db_id: uuid.UUID) -> bool: # Removido async
        if not self.client: print("ERRO: revoke_refresh_token, self.client é None."); return False
        try:
            response = self.client.table("refresh_tokens").update({"revoked": True}).eq("id", str(token_db_id)).execute() # SÍNCRONO
            return bool(response.data and len(response.data) > 0)
        except Exception as e: print(f"Erro ao revogar refresh token ID {token_db_id}: {e}"); return False

    def revoke_refresh_token_by_hash(self, token_str: str) -> bool: # Removido async
        if not self.client: print("ERRO: revoke_refresh_token_by_hash, self.client é None."); return False
        token_hashed = hash_token(token_str)
        try:
            response = self.client.table("refresh_tokens").update({"revoked": True}).eq("token_hash", token_hashed).eq("revoked", False).execute() # SÍNCRONO
            return bool(response.data and len(response.data) > 0)
        except Exception as e: print(f"Erro ao revogar refresh token por hash: {e}"); return False

    def revoke_all_user_refresh_tokens(self, user_id: uuid.UUID) -> bool: # Removido async
        if not self.client: print("ERRO: revoke_all_user_refresh_tokens, self.client é None."); return False
        try:
            response = self.client.table("refresh_tokens").update({"revoked": True}).eq("user_id", str(user_id)).eq("revoked", False).execute() # SÍNCRONO
            return True 
        except Exception as e: print(f"Erro ao revogar todos os refresh tokens para user {user_id}: {e}"); return False

    # Implementando método de log de segurança
    def log_security_event(self, event_type: str, user_id: Optional[str] = None, 
                         details: Optional[str] = None, severity: str = "info", 
                         ip: Optional[str] = None) -> bool:
        """
        Registra um evento de segurança na tabela security_events
        """
        if not self.client: 
            print("ERRO: log_security_event, self.client é None."); 
            return False
        
        try:
            event_data = {
                "event_type": event_type,
                "user_id": user_id,
                "timestamp": datetime.now().isoformat(),
                "details": details,
                "severity": severity,
                "ip_address": ip
            }
            
            response = self.client.table("security_events").insert(event_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar evento de segurança: {e}")
            return False
    
    # Métodos para o painel de segurança
    def get_security_events(self, limit: int = 100, offset: int = 0, 
                          start_date: Optional[datetime] = None,
                          filters: Optional[Dict[str, Any]] = None) -> list:
        """
        Busca eventos de segurança com filtros opcionais
        """
        if not self.client: 
            print("ERRO: get_security_events, self.client é None."); 
            return []
        
        try:
            query = self.client.table("security_events").select("*").order("timestamp", desc=True)
            
            # Aplica filtros se fornecidos
            if filters:
                for key, value in filters.items():
                    if value is not None:
                        query = query.eq(key, value)
            
            # Filtra por data se fornecida
            if start_date:
                query = query.gte("timestamp", start_date.isoformat())
            
            # Aplica paginação
            query = query.limit(limit).offset(offset)
            
            # Executa a consulta
            response = query.execute()
            return response.data if response.data else []
        except Exception as e:
            print(f"Erro ao buscar eventos de segurança: {e}")
            return []
    
    async def get_security_stats(self, start_date: datetime) -> Optional[Dict[str, Any]]:
        """Obtém estatísticas de segurança"""
        if not self.client:
            print("ERRO: get_security_stats, self.client é None.");
            return None
            
        # Implementação atual retorna None, será expandida posteriormente
        return None
        
    async def get_global_stats(self) -> Optional[Dict[str, Any]]:
        """
        Obtém estatísticas globais da plataforma.
        Retorna None se não for possível obter os dados.
        """
        if not self.client:
            print("ERRO: get_global_stats, self.client é None.")
            return None
            
        try:
            # Busca total de usuários
            users_response = await self.client.table('profiles').select('count', count='exact').execute()
            total_users = users_response.count if hasattr(users_response, 'count') else 0
            
            # Busca total de miras
            crosshairs_response = await self.client.table('crosshairs').select('count', count='exact').execute()
            total_crosshairs = crosshairs_response.count if hasattr(crosshairs_response, 'count') else 0
            
            # Busca usuários ativos hoje
            today = datetime.now().date()
            today_str = today.isoformat()
            active_users_today_response = await self.client.table('user_activity').select('count', count='exact').gte('last_active_at', today_str).execute()
            active_users_today = active_users_today_response.count if hasattr(active_users_today_response, 'count') else 0
            
            # Busca usuários ativos na última semana
            week_ago = (today - timedelta(days=7)).isoformat()
            active_users_week_response = await self.client.table('user_activity').select('count', count='exact').gte('last_active_at', week_ago).execute()
            active_users_week = active_users_week_response.count if hasattr(active_users_week_response, 'count') else 0
            
            # Busca jogos populares
            # Esta consulta seria mais complexa no Supabase real, simplificada aqui
            popular_games_response = await self.client.rpc('get_popular_games').execute()
            popular_games = popular_games_response.data if hasattr(popular_games_response, 'data') else []
            
            # Distribuição de miras por jogo
            crosshairs_per_game_response = await self.client.rpc('get_crosshairs_per_game').execute()
            crosshairs_per_game = crosshairs_per_game_response.data if hasattr(crosshairs_per_game_response, 'data') else {}
            
            # Jogos recentemente adicionados
            newest_games_response = await self.client.table('games').select('name').order('created_at', desc=True).limit(5).execute()
            newest_games = [game.get('name') for game in newest_games_response.data] if hasattr(newest_games_response, 'data') else []
            
            return {
                "total_users": total_users,
                "total_crosshairs": total_crosshairs,
                "active_users_today": active_users_today,
                "active_users_week": active_users_week,
                "popular_games": popular_games,
                "crosshairs_per_game": crosshairs_per_game,
                "newest_games": newest_games,
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"ERRO ao obter estatísticas globais: {str(e)}")
            return None
            
    async def get_user_stats(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtém estatísticas de um usuário específico.
        Retorna None se não for possível obter os dados.
        """
        if not self.client:
            print(f"ERRO: get_user_stats para usuário {user_id}, self.client é None.")
            return None
            
        try:
            # Busca total de miras do usuário
            crosshairs_response = await self.client.table('crosshairs').select('count', count='exact').eq('user_id', user_id).execute()
            total_crosshairs = crosshairs_response.count if hasattr(crosshairs_response, 'count') else 0
            
            # Busca jogos favoritos do usuário
            favorite_games_response = await self.client.rpc('get_user_favorite_games', {"user_id_param": user_id}).execute()
            favorite_games = favorite_games_response.data if hasattr(favorite_games_response, 'data') else []
            
            # Busca atividade recente
            recent_activity_response = await self.client.table('user_activity_log').select('*').eq('user_id', user_id).order('created_at', desc=True).limit(10).execute()
            recent_activity = recent_activity_response.data if hasattr(recent_activity_response, 'data') else []
            
            # Busca conquistas
            achievements_response = await self.client.table('user_achievements').select('*').eq('user_id', user_id).execute()
            achievements = achievements_response.data if hasattr(achievements_response, 'data') else []
            
            return {
                "total_crosshairs": total_crosshairs,
                "favorite_games": favorite_games,
                "recent_activity": recent_activity,
                "achievements": achievements
            }
        except Exception as e:
            print(f"ERRO ao obter estatísticas do usuário {user_id}: {str(e)}")
            return None

    def get_blocked_ips(self) -> list:
        """
        Retorna a lista de IPs bloqueados
        """
        if not self.client: 
            print("ERRO: get_blocked_ips, self.client é None."); 
            return []
        
        try:
            response = self.client.table("blocked_ips").select("*").execute()
            return response.data if response.data else []
        except Exception as e:
            print(f"Erro ao buscar IPs bloqueados: {e}")
            return []
    
    # Métodos para logging de atividade administrativa
    def log_admin_activity(self, admin_id: str, action: str, details: Optional[str] = None) -> bool:
        """
        Registra atividade de administrador
        """
        if not self.client: 
            print("ERRO: log_admin_activity, self.client é None."); 
            return False
        
        try:
            activity_data = {
                "admin_id": admin_id,
                "action": action,
                "details": details,
                "timestamp": datetime.now().isoformat()
            }
            
            response = self.client.table("admin_activity_logs").insert(activity_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar atividade de admin: {e}")
            return False
    
    def log_admin_login_success(self, ip: str, admin_id: str, username: str) -> bool:
        """
        Registra login bem-sucedido de administrador
        """
        if not self.client: 
            print("ERRO: log_admin_login_success, self.client é None."); 
            return False
        
        try:
            log_data = {
                "admin_id": admin_id,
                "ip_address": ip,
                "username": username,
                "timestamp": datetime.now().isoformat(),
                "successful": True
            }
            
            response = self.client.table("admin_login_logs").insert(log_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar login de admin: {e}")
            return False
    
    def log_admin_login_failure(self, ip: str, username: str, reason: str) -> bool:
        """
        Registra falha de login de administrador
        """
        if not self.client: 
            print("ERRO: log_admin_login_failure, self.client é None."); 
            return False
        
        try:
            log_data = {
                "ip_address": ip,
                "username": username,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
                "successful": False
            }
            
            response = self.client.table("admin_login_logs").insert(log_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar falha de login de admin: {e}")
            return False
    
    def log_admin_access_attempt(self, ip: str, user_agent: str, path: str, method: str) -> bool:
        """
        Registra tentativa de acesso ao painel de administração
        """
        if not self.client: 
            print("ERRO: log_admin_access_attempt, self.client é None."); 
            return False
        
        try:
            log_data = {
                "ip_address": ip,
                "user_agent": user_agent,
                "path": path,
                "method": method,
                "timestamp": datetime.now().isoformat()
            }
            
            response = self.client.table("admin_access_logs").insert(log_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar tentativa de acesso admin: {e}")
            return False
    
    # Método para logging de autenticação
    def log_auth_attempt(self, ip: str, username: str, successful: bool, 
                       reason: Optional[str] = None, user_id: Optional[str] = None) -> bool:
        """
        Registra tentativa de autenticação
        """
        if not self.client: 
            print("ERRO: log_auth_attempt, self.client é None."); 
            return False
        
        try:
            log_data = {
                "ip_address": ip,
                "username": username,
                "successful": successful,
                "reason": reason,
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            }
            
            response = self.client.table("auth_attempt_logs").insert(log_data).execute()
            return bool(response.data and len(response.data) > 0)
        except Exception as e:
            print(f"Erro ao registrar tentativa de autenticação: {e}")
            return False

supabase_service = SupabaseService()
