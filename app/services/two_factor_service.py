import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import secrets
import hashlib
from app.core.config import settings
from app.services.supabase_service import supabase_service
from typing import Dict, Optional, Tuple, Any

class TwoFactorService:
    """
    Serviço para gerenciar autenticação de dois fatores (2FA)
    """
    def __init__(self):
        self.issuer_name = settings.APP_NAME
        self.recovery_codes_count = 10
        self.backup_codes_length = 10
        self.totp_digits = 6
        self.totp_interval = 30  # segundos
        self.totp_window = 1  # permite 1 intervalo antes/depois para compensar desincronização de relógio
        self.backup_tokens = {}  # armazena tokens temporários para recuperação
    
    async def generate_secret(self, user_id: str, email: str) -> str:
        """
        Gera um segredo TOTP para o usuário
        """
        # Gera um segredo base32 aleatório
        secret = pyotp.random_base32()
        
        # Armazena o segredo (na prática, você armazenaria no banco de dados)
        try:
            # Adiciona o segredo ao banco de dados
            await supabase_service.client.table("user_2fa").insert({
                "user_id": user_id,
                "secret": secret,
                "enabled": False,
                "created_at": datetime.now().isoformat(),
                "last_used": None
            }).execute()
        except Exception as e:
            print(f"Erro ao armazenar segredo 2FA: {e}")
            raise
        
        return secret
    
    async def generate_qr_code(self, user_id: str, email: str) -> Tuple[str, str]:
        """
        Gera um código QR para configuração do 2FA
        """
        # Verifica se já existe um segredo
        existing = await self.get_user_secret(user_id)
        
        if existing:
            secret = existing
        else:
            # Gera um novo segredo
            secret = await self.generate_secret(user_id, email)
        
        # Gera a URL TOTP
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name=self.issuer_name)
        
        # Gera o código QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}", secret
    
    async def verify_code(self, user_id: str, code: str) -> bool:
        """
        Verifica um código TOTP
        """
        # Obtém o segredo do usuário
        secret = await self.get_user_secret(user_id)
        
        if not secret:
            return False
        
        # Verifica o código
        totp = pyotp.TOTP(secret)
        result = totp.verify(code, valid_window=self.totp_window)
        
        # Se o código for válido, atualiza o último uso
        if result:
            try:
                await supabase_service.client.table("user_2fa").update({
                    "last_used": datetime.now().isoformat(),
                    "failed_attempts": 0
                }).eq("user_id", user_id).execute()
            except Exception as e:
                print(f"Erro ao atualizar último uso 2FA: {e}")
        else:
            # Incrementa contador de falhas
            try:
                await self._increment_failed_attempts(user_id)
            except Exception as e:
                print(f"Erro ao incrementar falhas 2FA: {e}")
        
        return result
    
    async def _increment_failed_attempts(self, user_id: str) -> None:
        """
        Incrementa o contador de tentativas falhas
        """
        try:
            # Obtém as informações atuais
            response = await supabase_service.client.table("user_2fa").select("failed_attempts").eq("user_id", user_id).execute()
            
            if response.data:
                current = response.data[0].get("failed_attempts", 0) or 0
                
                # Incrementa
                await supabase_service.client.table("user_2fa").update({
                    "failed_attempts": current + 1,
                    "last_failed": datetime.now().isoformat()
                }).eq("user_id", user_id).execute()
        except Exception as e:
            print(f"Erro ao incrementar falhas 2FA: {e}")
    
    async def get_user_secret(self, user_id: str) -> Optional[str]:
        """
        Obtém o segredo TOTP do usuário
        """
        try:
            response = await supabase_service.client.table("user_2fa").select("secret").eq("user_id", user_id).execute()
            
            if response.data and len(response.data) > 0:
                return response.data[0].get("secret")
            
            return None
        except Exception as e:
            print(f"Erro ao obter segredo 2FA: {e}")
            return None
    
    async def is_2fa_enabled(self, user_id: str) -> bool:
        """
        Verifica se o 2FA está habilitado para o usuário
        """
        try:
            response = await supabase_service.client.table("user_2fa").select("enabled").eq("user_id", user_id).execute()
            
            if response.data and len(response.data) > 0:
                return response.data[0].get("enabled", False)
            
            return False
        except Exception as e:
            print(f"Erro ao verificar status 2FA: {e}")
            return False
    
    async def enable_2fa(self, user_id: str, code: str) -> Dict[str, Any]:
        """
        Habilita o 2FA para o usuário após verificação de código
        """
        # Verifica o código
        if not await self.verify_code(user_id, code):
            return {
                "success": False,
                "message": "Código inválido"
            }
        
        # Gera códigos de backup
        backup_codes = await self.generate_backup_codes(user_id)
        
        # Habilita o 2FA
        try:
            await supabase_service.client.table("user_2fa").update({
                "enabled": True,
                "activated_at": datetime.now().isoformat()
            }).eq("user_id", user_id).execute()
            
            # Registra evento de segurança
            await supabase_service.log_security_event(
                event_type="2fa_enabled",
                user_id=user_id,
                details="Autenticação de dois fatores habilitada",
                severity="info"
            )
            
            return {
                "success": True,
                "message": "2FA habilitado com sucesso",
                "backup_codes": backup_codes
            }
        except Exception as e:
            print(f"Erro ao habilitar 2FA: {e}")
            return {
                "success": False,
                "message": f"Erro ao habilitar 2FA: {str(e)}"
            }
    
    async def disable_2fa(self, user_id: str, code: str) -> Dict[str, bool]:
        """
        Desabilita o 2FA para o usuário
        """
        # Verifica o código ou backup code
        valid_code = await self.verify_code(user_id, code)
        valid_backup = await self.verify_backup_code(user_id, code)
        
        if not valid_code and not valid_backup:
            return {
                "success": False,
                "message": "Código inválido"
            }
        
        # Desabilita o 2FA
        try:
            await supabase_service.client.table("user_2fa").update({
                "enabled": False,
                "deactivated_at": datetime.now().isoformat()
            }).eq("user_id", user_id).execute()
            
            # Registra evento de segurança
            await supabase_service.log_security_event(
                event_type="2fa_disabled",
                user_id=user_id,
                details="Autenticação de dois fatores desabilitada",
                severity="warning"
            )
            
            return {
                "success": True,
                "message": "2FA desabilitado com sucesso"
            }
        except Exception as e:
            print(f"Erro ao desabilitar 2FA: {e}")
            return {
                "success": False,
                "message": f"Erro ao desabilitar 2FA: {str(e)}"
            }
    
    async def generate_backup_codes(self, user_id: str) -> list:
        """
        Gera códigos de backup para o usuário
        """
        codes = []
        
        for _ in range(self.recovery_codes_count):
            # Gera código alfanumérico
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(self.backup_codes_length))
            codes.append(code)
        
        # Armazena hashes dos códigos
        code_hashes = []
        for code in codes:
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            code_hashes.append(code_hash)
        
        # Salva os hashes no banco
        try:
            # Remove códigos antigos
            await supabase_service.client.table("user_backup_codes").delete().eq("user_id", user_id).execute()
            
            # Adiciona novos códigos
            for code_hash in code_hashes:
                await supabase_service.client.table("user_backup_codes").insert({
                    "user_id": user_id,
                    "code_hash": code_hash,
                    "used": False,
                    "created_at": datetime.now().isoformat()
                }).execute()
        except Exception as e:
            print(f"Erro ao armazenar códigos de backup: {e}")
            raise
        
        return codes
    
    async def verify_backup_code(self, user_id: str, code: str) -> bool:
        """
        Verifica um código de backup
        """
        # Gera hash do código
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        try:
            # Busca o código
            response = await supabase_service.client.table("user_backup_codes").select("*").eq("user_id", user_id).eq("code_hash", code_hash).eq("used", False).execute()
            
            if response.data and len(response.data) > 0:
                # Marca como usado
                code_id = response.data[0].get("id")
                await supabase_service.client.table("user_backup_codes").update({
                    "used": True,
                    "used_at": datetime.now().isoformat()
                }).eq("id", code_id).execute()
                
                # Registra evento de segurança
                await supabase_service.log_security_event(
                    event_type="backup_code_used",
                    user_id=user_id,
                    details="Código de backup utilizado",
                    severity="medium"
                )
                
                return True
            
            return False
        except Exception as e:
            print(f"Erro ao verificar código de backup: {e}")
            return False
    
    async def generate_recovery_token(self, user_id: str, email: str) -> str:
        """
        Gera um token de recuperação para 2FA
        """
        token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(hours=1)
        
        # Armazena o token
        self.backup_tokens[token] = {
            "user_id": user_id,
            "email": email,
            "expires": expires
        }
        
        # Registra evento de segurança
        await supabase_service.log_security_event(
            event_type="2fa_recovery_token_generated",
            user_id=user_id,
            details="Token de recuperação 2FA gerado",
            severity="medium"
        )
        
        return token
    
    async def verify_recovery_token(self, token: str) -> Optional[str]:
        """
        Verifica um token de recuperação
        """
        if token not in self.backup_tokens:
            return None
        
        token_data = self.backup_tokens[token]
        
        # Verifica expiração
        if datetime.now() > token_data["expires"]:
            # Remove token expirado
            self.backup_tokens.pop(token)
            return None
        
        # Remove token usado
        user_id = token_data["user_id"]
        self.backup_tokens.pop(token)
        
        # Registra evento de segurança
        await supabase_service.log_security_event(
            event_type="2fa_recovery_token_used",
            user_id=user_id,
            details="Token de recuperação 2FA utilizado",
            severity="medium"
        )
        
        return user_id

# Instância global do serviço
two_factor_service = TwoFactorService() 