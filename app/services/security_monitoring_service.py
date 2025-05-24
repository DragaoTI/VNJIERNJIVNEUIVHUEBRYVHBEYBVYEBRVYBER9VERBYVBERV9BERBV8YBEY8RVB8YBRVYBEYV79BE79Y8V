from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import asyncio
import json
from collections import defaultdict
import hashlib
import ipaddress
from app.services.supabase_service import supabase_service
from app.core.config import settings

class SecurityMonitoringService:
    """
    Serviço para monitoramento de segurança e detecção de comportamentos suspeitos
    """
    def __init__(self):
        # Cache de IPs suspeitos (IP -> {contagem, última_atividade, score})
        self.suspicious_ips = {}
        
        # Cache de atividades por usuário (user_id -> {ações recentes})
        self.user_activities = {}
        
        # Cache de alertas recentes
        self.recent_alerts = []
        
        # Limiares
        self.max_failed_logins = 5
        self.brute_force_window_minutes = 15
        self.admin_action_window_minutes = 10
        self.max_admin_actions = 20
        self.unusual_geo_score_threshold = 80
        
        # Lista de IPs bloqueados permanentemente
        self.blocked_ips = set()
        
        # Lista de IPs confiáveis
        self.trusted_ips = set()
        self.trusted_networks = []
        
        # Carrega IPs confiáveis das configurações
        self._load_trusted_ips()
    
    def _load_trusted_ips(self):
        """
        Carrega IPs e redes confiáveis das configurações
        """
        if hasattr(settings, "TRUSTED_IPS") and settings.TRUSTED_IPS:
            for ip in settings.TRUSTED_IPS.split(","):
                ip = ip.strip()
                self.trusted_ips.add(ip)
        
        if hasattr(settings, "TRUSTED_NETWORKS") and settings.TRUSTED_NETWORKS:
            for network in settings.TRUSTED_NETWORKS.split(","):
                try:
                    self.trusted_networks.append(ipaddress.ip_network(network.strip()))
                except (ValueError, Exception):
                    continue
    
    def is_ip_trusted(self, ip: str) -> bool:
        """
        Verifica se um IP está na lista de confiáveis
        """
        if ip in self.trusted_ips:
            return True
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.trusted_networks:
                if ip_obj in network:
                    return True
        except (ValueError, Exception):
            pass
            
        return False
    
    def is_ip_blocked(self, ip: str) -> bool:
        """
        Verifica se um IP está bloqueado
        """
        return ip in self.blocked_ips
    
    async def register_login_attempt(self, ip: str, success: bool, user_id: Optional[str] = None) -> None:
        """
        Registra uma tentativa de login e verifica possíveis ataques de força bruta
        """
        # Ignora IPs confiáveis
        if self.is_ip_trusted(ip):
            return
        
        # Obtém ou cria entrada para o IP
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {
                "failed_logins": 0,
                "last_attempt": datetime.now(),
                "score": 0,
                "user_ids": set()
            }
        
        # Atualiza dados
        ip_data = self.suspicious_ips[ip]
        
        if not success:
            ip_data["failed_logins"] += 1
            ip_data["score"] += 10  # Aumenta o score de suspeita
        else:
            ip_data["failed_logins"] = 0  # Reset ao ter sucesso
            ip_data["score"] = max(0, ip_data["score"] - 5)  # Diminui o score
        
        ip_data["last_attempt"] = datetime.now()
        
        if user_id:
            ip_data["user_ids"].add(user_id)
        
        # Verifica força bruta
        if ip_data["failed_logins"] >= self.max_failed_logins:
            # Bloqueia temporariamente
            await self.block_ip_temporary(ip, "Possível ataque de força bruta")
        
        # Verifica tentativas em múltiplas contas
        if len(ip_data["user_ids"]) > 3 and not success:
            await self.raise_security_alert(
                "multiple_accounts_attempt",
                f"Tentativas de login em {len(ip_data['user_ids'])} contas diferentes a partir do mesmo IP",
                "high",
                ip=ip,
                user_ids=list(ip_data["user_ids"]),
                failed_count=ip_data["failed_logins"]
            )
    
    async def register_admin_action(self, admin_id: str, ip: str, action: str, target_id: Optional[str] = None) -> None:
        """
        Registra uma ação administrativa e detecta possíveis anomalias
        """
        # Ignora IPs confiáveis
        if self.is_ip_trusted(ip):
            return
        
        # Obtém ou cria entrada para o admin
        if admin_id not in self.user_activities:
            self.user_activities[admin_id] = {
                "actions": [],
                "ips": set(),
                "last_action_time": None
            }
        
        admin_data = self.user_activities[admin_id]
        
        # Adiciona ação
        now = datetime.now()
        admin_data["actions"].append({
            "action": action,
            "time": now,
            "ip": ip,
            "target_id": target_id
        })
        
        admin_data["ips"].add(ip)
        admin_data["last_action_time"] = now
        
        # Limpa ações antigas
        cutoff = now - timedelta(minutes=self.admin_action_window_minutes)
        admin_data["actions"] = [a for a in admin_data["actions"] if a["time"] > cutoff]
        
        # Verifica múltiplas ações em curto período
        if len(admin_data["actions"]) > self.max_admin_actions:
            await self.raise_security_alert(
                "admin_action_burst",
                f"Muitas ações administrativas ({len(admin_data['actions'])}) em um curto período",
                "high",
                admin_id=admin_id,
                ip=ip,
                actions=[(a["action"], a["time"].isoformat()) for a in admin_data["actions"][-10:]]
            )
        
        # Verifica múltiplos IPs para o mesmo admin
        if len(admin_data["ips"]) > 1:
            await self.raise_security_alert(
                "admin_multiple_ips",
                f"Ações administrativas de {len(admin_data['ips'])} IPs diferentes para o mesmo admin",
                "high",
                admin_id=admin_id,
                ips=list(admin_data["ips"]),
                action_count=len(admin_data["actions"])
            )
    
    async def register_geo_anomaly(self, user_id: str, ip: str, country: str, city: str, score: int) -> None:
        """
        Registra uma anomalia geográfica detectada
        """
        if score >= self.unusual_geo_score_threshold:
            await self.raise_security_alert(
                "geo_anomaly",
                f"Acesso a partir de localização incomum: {city}, {country}",
                "medium" if score < 90 else "high",
                user_id=user_id,
                ip=ip,
                country=country,
                city=city,
                anomaly_score=score
            )
    
    async def register_api_anomaly(self, ip: str, path: str, method: str, status_code: int, user_agent: str, user_id: Optional[str] = None) -> None:
        """
        Registra uma anomalia na API (muitas requisições, padrões incomuns, etc)
        """
        # Ignora IPs confiáveis
        if self.is_ip_trusted(ip):
            return
        
        # Verifica padrões suspeitos no caminho
        suspicious_patterns = [
            "/admin", "/config", "/login", "/wp-", "/phpmyadmin", "/.env",
            "/config.php", "/wp-login", "/.git", "/xmlrpc.php", "/shell",
            "/passwd", "/config.json", "/api/v1/admin", "/.aws", "/.bash_history"
        ]
        
        is_suspicious_path = any(pattern in path for pattern in suspicious_patterns) and status_code >= 400
        
        if is_suspicious_path:
            await self.raise_security_alert(
                "suspicious_path_access",
                f"Tentativa de acesso a caminho suspeito: {path}",
                "medium",
                ip=ip,
                path=path,
                method=method,
                status_code=status_code,
                user_agent=user_agent,
                user_id=user_id
            )
        
        # Verifica status code 403/401 repetidos
        if status_code in [401, 403]:
            if ip not in self.suspicious_ips:
                self.suspicious_ips[ip] = {
                    "forbidden_count": 1,
                    "last_forbidden": datetime.now(),
                    "score": 5
                }
            else:
                data = self.suspicious_ips[ip]
                data["forbidden_count"] = data.get("forbidden_count", 0) + 1
                data["last_forbidden"] = datetime.now()
                data["score"] = data.get("score", 0) + 5
                
                # Verifica muitos 403/401 em sequência
                if data["forbidden_count"] >= 10:
                    await self.raise_security_alert(
                        "repeated_auth_failures",
                        f"Muitos erros de autorização consecutivos: {data['forbidden_count']}",
                        "medium",
                        ip=ip,
                        path=path,
                        status_codes=[401, 403],
                        user_agent=user_agent
                    )
                    
                    # Reset contador
                    data["forbidden_count"] = 0
    
    async def block_ip_temporary(self, ip: str, reason: str, duration_minutes: int = 30) -> None:
        """
        Bloqueia um IP temporariamente e registra o evento
        """
        # Adiciona à lista de bloqueados
        self.blocked_ips.add(ip)
        
        # Registra o bloqueio
        await self.raise_security_alert(
            "ip_blocked",
            f"IP bloqueado temporariamente: {reason}",
            "high",
            ip=ip,
            reason=reason,
            duration_minutes=duration_minutes
        )
        
        # Agenda a remoção do bloqueio após o tempo definido
        asyncio.create_task(self._unblock_ip_after_timeout(ip, duration_minutes))
    
    async def _unblock_ip_after_timeout(self, ip: str, minutes: int) -> None:
        """
        Remove um IP da lista de bloqueados após o tempo especificado
        """
        await asyncio.sleep(minutes * 60)
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
    
    async def raise_security_alert(self, alert_type: str, message: str, severity: str, **details) -> None:
        """
        Levanta um alerta de segurança e o registra
        """
        now = datetime.now()
        
        # Gera um ID único para o alerta
        alert_id = hashlib.sha256(f"{alert_type}:{now.isoformat()}:{json.dumps(details)}".encode()).hexdigest()
        
        # Cria o alerta
        alert = {
            "id": alert_id,
            "type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": now.isoformat(),
            "details": details
        }
        
        # Adiciona aos alertas recentes
        self.recent_alerts.append(alert)
        
        # Mantém apenas os 100 alertas mais recentes
        if len(self.recent_alerts) > 100:
            self.recent_alerts = self.recent_alerts[-100:]
        
        # Registra no Supabase
        try:
            await supabase_service.log_security_event(
                event_type=alert_type,
                ip=details.get("ip"),
                user_id=details.get("user_id"),
                admin_id=details.get("admin_id"),
                details=message,
                severity=severity,
                **details
            )
        except Exception as e:
            print(f"Erro ao registrar alerta de segurança: {str(e)}")
    
    async def get_recent_alerts(self, limit: int = 20, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retorna os alertas recentes, opcionalmente filtrados por severidade
        """
        if severity:
            filtered = [a for a in self.recent_alerts if a["severity"] == severity]
            return filtered[-limit:]
        
        return self.recent_alerts[-limit:]
    
    async def cleanup_old_data(self) -> None:
        """
        Limpa dados antigos dos caches
        """
        now = datetime.now()
        
        # Limpa IPs suspeitos inativos
        for ip in list(self.suspicious_ips.keys()):
            last_activity = self.suspicious_ips[ip].get("last_attempt") or self.suspicious_ips[ip].get("last_forbidden")
            if last_activity and (now - last_activity).total_seconds() > 86400:  # 24 horas
                self.suspicious_ips.pop(ip)
        
        # Limpa atividades de usuários
        for user_id in list(self.user_activities.keys()):
            last_action = self.user_activities[user_id].get("last_action_time")
            if last_action and (now - last_action).total_seconds() > 86400:  # 24 horas
                self.user_activities.pop(user_id)

# Instância global do serviço
security_monitoring_service = SecurityMonitoringService() 