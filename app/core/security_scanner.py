from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import re
import json
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime
import secrets
import hashlib
from app.core.config import settings
from app.services import supabase_service

class SecurityScannerMiddleware(BaseHTTPMiddleware):
    """
    Middleware para detectar e bloquear ataques e tentativas de exploração de vulnerabilidades
    """
    def __init__(self, app):
        super().__init__(app)
        self.blocked_ips = set()
        self.suspicious_activity = {}
        self.honeypot_tokens = {}
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",
            r"javascript:",
            r"<iframe[^>]*>",
            r"<img[^>]*onerror=",
            r"<svg[^>]*on\w+=",
            r"document\.cookie",
            r"fetch\s*\(",
            r"alert\s*\(",
            r"eval\s*\(",
            r"Function\s*\(",
            r"\"\s*\+\s*\"",
            r"window\.location",
            r"base64",
        ]
        
        self.sqli_patterns = [
            r";\s*SELECT\s+",
            r";\s*INSERT\s+",
            r";\s*UPDATE\s+",
            r";\s*DELETE\s+",
            r";\s*DROP\s+",
            r";\s*CREATE\s+",
            r";\s*ALTER\s+",
            r"UNION\s+SELECT",
            r"SELECT\s+.*\s+FROM",
            r"'(\s+)OR(\s+).*(=|>|<)",
            r"\bOR\b.*\b(TRUE|1|1=1)\b",
            r"\bAND\b.*\b(FALSE|0|1=0)\b",
            r"--\s+",
            r"#\s*$",
            r"/\*.*\*/",
            r"@@version",
            r"information_schema",
            r"pg_tables",
            r"WAITFOR\s+DELAY",
            r"BENCHMARK\s*\(",
            r"SLEEP\s*\(",
        ]
        
        self.nosqli_patterns = [
            r"\{\s*\$where\s*:",
            r"\{\s*\$regex\s*:",
            r"\{\s*\$gt\s*:",
            r"\{\s*\$lt\s*:",
            r"\{\s*\$ne\s*:",
            r"\{\s*\$or\s*:",
            r"\{\s*\$and\s*:",
            r"\$\{.*\}",
        ]
        
        self.path_traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"\.\.%2f",
            r"%2e\.%2f",
            r"..;\/",
            r"\.\.%252f",
            r"\/etc\/passwd",
            r"c:\\windows\\",
            r"\/windows\/system32",
            r"%00",
            r"file:\/\/",
        ]
        
        self.command_injection_patterns = [
            r";\s*\w+",
            r"\|\s*\w+",
            r"`.*`",
            r"\$\(.*\)",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
            r">\s*\w+\.+\w+",
            r">>\s*\w+\.+\w+",
            r"<\s*\w+\.+\w+",
            r"ping\s+",
            r"curl\s+",
            r"wget\s+",
            r"nc\s+",
            r"netcat\s+",
            r"bash\s+",
            r"cmd\s+",
            r"powershell\s+",
            r"nslookup\s+",
            r"dig\s+",
            r"traceroute\s+",
            r"\/bin\/",
        ]
        
        self.suspicious_uas = [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"masscan",
            r"zmeu",
            r"scanbot",
            r"acunetix",
            r"nessus",
            r"arachni",
            r"metasploit",
            r"w3af",
            r"dirbuster",
            r"wfuzz",
            r"gobuster",
            r"zap",
            r"burpsuite",
            r"paros",
            r"whatweb",
            r"autopsy",
            r"harvester",
            r"python-requests",
            r"go-http-client",
            r"curl",
            r"wget",
        ]
        
        # Lista de IPs permitidos (whitelist)
        self.allowed_ips = []
        if hasattr(settings, "ALLOWED_IPS") and settings.ALLOWED_IPS:
            for ip_range in settings.ALLOWED_IPS.split(","):
                try:
                    self.allowed_ips.append(ipaddress.ip_network(ip_range.strip()))
                except ValueError:
                    pass
        
        # Criar honeypot token para detecção de bots
        self.create_honeypot_tokens()
    
    def create_honeypot_tokens(self):
        # Gera tokens aleatórios para serem usados como honeypots
        for i in range(5):
            token = secrets.token_urlsafe(16)
            self.honeypot_tokens[token] = {
                "created_at": datetime.now(),
                "hits": 0
            }
    
    async def dispatch(self, request: Request, call_next):
        # Verifica se o IP está bloqueado
        client_ip = request.client.host
        
        # Verifica se o IP está na whitelist
        if self.allowed_ips:
            try:
                client_ip_obj = ipaddress.ip_address(client_ip)
                if any(client_ip_obj in ip_range for ip_range in self.allowed_ips):
                    # IP está na whitelist, permite a requisição
                    return await call_next(request)
            except ValueError:
                pass
        
        # Verifica se o IP está bloqueado
        if client_ip in self.blocked_ips:
            return self.block_request(client_ip, "IP previamente bloqueado", "blocked_ip")
        
        # Verifica atividade suspeita prévia
        if client_ip in self.suspicious_activity:
            if self.suspicious_activity[client_ip]["score"] >= 100:
                self.blocked_ips.add(client_ip)
                return self.block_request(client_ip, "Múltiplas atividades suspeitas", "multiple_suspicious")
        
        # Analisa a requisição
        is_suspicious, reason, score, attack_type = await self.scan_request(request)
        
        if is_suspicious:
            # Registra atividade suspeita
            await self.record_suspicious_activity(client_ip, reason, score, attack_type, request)
            
            # Verifica se deve bloquear
            if score >= 100:
                self.blocked_ips.add(client_ip)
                return self.block_request(client_ip, reason, attack_type)
        
        # Adiciona honeypot tokens na resposta para detectar bots
        response = await call_next(request)
        
        # Adiciona headers de segurança em todas as respostas
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Adiciona honeypot token na resposta (usado para detectar bots que seguem links automaticamente)
        if hasattr(settings, "ENABLE_HONEYPOT") and settings.ENABLE_HONEYPOT:
            honeypot_token = secrets.choice(list(self.honeypot_tokens.keys()))
            response.headers["X-Resource-ID"] = honeypot_token
        
        return response
    
    async def scan_request(self, request: Request) -> tuple:
        score = 0
        attack_types = []
        reasons = []
        
        # Verifica User-Agent
        ua = request.headers.get("user-agent", "")
        if await self.check_suspicious_ua(ua):
            score += 50
            attack_types.append("suspicious_ua")
            reasons.append(f"User-Agent suspeito: {ua[:30]}...")
        
        # Verifica URL para path traversal
        url_path = request.url.path
        if await self.check_path_traversal(url_path):
            score += 80
            attack_types.append("path_traversal")
            reasons.append(f"Possível path traversal: {url_path[:30]}...")
        
        # Verifica parâmetros de query para injeções
        params = dict(request.query_params)
        if params:
            for param, value in params.items():
                # Verifica XSS
                if await self.check_xss(value):
                    score += 70
                    attack_types.append("xss")
                    reasons.append(f"Possível XSS em parâmetro {param}")
                
                # Verifica SQL Injection
                if await self.check_sqli(value):
                    score += 90
                    attack_types.append("sqli")
                    reasons.append(f"Possível SQLi em parâmetro {param}")
                
                # Verifica NoSQL Injection
                if await self.check_nosqli(value):
                    score += 90
                    attack_types.append("nosqli")
                    reasons.append(f"Possível NoSQLi em parâmetro {param}")
                
                # Verifica Command Injection
                if await self.check_command_injection(value):
                    score += 100
                    attack_types.append("command_injection")
                    reasons.append(f"Possível injeção de comando em parâmetro {param}")
        
        # Verifica body para injeções (se for POST/PUT/PATCH)
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                try:
                    # Tenta parsear como JSON
                    body = json.loads(body_bytes.decode())
                    if isinstance(body, dict):
                        for key, value in body.items():
                            if isinstance(value, str):
                                # Verifica XSS
                                if await self.check_xss(value):
                                    score += 70
                                    attack_types.append("xss")
                                    reasons.append(f"Possível XSS em body {key}")
                                
                                # Verifica SQL Injection
                                if await self.check_sqli(value):
                                    score += 90
                                    attack_types.append("sqli")
                                    reasons.append(f"Possível SQLi em body {key}")
                                
                                # Verifica NoSQL Injection
                                if await self.check_nosqli(value):
                                    score += 90
                                    attack_types.append("nosqli")
                                    reasons.append(f"Possível NoSQLi em body {key}")
                                
                                # Verifica Command Injection
                                if await self.check_command_injection(value):
                                    score += 100
                                    attack_types.append("command_injection")
                                    reasons.append(f"Possível injeção de comando em body {key}")
                except:
                    # Se não for JSON, verifica como form data
                    body_str = body_bytes.decode()
                    # Verifica XSS
                    if await self.check_xss(body_str):
                        score += 70
                        attack_types.append("xss")
                        reasons.append("Possível XSS no corpo da requisição")
                    
                    # Verifica SQL Injection
                    if await self.check_sqli(body_str):
                        score += 90
                        attack_types.append("sqli")
                        reasons.append("Possível SQLi no corpo da requisição")
                    
                    # Verifica NoSQL Injection
                    if await self.check_nosqli(body_str):
                        score += 90
                        attack_types.append("nosqli")
                        reasons.append("Possível NoSQLi no corpo da requisição")
                    
                    # Verifica Command Injection
                    if await self.check_command_injection(body_str):
                        score += 100
                        attack_types.append("command_injection")
                        reasons.append("Possível injeção de comando no corpo da requisição")
            except:
                # Erro ao ler body
                pass
        
        # Verifica se há honeypot tokens na requisição
        for token in self.honeypot_tokens:
            if token in url_path or token in request.headers.get("referer", ""):
                score += 100
                attack_types.append("honeypot_access")
                reasons.append("Acesso a recurso honeypot")
                self.honeypot_tokens[token]["hits"] += 1
        
        # Determina o tipo de ataque principal
        attack_type = "suspicious_request"
        if attack_types:
            attack_type = attack_types[0]
        
        # Formata a razão
        reason = "; ".join(reasons) if reasons else "Padrões suspeitos detectados"
        
        return score > 0, reason, score, attack_type
    
    async def record_suspicious_activity(self, ip: str, reason: str, score: int, attack_type: str, request: Request):
        now = datetime.now()
        
        # Atualiza contador de atividades suspeitas
        if ip not in self.suspicious_activity:
            self.suspicious_activity[ip] = {
                "first_seen": now,
                "last_seen": now,
                "score": score,
                "count": 1,
                "attacks": {attack_type: 1}
            }
        else:
            self.suspicious_activity[ip]["last_seen"] = now
            self.suspicious_activity[ip]["score"] += score
            self.suspicious_activity[ip]["count"] += 1
            
            if attack_type in self.suspicious_activity[ip]["attacks"]:
                self.suspicious_activity[ip]["attacks"][attack_type] += 1
            else:
                self.suspicious_activity[ip]["attacks"][attack_type] = 1
        
        # Registra no log de segurança
        try:
            await supabase_service.log_security_event(
                event_type="security_scanner_alert",
                ip=ip,
                user_agent=request.headers.get("user-agent", ""),
                path=str(request.url),
                method=request.method,
                details=reason,
                severity="high" if score >= 70 else "medium",
                attack_type=attack_type,
                score=score,
                headers=dict(request.headers),
                params=dict(request.query_params)
            )
        except Exception as e:
            print(f"Erro ao registrar evento de segurança: {str(e)}")
    
    def block_request(self, ip: str, reason: str, attack_type: str):
        # Bloqueia a requisição e retorna uma resposta de erro
        return Response(
            status_code=status.HTTP_403_FORBIDDEN,
            content=json.dumps({
                "detail": "Acesso bloqueado por motivos de segurança"
            }),
            media_type="application/json"
        )
    
    async def check_suspicious_ua(self, user_agent: str) -> bool:
        # Verifica se o User-Agent contém padrões suspeitos
        if not user_agent:
            return True  # UA vazio é suspeito
        
        for pattern in self.suspicious_uas:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        
        return False
    
    async def check_xss(self, value: str) -> bool:
        # Verifica padrões de XSS
        if not value or not isinstance(value, str):
            return False
        
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    async def check_sqli(self, value: str) -> bool:
        # Verifica padrões de SQL Injection
        if not value or not isinstance(value, str):
            return False
        
        for pattern in self.sqli_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    async def check_nosqli(self, value: str) -> bool:
        # Verifica padrões de NoSQL Injection
        if not value or not isinstance(value, str):
            return False
        
        for pattern in self.nosqli_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    async def check_path_traversal(self, value: str) -> bool:
        # Verifica padrões de Path Traversal
        if not value or not isinstance(value, str):
            return False
        
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    async def check_command_injection(self, value: str) -> bool:
        # Verifica padrões de Command Injection
        if not value or not isinstance(value, str):
            return False
        
        for pattern in self.command_injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False 