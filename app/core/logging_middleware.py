# app/core/logging_middleware.py
import time
import json
import re
from typing import Optional, Any, Dict, Callable, Awaitable
import logging
from logging.handlers import RotatingFileHandler
import os
import uuid
from datetime import datetime

try:
    from starlette.middleware.base import BaseHTTPMiddleware, DispatchFunction
    CALL_NEXT_TYPE = DispatchFunction
except ImportError:
    CALL_NEXT_TYPE = Callable[[Request], Awaitable[Response]]
    from starlette.middleware.base import BaseHTTPMiddleware

from starlette.types import ASGIApp
from starlette.requests import Request
from starlette.responses import Response
from jose import jwt, JWTError

from app.core.config import settings
ADMIN_JWT_ALGORITHM = getattr(settings, 'ADMIN_JWT_ALGORITHM', settings.JWT_ALGORITHM)
USER_JWT_ALGORITHM = settings.JWT_ALGORITHM

# Configuração do logger
logger = logging.getLogger("api")
logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))

# Cria diretório de logs se não existir
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Handler para arquivo
file_handler = RotatingFileHandler(
    os.path.join(log_dir, settings.LOG_FILE),
    maxBytes=settings.LOG_MAX_SIZE,
    backupCount=settings.LOG_BACKUP_COUNT
)

# Formato do log
if settings.LOG_FORMAT == "json":
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
                "request_id": getattr(record, "request_id", None),
                "client_ip": getattr(record, "client_ip", None),
                "method": getattr(record, "method", None),
                "path": getattr(record, "path", None),
                "status_code": getattr(record, "status_code", None),
                "response_time": getattr(record, "response_time", None),
                "user_agent": getattr(record, "user_agent", None),
                "error": getattr(record, "error", None)
            }
            return json.dumps(log_data)
    
    file_handler.setFormatter(JsonFormatter())
else:
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))

logger.addHandler(file_handler)

async def get_request_body_for_log(request: Request) -> Optional[Dict[str, Any]]:
    # Omitindo a leitura real do corpo para evitar consumir o stream e por segurança/simplicidade
    return None 

def get_id_from_token(token_str: Optional[str], key: str, algorithm: str) -> Optional[str]:
    if not token_str:
        return None
    try:
        if token_str.startswith("Bearer "):
            token_str = token_str.split("Bearer ", 1)[1]
        
        payload = jwt.decode(token_str, key, algorithms=[algorithm], options={"verify_aud": False})
        return payload.get("sub") 
    except JWTError:
        return None
    except Exception:
        return None


class ApiLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware para registrar todas as requisições e respostas da API de forma segura,
    com anonimização de dados sensíveis.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.sensitive_fields = [
            "password", "senha", "pwd", "secret", "token", "authorization",
            "credit_card", "card_number", "cvv", "cvc", "ssn", "social_security",
            "key", "apikey", "api_key", "access_key", "secret_key", "private_key",
            "2fa", "otp", "code", "recovery", "backup_code", "passphrase",
            "senha", "contraseña", "segredo"
        ]
        self.sensitive_headers = [
            "authorization", "cookie", "set-cookie", "x-csrf-token", "x-api-key"
        ]

    async def dispatch(self, request: Request, call_next: CALL_NEXT_TYPE) -> Response:
        # Gera ID único para a requisição
        request_id = str(uuid.uuid4())
        
        # Adiciona request_id ao request state
        request.state.request_id = request_id
        
        # Obtém informações da requisição
        client_ip = request.client.host
        method = request.method
        path = request.url.path
        user_agent = request.headers.get("user-agent", "")
        
        # Extrai query params
        query_params = self._sanitize_data(dict(request.query_params))
        
        # Tenta extrair o corpo da requisição (para métodos POST, PUT, PATCH)
        body = None
        if method in ["POST", "PUT", "PATCH"]:
            try:
                # Salva a posição atual do corpo
                body_position = await request.body()
                
                # Reseta o corpo para leitura posterior
                await request.body()
                
                # Tenta parsear como JSON
                try:
                    json_body = json.loads(body_position.decode())
                    body = self._sanitize_data(json_body)
                except:
                    # Se não for JSON, apenas registra o tamanho
                    body = {"size_bytes": len(body_position)}
            except:
                # Ignora erros na leitura do corpo
                pass
        
        # Sanitiza headers
        headers = self._sanitize_headers(dict(request.headers))
        
        # Registra início da requisição
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "user_agent": user_agent
            }
        )
        
        # Mede tempo de resposta
        start_time = time.time()
        
        response: Optional[Response] = None 
        status_code_for_log = 500 
        process_time = 0.0
        error_in_app_message: Optional[str] = None

        try:
            response = await call_next(request)
            process_time = (time.time() - start_time) * 1000
            status_code_for_log = response.status_code
            
            # Calcula tempo de resposta
            response_time = time.time() - start_time
            
            # Registra sucesso
            logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "method": method,
                    "path": path,
                    "status_code": status_code_for_log,
                    "response_time": response_time,
                    "user_agent": user_agent
                }
            )
            
            # Adiciona request_id ao header da resposta
            response.headers["X-Request-ID"] = request_id
            
            # Extrai ID de usuário e admin, se disponíveis
            user_id = getattr(request.state, "user_id", None)
            admin_id = getattr(request.state, "admin_id", None)
            
            # Registra informações da requisição
            if settings.API_LOGGING_ENABLED:
                # Monta payload
                log_data = {
                    "request_id": request_id,
                    "timestamp": datetime.now().isoformat(),
                    "method": method,
                    "path": path,
                    "status_code": status_code_for_log,
                    "process_time": round(process_time, 2),  # em ms
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "query_params": query_params,
                    "user_id": str(user_id) if user_id else None,
                    "admin_id": str(admin_id) if admin_id else None,
                    "headers": headers,
                    "body": body,
                    "response_size": int(response.headers.get("content-length", 0)),
                    "referer": request.headers.get("referer"),
                    "error": None
                }
                
                # Adiciona informação de dispositivo e SO se disponível
                if user_agent:
                    device_info = self._extract_device_info(user_agent)
                    if device_info:
                        log_data["device_info"] = device_info
                
                # Enviado ao serviço de logging
                try:
                    await supabase_service.log_api_request(**log_data)
                except Exception as e:
                    # Falha silenciosa se o logging falhar
                    print(f"Erro ao registrar log de API: {str(e)}")
            
            # Adiciona headers de segurança
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["X-Frame-Options"] = "DENY"
            
            return response
            
        except Exception as e:
            # Calcula tempo até o erro
            process_time = (time.time() - start_time) * 1000
            error_in_app_message = str(e)
            status_code_for_log = 500 
            print(f"ERRO NA APLICAÇÃO DURANTE REQUEST (Middleware): {e} para {request.method} {request.url.path}")
            
            # Calcula tempo de resposta
            response_time = time.time() - start_time
            
            # Registra erro
            logger.error(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "method": method,
                    "path": path,
                    "status_code": status_code_for_log,
                    "response_time": response_time,
                    "user_agent": user_agent,
                    "error": error_in_app_message
                },
                exc_info=True
            )
            
            # Registra informações do erro
            if settings.API_LOGGING_ENABLED:
                try:
                    error_data = {
                        "request_id": request_id,
                        "timestamp": datetime.now().isoformat(),
                        "method": method,
                        "path": path,
                        "status_code": 500,  # Erro interno
                        "process_time": round(process_time, 2),
                        "ip": client_ip,
                        "user_agent": user_agent,
                        "query_params": query_params,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }
                    
                    await supabase_service.log_api_error(**error_data)
                except:
                    # Falha silenciosa se o logging falhar
                    pass
            
            # Re-lança a exceção
            raise

        if response is None: # Cenário de fallback improvável
            print(f"AVISO: Nenhuma resposta foi gerada por call_next para {request.method} {request.url.path}. Retornando 500.")
            response = Response("Internal server error after middleware processing.", status_code=500)
            status_code_for_log = 500
            if not error_in_app_message: error_in_app_message = "No response from application stack."

        user_id_from_token: Optional[str] = None
        admin_id_from_token: Optional[str] = None
        auth_header = request.headers.get("authorization")

        if auth_header:
            admin_id_from_token = get_id_from_token(auth_header, settings.JWT_PUBLIC_KEY_CONTENT, ADMIN_JWT_ALGORITHM)
            if not admin_id_from_token:
                user_id_from_token = get_id_from_token(auth_header, settings.JWT_PUBLIC_KEY_CONTENT, USER_JWT_ALGORITHM)
        
        log_entry: Dict[str, Any] = {
            "method": request.method, "path": request.url.path, "status_code": status_code_for_log,
            "client_host": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent"), "user_id": user_id_from_token,
            "admin_id": admin_id_from_token, "request_body": request_body_log, 
            "processing_time_ms": round(process_time, 2), "error_message": error_in_app_message,
            "tags": ["api_request"]
        }
        
        path_for_tags = request.url.path
        if path_for_tags.startswith(f"{settings.API_V1_STR}/admin-panel"): log_entry["tags"].append("admin_panel_api")
        elif path_for_tags.startswith(f"{settings.API_V1_STR}/auth"): log_entry["tags"].append("user_auth_api")
        elif path_for_tags.startswith(f"{settings.API_V1_STR}/4L8FJYy4eWGL_admin"): log_entry["tags"].append("original_admin_api")

        if status_code_for_log >= 500: log_entry["tags"].append("error_server")
        elif status_code_for_log >= 400: log_entry["tags"].append("error_client")
        
        try:
            from app.services.supabase_service import supabase_service # Importar aqui para tentar mitigar startup issues
            
            if supabase_service and supabase_service.client:
                current_user_id = log_entry.get("user_id")
                if current_user_id and not isinstance(current_user_id, str): log_entry["user_id"] = str(current_user_id)
                elif current_user_id is None: log_entry["user_id"] = None
                current_admin_id = log_entry.get("admin_id")
                if current_admin_id and not isinstance(current_admin_id, str): log_entry["admin_id"] = str(current_admin_id)
                elif current_admin_id is None: log_entry["admin_id"] = None
                if log_entry.get("request_body") is None: log_entry["request_body"] = None 
                
                print(f"DEBUG LOGGING - Payload para Inserção em api_logs: {json.dumps(log_entry, default=str)}")
                
                # REMOVIDO 'await' DA LINHA ABAIXO
                supabase_service.client.table("api_logs").insert(log_entry).execute()
            else:
                print("AVISO DE LOGGING: Cliente Supabase não disponível, log da API não será salvo.")
        except Exception as log_e:
            print(f"ERRO CRÍTICO AO SALVAR LOG DA API: {log_e}")
            if hasattr(log_e, 'message') and log_e.message: print(f"   Detalhe do APIError (se houver): {log_e.message}")
            if hasattr(log_e, 'hint') and log_e.hint: print(f"   Dica do APIError (se houver): {log_e.hint}")
            if hasattr(log_e, 'details') and log_e.details: print(f"   Detalhes adicionais do APIError (se houver): {log_e.details}")
            import traceback
            traceback.print_exc()
        return response

    def _sanitize_headers(self, headers: dict) -> dict:
        """Remove headers sensíveis do log"""
        sensitive_headers = {
            "authorization",
            "cookie",
            "set-cookie",
            "x-csrf-token",
            "x-api-key"
        }
        
        return {
            k: v for k, v in headers.items()
            if k.lower() not in sensitive_headers
        }

    def _sanitize_body(self, body: str) -> str:
        """Remove dados sensíveis do corpo da requisição"""
        if not body:
            return body
            
        try:
            data = json.loads(body)
            
            # Lista de campos sensíveis
            sensitive_fields = {
                "password",
                "token",
                "api_key",
                "secret",
                "credit_card",
                "cvv",
                "ssn"
            }
            
            # Remove campos sensíveis
            for field in sensitive_fields:
                if field in data:
                    data[field] = "***REDACTED***"
                    
            return json.dumps(data)
        except:
            return "***BINARY DATA***"
