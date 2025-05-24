from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from typing import List

def get_cors_origins() -> List[str]:
    """
    Obtém as origens permitidas para CORS
    
    Retorna origens configuradas ou retorna lista vazia em produção
    para evitar configurações inseguras por padrão
    """
    if settings.CORS_ORIGINS == "*":
        # Em produção, não permita CORS aberto
        if settings.ENVIRONMENT == "production":
            # Retorna uma lista vazia para forçar a configuração explícita
            return []
        
        # Em ambiente de desenvolvimento, permite todas as origens
        return ["*"]
    
    # Processa a string de origens separadas por vírgula
    return [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]

def setup_cors(app):
    """
    Configura o middleware CORS com as configurações adequadas de segurança
    """
    origins = get_cors_origins()
    
    # Métodos HTTP permitidos
    # Em produção, limitamos a métodos específicos
    if settings.ENVIRONMENT == "production":
        allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    else:
        allowed_methods = ["*"]
    
    # Headers permitidos
    # Em produção, limitamos a headers específicos
    if settings.ENVIRONMENT == "production":
        allowed_headers = [
            "Authorization", 
            "Content-Type", 
            "Accept", 
            "Origin", 
            "X-Requested-With",
            "X-CSRF-Token"
        ]
    else:
        allowed_headers = ["*"]
    
    # Adiciona o middleware CORS com as configurações apropriadas
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,  # Permite credenciais
        allow_methods=allowed_methods,
        allow_headers=allowed_headers,
        expose_headers=["Content-Disposition", "X-Request-ID"],
        max_age=settings.CORS_MAX_AGE,  # Tempo em segundos para cache das verificações preflight
    )
    
    return app 