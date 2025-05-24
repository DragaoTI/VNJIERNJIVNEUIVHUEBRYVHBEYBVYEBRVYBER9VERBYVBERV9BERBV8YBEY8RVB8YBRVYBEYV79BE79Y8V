import os
import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List, Dict, Any, Union
from datetime import timedelta
import json

class Settings(BaseSettings):
    # Configurações básicas da aplicação
    APP_NAME: str = "CrosshairLab API"
    APP_DESCRIPTION: str = "API do CrosshairLab"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # Prefixo da API
    API_V1_STR: str = "/api/v1"
    
    # Configurações de segurança
    SECRET_KEY: str = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "RS256"  # Algoritmo mais seguro que HS256
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hora
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 dias
    ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 horas
    ENCRYPTION_KEY: Optional[str] = os.environ.get("ENCRYPTION_KEY")
    
    # Configurações de segurança avançadas
    PASSWORD_MIN_LENGTH: int = 10
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_COOLDOWN_MINUTES: int = 15
    ADMIN_MAX_INACTIVITY_DAYS: int = 30
    SESSION_MAX_AGE: int = 86400  # 24 horas em segundos
    MAX_ADMINS: int = 10
    
    # Caminhos de chaves RSA para JWT
    JWT_PRIVATE_KEY_PATH: Optional[str] = os.environ.get("JWT_PRIVATE_KEY_PATH", "rsa_private_key.pem")
    JWT_PUBLIC_KEY_PATH: Optional[str] = os.environ.get("JWT_PUBLIC_KEY_PATH", "rsa_public_key.pem")
    JWT_PRIVATE_KEY_CONTENT: Optional[str] = None
    JWT_PUBLIC_KEY_CONTENT: Optional[str] = None
    
    # URLs e rotas especiais
    ADMIN_PANEL_URL: str = "/admin-panel"
    FRONTEND_URL: str = "https://crosshairlab.com"
    
    # Configuração de CORS
    CORS_ORIGINS: str = "*"
    CORS_MAX_AGE: int = 3600  # 1 hora
    
    # Rate Limiting
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_SIGNUP: str = "3/minute"
    RATE_LIMIT_ADMIN: str = "120/minute"
    RATE_LIMIT_2FA: str = "10/minute"
    
    # Configuração de IPs e redes
    ALLOWED_ADMIN_IP_RANGES: Optional[str] = None  # Lista de IPs/redes separados por vírgula
    TRUSTED_IPS: Optional[str] = None  # IPs confiáveis separados por vírgula
    TRUSTED_NETWORKS: Optional[str] = None  # Redes confiáveis (CIDR) separadas por vírgula
    
    # Configurações de geolocalização
    MAXMIND_LICENSE_KEY: Optional[str] = None
    MAXMIND_ACCOUNT_ID: Optional[str] = None
    
    # Configurações de monitoramento e logging
    API_LOGGING_ENABLED: bool = True
    SENTRY_DSN: Optional[str] = None
    LOG_LEVEL: str = "INFO"
    ENABLE_PERFORMANCE_MONITORING: bool = True
    
    # Configurações de segurança para respostas e requisições
    ENABLE_HONEYPOT: bool = True
    SANITIZE_INPUTS: bool = True
    ENABLE_SECURITY_HEADERS: bool = True
    SECURITY_SCANNER_ENABLED: bool = True
    
    # Configurações de banco de dados
    DATABASE_URL: Optional[str] = None
    
    # Configurações do Supabase
    SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY", "")
    SUPABASE_JWT_SECRET: Optional[str] = os.environ.get("SUPABASE_JWT_SECRET")
    
    # Configurações de e-mail
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[str] = None
    EMAILS_FROM_NAME: Optional[str] = None
    
    # Configurações de armazenamento
    S3_BUCKET: Optional[str] = None
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_REGION: Optional[str] = None
    
    # Configurações do Stripe
    STRIPE_API_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    
    # Cache e Redis
    REDIS_URL: Optional[str] = None
    CACHE_TTL: int = 3600  # 1 hora
    
    # Configuração para carregar variáveis de ambiente de arquivo .env
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        
        # Carrega conteúdo das chaves RSA, se os caminhos existirem
        self._load_jwt_keys()
    
    def _load_jwt_keys(self) -> None:
        """
        Carrega o conteúdo das chaves RSA para JWT
        """
        # Tenta carregar a chave privada
        if not self.JWT_PRIVATE_KEY_CONTENT and self.JWT_PRIVATE_KEY_PATH:
            try:
                with open(self.JWT_PRIVATE_KEY_PATH, "r") as f:
                    self.JWT_PRIVATE_KEY_CONTENT = f.read()
            except FileNotFoundError:
                # Se o arquivo não existir, usa o valor da variável de ambiente
                self.JWT_PRIVATE_KEY_CONTENT = os.environ.get("JWT_PRIVATE_KEY")
        
        # Tenta carregar a chave pública
        if not self.JWT_PUBLIC_KEY_CONTENT and self.JWT_PUBLIC_KEY_PATH:
            try:
                with open(self.JWT_PUBLIC_KEY_PATH, "r") as f:
                    self.JWT_PUBLIC_KEY_CONTENT = f.read()
            except FileNotFoundError:
                # Se o arquivo não existir, usa o valor da variável de ambiente
                self.JWT_PUBLIC_KEY_CONTENT = os.environ.get("JWT_PUBLIC_KEY")

# Cria a instância de configurações
settings = Settings()

# Configurações para diferentes ambientes
if settings.ENVIRONMENT == "production":
    settings.DEBUG = False
    settings.CORS_ORIGINS = "https://crosshairlab.com,https://admin.crosshairlab.com"
    settings.ENABLE_SECURITY_HEADERS = True
    settings.SECURITY_SCANNER_ENABLED = True
    settings.API_LOGGING_ENABLED = True
    settings.ENABLE_PERFORMANCE_MONITORING = True
elif settings.ENVIRONMENT == "staging":
    settings.DEBUG = False
    settings.CORS_ORIGINS = "https://staging.crosshairlab.com,https://admin-staging.crosshairlab.com,http://localhost:3000"
    settings.ENABLE_SECURITY_HEADERS = True
    settings.SECURITY_SCANNER_ENABLED = True
    settings.API_LOGGING_ENABLED = True
elif settings.ENVIRONMENT == "development":
    settings.DEBUG = True
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 dia para facilitar o desenvolvimento
    settings.CORS_ORIGINS = "*"  # Permite qualquer origem em desenvolvimento
    settings.ENABLE_SECURITY_HEADERS = True
    settings.SECURITY_SCANNER_ENABLED = True
    settings.API_LOGGING_ENABLED = True
