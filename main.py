import os
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from io import BytesIO

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import pyotp
import qrcode
import jwt
from passlib.context import CryptContext
import redis

from supabase_client import get_client

# Configurações
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
ADMIN_WHITELIST_IPS = os.getenv("ADMIN_WHITELIST_IPS", "").split(",") if os.getenv("ADMIN_WHITELIST_IPS") else []
REDIS_URL = os.getenv("REDIS_URL")

# Rate limiting
try:
    redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None
    limiter = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL) if REDIS_URL else Limiter(key_func=get_remote_address)
except:
    limiter = Limiter(key_func=get_remote_address)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI app
app = FastAPI(
    title="CrosshairLab Admin API",
    description="API segura para administração do CrosshairLab",
    version="1.0.0"
)

# Middlewares
app.state.limiter = limiter

# CORS restrito
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://crosshairlab.app",
        "https://www.crosshairlab.app",
        "https://api.crosshairlab.app",
        "https://admin.crosshairlab.app",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Trusted hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["crosshairlab.app", "*.crosshairlab.app", "api.crosshairlab.app", "admin.crosshairlab.app", "81.20.248.134"]
)

# Security
security = HTTPBearer()

# Modelos Pydantic
class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str
    recaptcha_token: Optional[str] = None
    totp_code: Optional[str] = None

class AdminUser(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    is_admin: bool = True
    totp_secret: Optional[str] = None
    totp_enabled: bool = False
    created_at: datetime
    last_login: Optional[datetime] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = JWT_EXPIRATION_HOURS * 3600
    requires_2fa: bool = False
    temp_token: Optional[str] = None

class Setup2FAResponse(BaseModel):
    qr_code_url: str
    secret: str
    backup_codes: list[str]

class AdminStatsResponse(BaseModel):
    total_users: int
    active_users_24h: int
    total_crosshairs: int
    system_status: str

# Funções auxiliares
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar senha com hash bcrypt"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Gerar hash da senha"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Criar token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    """Verificar e decodificar token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )

async def verify_recaptcha(token: str) -> bool:
    """Verificar reCAPTCHA"""
    if not RECAPTCHA_SECRET_KEY or not token:
        return True  # Skip se não configurado
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": RECAPTCHA_SECRET_KEY,
                    "response": token
                }
            )
            result = response.json()
            return result.get("success", False)
        except:
            return False

def check_ip_whitelist(request: Request) -> bool:
    """Verificar se IP está na whitelist"""
    if not ADMIN_WHITELIST_IPS or not ADMIN_WHITELIST_IPS[0]:
        return True  # Skip se não configurado
    
    # Verificar se request.client existe antes de acessar host
    if not request.client:
        return False  # Bloquear se não conseguir obter IP do cliente
    
    client_ip = request.client.host
    x_forwarded_for = request.headers.get("x-forwarded-for")
    
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
    
    return client_ip in ADMIN_WHITELIST_IPS

def generate_qr_code(secret: str, email: str) -> str:
    """Gerar QR code para 2FA"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="CrosshairLab Admin"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, "PNG")
    
    # Converter para base64
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

async def get_admin_user(email: str) -> Optional[AdminUser]:
    """Buscar usuário admin no banco"""
    supabase = get_client()
    
    try:
        # Buscar admin na tabela admin_users
        result = supabase.table("admin_users").select("*").eq("email", email).execute()
        
        if not result.data:
            return None
        
        admin_data = result.data[0]
        return AdminUser(
            id=admin_data["id"],
            email=admin_data["email"],
            username=admin_data.get("username"),
            totp_secret=admin_data.get("totp_secret"),
            totp_enabled=admin_data.get("totp_enabled", False),
            created_at=datetime.fromisoformat(admin_data["created_at"].replace("Z", "+00:00")),
            last_login=datetime.fromisoformat(admin_data["last_login"].replace("Z", "+00:00")) if admin_data.get("last_login") else None
        )
    except Exception as e:
        print(f"Erro ao buscar admin: {e}")
        return None

async def update_admin_login(admin_id: str):
    """Atualizar último login do admin"""
    supabase = get_client()
    
    try:
        supabase.table("admin_users").update({
            "last_login": datetime.utcnow().isoformat()
        }).eq("id", admin_id).execute()
    except Exception as e:
        print(f"Erro ao atualizar login: {e}")

# Dependências
async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> AdminUser:
    """Obter admin atual do token"""
    payload = verify_token(credentials.credentials)
    
    admin_id = payload.get("sub")
    if not admin_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    supabase = get_client()
    try:
        result = supabase.table("admin_users").select("*").eq("id", admin_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin não encontrado"
            )
        
        admin_data = result.data[0]
        return AdminUser(
            id=admin_data["id"],
            email=admin_data["email"],
            username=admin_data.get("username"),
            totp_secret=admin_data.get("totp_secret"),
            totp_enabled=admin_data.get("totp_enabled", False),
            created_at=datetime.fromisoformat(admin_data["created_at"].replace("Z", "+00:00")),
            last_login=datetime.fromisoformat(admin_data["last_login"].replace("Z", "+00:00")) if admin_data.get("last_login") else None
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro ao verificar admin"
        )

# Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "CrosshairLab Admin API"
    }

@app.post("/admin/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def admin_login(request: Request, login_data: AdminLoginRequest):
    """Login de administrador com 2FA"""
    
    # 1. Verificar whitelist de IPs
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    # 2. Verificar reCAPTCHA
    if login_data.recaptcha_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token reCAPTCHA obrigatório"
        )
    
    if not await verify_recaptcha(login_data.recaptcha_token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA inválido"
        )
    
    # 3. Buscar admin no banco
    admin = await get_admin_user(login_data.email)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    # 4. Verificar senha
    supabase = get_client()
    try:
        result = supabase.table("admin_users").select("password_hash").eq("email", login_data.email).execute()
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas"
            )
        
        password_hash = result.data[0]["password_hash"]
        if not verify_password(login_data.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )
    
    # 5. Verificar 2FA
    if admin.totp_enabled and admin.totp_secret:
        if not login_data.totp_code:
            # Primeiro login - solicitar 2FA
            temp_token = create_access_token(
                data={"sub": admin.id, "email": admin.email, "temp": True},
                expires_delta=timedelta(minutes=5)
            )
            return TokenResponse(
                access_token="",
                requires_2fa=True,
                temp_token=temp_token
            )
        else:
            # Verificar código 2FA
            totp = pyotp.TOTP(admin.totp_secret)
            if not totp.verify(login_data.totp_code, valid_window=1):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Código 2FA inválido"
                )
    
    # 6. Gerar token final
    access_token = create_access_token(
        data={
            "sub": admin.id,
            "email": admin.email,
            "username": admin.username,
            "is_admin": True
        }
    )
    
    # 7. Atualizar último login
    await update_admin_login(admin.id)
    
    return TokenResponse(access_token=access_token)

@app.post("/admin/setup-2fa", response_model=Setup2FAResponse)
@limiter.limit("3/minute")
async def setup_2fa(request: Request, current_admin: AdminUser = Depends(get_current_admin)):
    """Configurar 2FA para admin"""
    
    # Verificar whitelist
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    # Gerar novo secret
    secret = pyotp.random_base32()
    
    # Gerar QR code
    qr_code_url = generate_qr_code(secret, current_admin.email)
    
    # Gerar códigos de backup
    backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
    
    # Salvar no banco (temporariamente, será confirmado quando o usuário inserir o código)
    supabase = get_client()
    try:
        supabase.table("admin_users").update({
            "totp_secret_temp": secret,
            "backup_codes": backup_codes
        }).eq("id", current_admin.id).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao configurar 2FA"
        )
    
    return Setup2FAResponse(
        qr_code_url=qr_code_url,
        secret=secret,
        backup_codes=backup_codes
    )

@app.post("/admin/confirm-2fa")
@limiter.limit("5/minute")
async def confirm_2fa(
    request: Request,
    totp_code: str,
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Confirmar configuração do 2FA"""
    
    # Verificar whitelist
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    supabase = get_client()
    
    try:
        # Buscar secret temporário
        result = supabase.table("admin_users").select("totp_secret_temp").eq("id", current_admin.id).execute()
        
        if not result.data or not result.data[0].get("totp_secret_temp"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Configuração 2FA não iniciada"
            )
        
        temp_secret = result.data[0]["totp_secret_temp"]
        
        # Verificar código
        totp = pyotp.TOTP(temp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código inválido"
            )
        
        # Confirmar 2FA
        supabase.table("admin_users").update({
            "totp_secret": temp_secret,
            "totp_enabled": True,
            "totp_secret_temp": None
        }).eq("id", current_admin.id).execute()
        
        return {"message": "2FA configurado com sucesso"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao confirmar 2FA"
        )

@app.get("/admin/users")
@limiter.limit("10/minute")
async def list_users(
    request: Request,
    page: int = 1,
    limit: int = 20,
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Listar usuários (com paginação)"""
    
    # Verificar whitelist
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    supabase = get_client()
    
    try:
        # Usar função segura do banco
        result = supabase.rpc("get_users_list", {
            "page_num": page,
            "page_size": min(limit, 100)  # Máximo 100 por página
        }).execute()
        
        return {
            "users": result.data,
            "page": page,
            "limit": limit,
            "total": len(result.data)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao buscar usuários"
        )

@app.get("/admin/stats", response_model=AdminStatsResponse)
@limiter.limit("10/minute")
async def get_admin_stats(
    request: Request,
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Obter estatísticas do sistema"""
    
    # Verificar whitelist
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    supabase = get_client()
    
    try:
        # Usar função segura do banco
        result = supabase.rpc("get_admin_stats").execute()
        
        if not result.data:
            return AdminStatsResponse(
                total_users=0,
                active_users_24h=0,
                total_crosshairs=0,
                system_status="unknown"
            )
        
        stats = result.data[0]
        return AdminStatsResponse(
            total_users=stats.get("total_users", 0),
            active_users_24h=stats.get("active_users_24h", 0),
            total_crosshairs=stats.get("total_crosshairs", 0),
            system_status="operational"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao buscar estatísticas"
        )

@app.delete("/admin/users/{user_id}")
@limiter.limit("5/minute")
async def delete_user(
    user_id: str,
    request: Request,
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Deletar usuário"""
    
    # Verificar whitelist
    if not check_ip_whitelist(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: IP não autorizado"
        )
    
    # Validar UUID
    try:
        import uuid
        uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de usuário inválido"
        )
    
    supabase = get_client()
    
    try:
        # Usar função segura do banco
        result = supabase.rpc("delete_user_by_id", {
            "target_user_id": user_id,
            "admin_id": current_admin.id
        }).execute()
        
        if result.data and result.data[0].get("success"):
            return {"message": "Usuário deletado com sucesso"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuário não encontrado"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao deletar usuário"
        )

@app.get("/admin/me")
async def get_current_admin_info(current_admin: AdminUser = Depends(get_current_admin)):
    """Obter informações do admin atual"""
    return {
        "id": current_admin.id,
        "email": current_admin.email,
        "username": current_admin.username,
        "totp_enabled": current_admin.totp_enabled,
        "last_login": current_admin.last_login,
        "created_at": current_admin.created_at
    }

# Tratamento de erros global
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Erro interno do servidor", "status_code": 500}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
