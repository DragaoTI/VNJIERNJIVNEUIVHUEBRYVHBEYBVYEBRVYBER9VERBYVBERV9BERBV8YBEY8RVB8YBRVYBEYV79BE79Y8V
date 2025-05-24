from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from app.auth.jwt_handler import verify_token
from app.auth.schemas import TokenData
from app.services.supabase_service import supabase_service
from app.models.user import User
from typing import Optional
import uuid
from app.core.config import settings
import time
from app.utils.rate_limiter import limiter

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    scheme_name="JWT",
    auto_error=True
)

async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme)
) -> User:
    # Verifica rate limit por IP
    client_ip = request.client.host
    if not await limiter.check_rate_limit(client_ip, "auth"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later."
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": f"{settings.JWT_TOKEN_PREFIX}"},
    )

    # Verifica formato do token
    if not token.startswith(f"{settings.JWT_TOKEN_PREFIX} "):
        raise credentials_exception

    # Remove o prefixo do token
    token = token.replace(f"{settings.JWT_TOKEN_PREFIX} ", "")

    # Verifica o token
    token_data: Optional[TokenData] = verify_token(token, credentials_exception)
    if not token_data or token_data.token_type != "access":
        raise credentials_exception
    
    if token_data.user_id is None:
        raise credentials_exception

    # Verifica se o token não expirou
    if token_data.exp < time.time():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": f"{settings.JWT_TOKEN_PREFIX}"},
        )

    try:
        user_id_uuid = uuid.UUID(token_data.user_id)
    except ValueError:
        raise credentials_exception

    # Busca usuário no banco
    user = await supabase_service.get_user_by_id(user_id_uuid)
    if user is None:
        raise credentials_exception
    
    # Verifica se o usuário está bloqueado
    if user.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is blocked"
        )

    # Verifica se o usuário precisa redefinir a senha
    if user.force_password_reset:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reset required"
        )

    # Registra último acesso
    await supabase_service.update_last_access(user_id_uuid)

    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    if not current_user.role or current_user.role.lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges (admin required)"
        )
    return current_user

async def get_current_super_admin_user(
    current_user: User = Depends(get_current_admin_user)
) -> User:
    if not current_user.role or current_user.role.lower() != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges (super admin required)"
        )
    return current_user
