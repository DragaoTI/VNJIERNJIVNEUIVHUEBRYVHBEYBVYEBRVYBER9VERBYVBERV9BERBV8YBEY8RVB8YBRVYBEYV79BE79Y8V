from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Body, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from app.auth.schemas import Token, UserLoginSchema, RefreshTokenRequest # Supondo que estes schemas existem
from app.schemas.user_schemas import UserCreate, UserResponse
from app.services.supabase_service import supabase_service
from app.services.geoip_service import get_geoip_data
from app.schemas.geo_log_schemas import GeoLogCreate
from app.auth.jwt_handler import create_access_token, create_refresh_token, verify_token
from app.models.user import User
from app.auth.dependencies import get_current_active_user
from app.utils.rate_limiter import limiter
from app.core.config import settings
from datetime import timedelta, datetime, timezone
from typing import Optional, Dict
import uuid
import secrets
import json
import traceback
from app.schemas.auth_schemas import (
    TokenRefresh, PasswordReset, 
    PasswordResetRequest, ChangePasswordRequest
)
from app.schemas.two_factor_schemas import TwoFactorVerifyRequest, TwoFactorResponse
from app.auth.password_handler import get_password_hash, verify_password
from app.services.two_factor_service import two_factor_service

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# Cache de desafios 2FA pendentes
pending_2fa_challenges = {}

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour") # Limite para registro
async def register_user(request: Request, user_in: UserCreate):
    # Logs detalhados para debug
    print("="*50)
    print(f"[REGISTRO] Nova solicitação recebida - {datetime.now().isoformat()}")
    print(f"[REGISTRO] Email: {user_in.email}")
    print(f"[REGISTRO] Username: {user_in.username}")
    print(f"[REGISTRO] Metadados: {json.dumps(user_in.user_metadata) if user_in.user_metadata else 'None'}")
    print(f"[REGISTRO] IP do cliente: {request.client.host if request.client else 'unknown'}")
    print(f"[REGISTRO] User-Agent: {request.headers.get('user-agent', 'unknown')}")
    
    # Verificar se email já existe
    print(f"[REGISTRO] Verificando se email já existe: {user_in.email}")
    email_exists = await supabase_service.get_user_by_email_for_check(user_in.email)
    if email_exists:
        print(f"[REGISTRO] Email já registrado: {user_in.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    print(f"[REGISTRO] Email disponível: {user_in.email}")
    
    try:
        # Tentativa de criação de usuário com mais detalhes de log
        print(f"[REGISTRO] Iniciando criação de usuário no Supabase")
        print(f"[REGISTRO] Dados completos sendo enviados: {user_in.model_dump(exclude={'password'})}")
        
        new_user = await supabase_service.create_user(user_in)
        
        if not new_user:
            print(f"[REGISTRO] ERRO: create_user retornou None para {user_in.email}")
            print(f"[REGISTRO] Verifique logs do Supabase para mais detalhes")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create user in Supabase",
            )
            
        print(f"[REGISTRO] Usuário criado com sucesso: {new_user.id}")
        print("="*50)
        return new_user
        
    except Exception as e:
        print(f"[REGISTRO] EXCEÇÃO durante registro: {str(e)}")
        print("[REGISTRO] Stack trace completa:")
        traceback.print_exc()
        print(f"[REGISTRO] Tipo de exceção: {type(e).__name__}")
        
        # Tenta extrair mais informações do erro
        error_details = str(e)
        if hasattr(e, 'detail'):
            error_details = e.detail
        elif hasattr(e, 'args') and len(e.args) > 0:
            error_details = str(e.args[0])
            
        print(f"[REGISTRO] Detalhes do erro: {error_details}")
        print("="*50)
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating user: {error_details}",
        )


@router.post("/login/json", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_LOGIN_ATTEMPTS)
async def login_for_access_token_json(
    request: Request,
    form_data: UserLoginSchema
):
    user = await supabase_service.login_user(email=form_data.email, password=form_data.password)
    if not user or not user.id: # Checar se user e user.id são válidos
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    # Log GeoIP
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    if ip_address != "unknown":
        geoip_data = await get_geoip_data(ip_address)
        log_entry_data = {
            "user_id": user.id,
            "ip_address": ip_address,
            "user_agent": user_agent,
        }
        if geoip_data:
            log_entry_data.update({
                "country": geoip_data.get("country_name"),
                "city": geoip_data.get("city"),
                "region": geoip_data.get("region"),
                "latitude": geoip_data.get("latitude"),
                "longitude": geoip_data.get("longitude"),
            })
        await supabase_service.add_geo_log(GeoLogCreate(**log_entry_data))


    access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token_payload = {"sub": str(user.id), "role": user.role}
    access_token = create_access_token(
        data=access_token_payload, expires_delta=access_token_expires_delta
    )
    
    raw_refresh_token, refresh_token_expires_at = create_refresh_token(
        data={"sub": str(user.id)}, expires_delta=refresh_token_expires_delta
    )

    stored_token_info = await supabase_service.store_refresh_token(
        user_id=user.id,
        token_str=raw_refresh_token,
        expires_at=refresh_token_expires_at
    )
    if not stored_token_info:
        print(f"AVISO: Falha ao armazenar refresh token para o usuário {user.id} durante o login.")
        # Decidir se isso deve ser um erro fatal para o login.
        # Por ora, permite o login, mas o refresh pode falhar.

    return {"access_token": access_token, "refresh_token": raw_refresh_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Autentica um usuário e retorna tokens de acesso e refresh se bem-sucedido.
    Caso o usuário tenha 2FA habilitado, retorna um desafio 2FA pendente.
    """
    # Verifica rate limit
    client_ip = request.client.host
    if not await limiter.check_rate_limit(client_ip, "login", max_requests=5, window_seconds=60):
        # Registra tentativa de login bloqueada por rate limit
        await supabase_service.log_auth_attempt(
            ip=client_ip,
            username=form_data.username,
            successful=False,
            reason="rate_limit_exceeded"
        )
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Tente novamente mais tarde."
        )
    
    # Verifica credenciais
    user = await supabase_service.authenticate_user(
        email=form_data.username,
        password=form_data.password
    )
    
    if not user:
        # Registra tentativa de login com credenciais inválidas
        await supabase_service.log_auth_attempt(
            ip=client_ip,
            username=form_data.username,
            successful=False,
            reason="invalid_credentials"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica se a conta está ativa
    if user.status != "active":
        # Registra tentativa de login com conta inativa
        await supabase_service.log_auth_attempt(
            ip=client_ip,
            username=form_data.username,
            successful=False,
            reason="inactive_account",
            user_id=str(user.id)
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Esta conta está {user.status}. Entre em contato com o suporte."
        )
    
    # Verifica se o usuário tem 2FA habilitado
    has_2fa = await two_factor_service.is_2fa_enabled(str(user.id))
    
    if has_2fa:
        # Cria um desafio 2FA pendente
        challenge_id = secrets.token_urlsafe(32)
        pending_2fa_challenges[challenge_id] = {
            "user_id": str(user.id),
            "email": user.email,
            "expires_at": datetime.now() + timedelta(minutes=5),
            "ip": client_ip
        }
        
        # Registra desafio 2FA pendente
        await supabase_service.log_auth_attempt(
            ip=client_ip,
            username=form_data.username,
            successful=True,
            reason="2fa_required",
            user_id=str(user.id)
        )
        
        # Retorna token de desafio 2FA
        return {
            "access_token": "",
            "refresh_token": "",
            "token_type": "bearer",
            "expires_in": 0,
            "requires_2fa": True,
            "challenge_id": challenge_id
        }
    
    # Gera tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)},
        expires_delta=refresh_token_expires
    )
    
    # Atualiza último login
    await supabase_service.update_last_login(user.id)
    
    # Registra login bem-sucedido
    await supabase_service.log_auth_attempt(
        ip=client_ip,
        username=form_data.username,
        successful=True,
        reason="success",
        user_id=str(user.id)
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.total_seconds(),
        "requires_2fa": False
    }

@router.post("/verify-2fa", response_model=Token)
async def verify_2fa_challenge(
    request: Request,
    response: Response,
    data: TwoFactorVerifyRequest = Body(...),
    challenge_id: str = Body(...)
):
    """
    Verifica um desafio 2FA e retorna tokens se bem-sucedido.
    """
    # Verifica se o desafio existe
    if challenge_id not in pending_2fa_challenges:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Desafio 2FA inválido ou expirado."
        )
    
    challenge = pending_2fa_challenges[challenge_id]
    
    # Verifica expiração
    if datetime.now() > challenge["expires_at"]:
        # Remove desafio expirado
        pending_2fa_challenges.pop(challenge_id)
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Desafio 2FA expirado. Faça login novamente."
        )
    
    # Verifica código 2FA
    is_valid = await two_factor_service.verify_code(challenge["user_id"], data.code)
    
    if not is_valid:
        # Tenta verificar código de backup
        is_valid_backup = await two_factor_service.verify_backup_code(challenge["user_id"], data.code)
        
        if not is_valid_backup:
            # Registra falha na verificação 2FA
            await supabase_service.log_auth_attempt(
                ip=request.client.host,
                username=challenge["email"],
                successful=False,
                reason="invalid_2fa_code",
                user_id=challenge["user_id"]
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código 2FA inválido."
            )
        
        # Se usou código de backup, registra isso
        await supabase_service.log_security_event(
            event_type="backup_code_used_login",
            user_id=challenge["user_id"],
            details="Código de backup utilizado para login",
            severity="medium",
            ip=request.client.host
        )
    
    # Remove desafio
    pending_2fa_challenges.pop(challenge_id)
    
    # Gera tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": challenge["user_id"]},
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        data={"sub": challenge["user_id"]},
        expires_delta=refresh_token_expires
    )
    
    # Atualiza último login
    await supabase_service.update_last_login(uuid.UUID(challenge["user_id"]))
    
    # Registra login bem-sucedido com 2FA
    await supabase_service.log_auth_attempt(
        ip=request.client.host,
        username=challenge["email"],
        successful=True,
        reason="success_2fa",
        user_id=challenge["user_id"]
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.total_seconds(),
        "requires_2fa": False
    }

@router.post("/refresh", response_model=Token)
@limiter.limit("20/minute")
async def refresh_access_token(request: Request, token_request: RefreshTokenRequest):
    client_refresh_token_str = token_request.refresh_token
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    auth_failed_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, # Usar 403 para falhas de autorização de token
        detail="Invalid or revoked refresh token",
    )

    # 1. Obter dados do token do banco de dados usando o HASH
    db_token_data = await supabase_service.get_refresh_token_data_by_hash(client_refresh_token_str)

    if not db_token_data:
        # print(f"Debug: /refresh - Token não encontrado no DB para o hash de: {client_refresh_token_str[:20]}...")
        raise auth_failed_exception

    db_token_id = uuid.UUID(db_token_data["id"])
    db_user_id_str = db_token_data["user_id"]

    # 2. Verificar se foi revogado
    if db_token_data.get("revoked"):
        # print(f"Debug: /refresh - Token (DB ID: {db_token_id}) está revogado.")
        # Medida de segurança: se um token revogado é usado, revogar toda a família de tokens descendentes.
        # Esta lógica pode ser mais complexa se você rastrear a cadeia de `parent_token_hash`.
        # Por simplicidade aqui, vamos apenas revogar todos os tokens do usuário se um revogado for usado.
        await supabase_service.revoke_all_user_refresh_tokens(uuid.UUID(db_user_id_str))
        raise auth_failed_exception

    # 3. Verificar se expirou
    expires_at_str = db_token_data.get("expires_at")
    if not expires_at_str: # Checagem de segurança
        # print(f"Debug: /refresh - Token (DB ID: {db_token_id}) não tem expires_at no DB.")
        await supabase_service.revoke_refresh_token(db_token_id)
        raise auth_failed_exception

    expires_at_utc = datetime.fromisoformat(expires_at_str).replace(tzinfo=timezone.utc)
    if expires_at_utc < datetime.now(timezone.utc):
        # print(f"Debug: /refresh - Token (DB ID: {db_token_id}) expirou em {expires_at_utc}.")
        await supabase_service.revoke_refresh_token(db_token_id) # Revoga o token expirado
        raise auth_failed_exception
        
    # 4. Validar o JWT do refresh token em si (opcional, mas bom para consistência)
    # Isto verifica a assinatura do token, expiração JWT (redundante com a do DB, mas ok), tipo, e 'sub'.
    try:
        jwt_payload = verify_token(client_refresh_token_str, credentials_exception) # Reutiliza verify_token
        if not jwt_payload or jwt_payload.token_type != "refresh" or jwt_payload.user_id != db_user_id_str:
            # print(f"Debug: /refresh - Payload JWT inválido ou não corresponde ao DB. JWT UserID: {jwt_payload.user_id if jwt_payload else 'N/A'}, DB UserID: {db_user_id_str}")
            await supabase_service.revoke_refresh_token(db_token_id)
            raise auth_failed_exception
    except HTTPException as e: # Captura a credentials_exception de verify_token
        # print(f"Debug: /refresh - verify_token falhou para o token do cliente: {e.detail}")
        await supabase_service.revoke_refresh_token(db_token_id)
        raise auth_failed_exception # Re-levanta a exceção com o detalhe apropriado

    # 5. Revogar o token antigo que foi usado (CRUCIAL para rotação segura)
    if not await supabase_service.revoke_refresh_token(db_token_id):
        print(f"ERRO CRÍTICO: Falha ao revogar o refresh token usado (DB ID: {db_token_id}) para o usuário {db_user_id_str}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token refresh process failed internally.")

    # 6. Obter dados do usuário para o novo token
    user = await supabase_service.get_user_by_id(uuid.UUID(db_user_id_str))
    if not user or not user.is_active:
        # print(f"Debug: /refresh - Usuário {db_user_id_str} não encontrado ou inativo.")
        # O usuário pode ter sido desativado/deletado. Não emitir novos tokens.
        raise auth_failed_exception # Ou credentials_exception

    # 7. Gerar novo access token
    new_access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token_payload = {"sub": str(user.id), "role": user.role}
    new_access_token = create_access_token(
        data=new_access_token_payload, expires_delta=new_access_token_expires_delta
    )

    # 8. Gerar novo refresh token (rotação)
    new_refresh_token_expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    new_raw_refresh_token, new_refresh_token_expires_at = create_refresh_token(
        data={"sub": str(user.id)}, expires_delta=new_refresh_token_expires_delta
    )

    # 9. Armazenar o novo refresh token no banco de dados
    new_stored_token_info = await supabase_service.store_refresh_token(
        user_id=user.id,
        token_str=new_raw_refresh_token,
        expires_at=new_refresh_token_expires_at,
        parent_token_str=client_refresh_token_str # Rastreia a origem
    )
    if not new_stored_token_info:
        print(f"ERRO CRÍTICO: Falha ao armazenar o NOVO refresh token para o usuário {user.id} durante o refresh.")
        # Neste ponto, o token antigo já foi revogado. O usuário ficará sem refresh token.
        # É uma situação ruim. Retornar erro 500.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to store new refresh token.")

    # print(f"Debug: /refresh - Sucesso. Novo access token e refresh token emitidos para user {user.id}.")
    return {"access_token": new_access_token, "refresh_token": new_raw_refresh_token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute") # Ajustar limite conforme necessidade
async def logout_user(
    request: Request,
    token_request: Optional[RefreshTokenRequest] = None,
    current_user: Optional[User] = Depends(get_current_active_user) # Tornar opcional se quisermos permitir logout anônimo de um token específico
):
    """
    Revoga refresh tokens.
    - Se 'refresh_token' é fornecido no corpo, tenta revogar esse token específico.
      Isso permite que um cliente revogue um token mesmo que o access token associado tenha expirado.
    - Se 'refresh_token' não é fornecido E um usuário está autenticado (current_user),
      revoga todos os tokens ativos para esse usuário. (Logout de todas as sessões)
    """
    revoked_something = False
    if token_request and token_request.refresh_token:
        # print(f"Debug: /logout - Tentando revogar refresh token específico fornecido.")
        if await supabase_service.revoke_refresh_token_by_hash(token_request.refresh_token):
            revoked_something = True
            # print(f"Debug: /logout - Refresh token específico revogado com sucesso.")
        # else:
            # print(f"Debug: /logout - Falha ao revogar refresh token específico (pode já estar inválido/revogado).")
    
    elif current_user and current_user.id: # Se nenhum token específico foi dado, mas há um usuário logado
        # print(f"Debug: /logout - Tentando revogar todos os refresh tokens para o usuário {current_user.id}.")
        if await supabase_service.revoke_all_user_refresh_tokens(current_user.id):
            revoked_something = True
            # print(f"Debug: /logout - Todos os refresh tokens para o usuário {current_user.id} solicitados para revogação.")
        # else:
            # print(f"Debug: /logout - Falha ao solicitar revogação de todos os tokens para o usuário {current_user.id}.")
    
    else: # Nenhum token para revogar ou usuário para identificar
        # print("Debug: /logout - Nenhuma ação de revogação de token realizada (sem token específico ou usuário autenticado).")
        # Pode ser um logout onde o cliente apenas descarta tokens localmente sem informar o servidor.
        # Ou um erro se o cliente esperava que um token fosse revogado.
        # Se o objetivo é SEMPRE ter um usuário para revogar todos os tokens, remova a opcionalidade de current_user.
        pass

    # O status 204 significa "No Content", então não retornamos corpo.
    return None


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        is_active=current_user.is_active,
        role=current_user.role
        # user_metadata=current_user.user_metadata # Se o UserResponse tiver este campo
    )
