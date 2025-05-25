from fastapi import APIRouter, Depends, HTTPException, status, Body, Response, Cookie, Request
from app.auth.dependencies import get_current_active_user
from app.models.user import User
from app.services.two_factor_service import two_factor_service
from app.services.supabase_service import supabase_service
from app.schemas.two_factor_schemas import TwoFactorSetupResponse, TwoFactorVerifyRequest, TwoFactorResponse
from app.utils.rate_limiter import limiter
from pydantic import BaseModel, Field
from typing import Optional, List
import uuid

class TwoFactorRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

class DisableTwoFactorRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=10)

class RecoveryCodeResponse(BaseModel):
    success: bool
    message: str
    backup_codes: Optional[List[str]] = None

router = APIRouter(
    prefix="/2fa",
    tags=["Two Factor Authentication"]
)

@router.post("/setup", response_model=TwoFactorSetupResponse, summary="Iniciar configuração de 2FA")
async def setup_2fa(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Inicia o processo de configuração de autenticação de dois fatores.
    Retorna um código QR que deve ser escaneado com um aplicativo autenticador (Google Authenticator, Authy, etc).
    """
    # Verifica se o 2FA já está habilitado
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    if is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Autenticação de dois fatores já está habilitada para este usuário"
        )
    
    # Gera o código QR
    qr_code, secret = await two_factor_service.generate_qr_code(
        str(current_user.id), 
        current_user.email
    )
    
    # Registra evento de segurança
    await supabase_service.log_security_event(
        event_type="2fa_setup_initiated",
        user_id=str(current_user.id),
        details="Configuração de 2FA iniciada",
        severity="info",
        ip=request.client.host
    )
    
    return {
        "qr_code": qr_code,
        "secret": secret,
        "enabled": False
    }

@router.post("/verify", response_model=RecoveryCodeResponse, summary="Verificar e ativar 2FA")
async def verify_2fa(
    request: Request,
    data: TwoFactorRequest = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifica o código 2FA fornecido e, se válido, ativa a autenticação de dois fatores para o usuário.
    Retorna códigos de recuperação que devem ser armazenados em um local seguro.
    """
    # Verifica se o 2FA já está habilitado
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    if is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Autenticação de dois fatores já está habilitada para este usuário"
        )
    
    # Habilita o 2FA
    result = await two_factor_service.enable_2fa(str(current_user.id), data.code)
    
    if not result["success"]:
        # Registra falha
        await supabase_service.log_security_event(
            event_type="2fa_setup_failed",
            user_id=str(current_user.id),
            details="Falha ao verificar código 2FA durante setup",
            severity="medium",
            ip=request.client.host
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"]
        )
    
    # Registra evento de segurança
    await supabase_service.log_security_event(
        event_type="2fa_setup_completed",
        user_id=str(current_user.id),
        details="Configuração de 2FA concluída com sucesso",
        severity="info",
        ip=request.client.host
    )
    
    return {
        "success": True,
        "message": "Autenticação de dois fatores habilitada com sucesso",
        "backup_codes": result.get("backup_codes", [])
    }

@router.post("/check", response_model=TwoFactorResponse, summary="Verificar código 2FA")
async def check_2fa(
    request: Request,
    data: TwoFactorRequest = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifica se um código 2FA é válido. Útil para testar a configuração.
    """
    # Verifica se o 2FA está habilitado
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    if not is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Autenticação de dois fatores não está habilitada para este usuário"
        )
    
    # Verifica o código
    is_valid = await two_factor_service.verify_code(str(current_user.id), data.code)
    
    # Registra evento de segurança
    if not is_valid:
        await supabase_service.log_security_event(
            event_type="2fa_check_failed",
            user_id=str(current_user.id),
            details="Falha ao verificar código 2FA",
            severity="medium",
            ip=request.client.host
        )
    
    return {
        "valid": is_valid,
        "message": "Código válido" if is_valid else "Código inválido"
    }

@router.post("/disable", response_model=TwoFactorResponse, summary="Desabilitar 2FA")
async def disable_2fa(
    request: Request,
    data: DisableTwoFactorRequest = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Desabilita a autenticação de dois fatores para o usuário após verificação do código.
    """
    # Verifica se o 2FA está habilitado
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    if not is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Autenticação de dois fatores não está habilitada para este usuário"
        )
    
    # Desabilita o 2FA
    result = await two_factor_service.disable_2fa(str(current_user.id), data.code)
    
    if not result["success"]:
        # Registra falha
        await supabase_service.log_security_event(
            event_type="2fa_disable_failed",
            user_id=str(current_user.id),
            details="Falha ao desabilitar 2FA",
            severity="medium",
            ip=request.client.host
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"]
        )
    
    # Registra evento de segurança
    await supabase_service.log_security_event(
        event_type="2fa_disabled",
        user_id=str(current_user.id),
        details="2FA desabilitado com sucesso",
        severity="warning",
        ip=request.client.host
    )
    
    return {
        "valid": True,
        "message": "Autenticação de dois fatores desabilitada com sucesso"
    }

@router.post("/regenerate-backup-codes", response_model=RecoveryCodeResponse, summary="Regenerar códigos de backup")
async def regenerate_backup_codes(
    request: Request,
    data: TwoFactorRequest = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Regenera os códigos de backup após verificação do código 2FA.
    """
    # Verifica se o 2FA está habilitado
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    if not is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Autenticação de dois fatores não está habilitada para este usuário"
        )
    
    # Verifica o código
    is_valid = await two_factor_service.verify_code(str(current_user.id), data.code)
    if not is_valid:
        # Registra falha
        await supabase_service.log_security_event(
            event_type="2fa_backup_codes_regeneration_failed",
            user_id=str(current_user.id),
            details="Falha ao verificar código 2FA para regenerar códigos de backup",
            severity="medium",
            ip=request.client.host
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código inválido"
        )
    
    # Gera novos códigos de backup
    backup_codes = await two_factor_service.generate_backup_codes(str(current_user.id))
    
    # Registra evento de segurança
    await supabase_service.log_security_event(
        event_type="2fa_backup_codes_regenerated",
        user_id=str(current_user.id),
        details="Códigos de backup regenerados com sucesso",
        severity="medium",
        ip=request.client.host
    )
    
    return {
        "success": True,
        "message": "Códigos de backup regenerados com sucesso",
        "backup_codes": backup_codes
    }

@router.get("/status", response_model=TwoFactorResponse, summary="Verificar status 2FA")
async def get_2fa_status(
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Verifica se o 2FA está habilitado para o usuário.
    """
    is_enabled = await two_factor_service.is_2fa_enabled(str(current_user.id))
    
    return {
        "valid": True,
        "message": "2FA está habilitado" if is_enabled else "2FA não está habilitado",
        "enabled": is_enabled
    }
