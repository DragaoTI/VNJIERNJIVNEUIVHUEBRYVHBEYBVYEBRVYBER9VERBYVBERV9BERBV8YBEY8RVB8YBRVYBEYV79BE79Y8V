from pydantic import BaseModel, Field
from typing import Optional, List

class TwoFactorSetupResponse(BaseModel):
    """
    Resposta para a configuração inicial do 2FA
    """
    qr_code: str
    secret: str
    enabled: bool

class TwoFactorVerifyRequest(BaseModel):
    """
    Requisição para verificação de código 2FA
    """
    code: str = Field(..., min_length=6, max_length=8)

class TwoFactorResponse(BaseModel):
    """
    Resposta para operações de 2FA
    """
    valid: bool
    message: str
    enabled: Optional[bool] = None

class TwoFactorBackupCodesResponse(BaseModel):
    """
    Resposta com códigos de backup
    """
    success: bool
    message: str
    backup_codes: List[str] 