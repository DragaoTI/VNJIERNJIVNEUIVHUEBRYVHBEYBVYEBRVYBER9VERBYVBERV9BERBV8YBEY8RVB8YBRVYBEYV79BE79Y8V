from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from app.auth.admin_dependencies import get_current_super_admin_user
from app.models.admin import Administrator
from app.services.security_monitoring_service import security_monitoring_service
from app.services.supabase_service import supabase_service
from app.utils.rate_limiter import limiter
import secrets

# Geração de um prefixo aleatório para aumentar a segurança
SECURITY_ROUTE_PREFIX = secrets.token_urlsafe(8)

router = APIRouter(
    prefix=f"/{SECURITY_ROUTE_PREFIX}_security",
    tags=["Security Monitoring"]
)

@router.get("/alerts", summary="Lista alertas de segurança recentes")
async def list_security_alerts(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, description="Filtro por severidade (low, medium, high, critical)"),
    days: int = Query(7, ge=1, le=30),
    current_admin: Administrator = Depends(get_current_super_admin_user)
):
    """
    Lista os alertas de segurança mais recentes.
    Disponível apenas para super admins.
    """
    # Registra acesso
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_security_alerts",
        details=f"Visualizou alertas de segurança dos últimos {days} dias"
    )
    
    # Busca alertas recentes
    if security_monitoring_service:
        # Alertas em memória
        recent_alerts = await security_monitoring_service.get_recent_alerts(
            limit=limit,
            severity=severity
        )
    else:
        recent_alerts = []
    
    # Busca alertas no banco de dados
    start_date = datetime.now() - timedelta(days=days)
    
    try:
        filters = {}
        if severity:
            filters["severity"] = severity
        
        db_alerts = await supabase_service.get_security_events(
            limit=limit,
            offset=0,
            start_date=start_date,
            filters=filters
        )
    except Exception as e:
        db_alerts = []
    
    # Combina os resultados
    combined_alerts = recent_alerts
    
    # Adiciona alertas do banco que não estão na memória
    for db_alert in db_alerts:
        if not any(ra.get("id") == db_alert.get("id") for ra in recent_alerts):
            combined_alerts.append(db_alert)
    
    # Limita ao número solicitado
    combined_alerts = combined_alerts[:limit]
    
    return {
        "total": len(combined_alerts),
        "results": combined_alerts
    }

@router.get("/stats", summary="Estatísticas de segurança")
async def security_stats(
    request: Request,
    days: int = Query(7, ge=1, le=30),
    current_admin: Administrator = Depends(get_current_super_admin_user)
):
    """
    Retorna estatísticas de segurança para o painel de administração.
    Disponível apenas para super admins.
    """
    # Registra acesso
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_security_stats",
        details=f"Visualizou estatísticas de segurança dos últimos {days} dias"
    )
    
    # Calcula datas
    now = datetime.now()
    start_date = now - timedelta(days=days)
    
    # Estatísticas de alertas por severidade
    alerts_by_severity = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }
    
    # Estatísticas de tipos de alerta mais comuns
    alert_types = {}
    
    # IPs bloqueados
    blocked_ips_count = 0
    
    # Falhas de login
    login_failures = 0
    
    # Eventos 2FA
    two_factor_events = 0
    
    try:
        # Busca estatísticas no Supabase
        security_stats = await supabase_service.get_security_stats(start_date)
        
        # Preenche dados das estatísticas
        if security_stats:
            if "alerts_by_severity" in security_stats:
                alerts_by_severity = security_stats["alerts_by_severity"]
            
            if "alert_types" in security_stats:
                alert_types = security_stats["alert_types"]
            
            if "blocked_ips_count" in security_stats:
                blocked_ips_count = security_stats["blocked_ips_count"]
            
            if "login_failures" in security_stats:
                login_failures = security_stats["login_failures"]
            
            if "two_factor_events" in security_stats:
                two_factor_events = security_stats["two_factor_events"]
    except Exception as e:
        print(f"Erro ao buscar estatísticas de segurança: {str(e)}")
    
    # Adiciona contagem de IPs bloqueados em memória
    if security_monitoring_service:
        blocked_ips_count += len(security_monitoring_service.blocked_ips)
    
    return {
        "alerts_by_severity": alerts_by_severity,
        "alert_types": alert_types,
        "blocked_ips_count": blocked_ips_count,
        "login_failures": login_failures,
        "two_factor_events": two_factor_events,
        "period_days": days,
        "timestamp": now.isoformat()
    }

@router.get("/blocked-ips", summary="Lista IPs bloqueados")
async def list_blocked_ips(
    request: Request,
    current_admin: Administrator = Depends(get_current_super_admin_user)
):
    """
    Lista os IPs atualmente bloqueados pelo sistema.
    Disponível apenas para super admins.
    """
    # Registra acesso
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="view_blocked_ips",
        details="Visualizou lista de IPs bloqueados"
    )
    
    # IPs bloqueados em memória
    memory_blocked_ips = []
    if security_monitoring_service:
        memory_blocked_ips = list(security_monitoring_service.blocked_ips)
    
    # IPs bloqueados no banco
    try:
        db_blocked_ips = await supabase_service.get_blocked_ips()
    except Exception as e:
        db_blocked_ips = []
    
    # Combina os resultados
    all_blocked_ips = []
    
    # Adiciona IPs da memória
    for ip in memory_blocked_ips:
        all_blocked_ips.append({
            "ip": ip,
            "source": "memory",
            "reason": "Bloqueado pelo sistema de monitoramento",
            "blocked_at": datetime.now().isoformat()
        })
    
    # Adiciona IPs do banco
    for ip_data in db_blocked_ips:
        if not any(bip["ip"] == ip_data["ip"] for bip in all_blocked_ips):
            all_blocked_ips.append(ip_data)
    
    return {
        "total": len(all_blocked_ips),
        "results": all_blocked_ips
    }

@router.post("/unblock-ip/{ip}", summary="Desbloqueia um IP")
async def unblock_ip(
    ip: str,
    request: Request,
    current_admin: Administrator = Depends(get_current_super_admin_user)
):
    """
    Remove um IP da lista de bloqueados.
    Disponível apenas para super admins.
    """
    # Registra ação
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="unblock_ip",
        details=f"Desbloqueou o IP {ip}"
    )
    
    # Remove da memória
    if security_monitoring_service and ip in security_monitoring_service.blocked_ips:
        security_monitoring_service.blocked_ips.remove(ip)
    
    # Remove do banco
    try:
        await supabase_service.unblock_ip(ip)
    except Exception as e:
        print(f"Erro ao desbloquear IP no banco: {str(e)}")
    
    return {
        "success": True,
        "message": f"IP {ip} desbloqueado com sucesso"
    }

@router.post("/block-ip/{ip}", summary="Bloqueia um IP manualmente")
async def block_ip(
    ip: str,
    request: Request,
    reason: str = Query(..., min_length=5),
    current_admin: Administrator = Depends(get_current_super_admin_user)
):
    """
    Adiciona um IP à lista de bloqueados manualmente.
    Disponível apenas para super admins.
    """
    # Registra ação
    await supabase_service.log_admin_activity(
        admin_id=current_admin.id,
        action="block_ip",
        details=f"Bloqueou o IP {ip}: {reason}"
    )
    
    # Adiciona à memória
    if security_monitoring_service:
        security_monitoring_service.blocked_ips.add(ip)
    
    # Adiciona ao banco
    try:
        await supabase_service.block_ip(ip, reason, admin_id=str(current_admin.id))
    except Exception as e:
        print(f"Erro ao bloquear IP no banco: {str(e)}")
    
    return {
        "success": True,
        "message": f"IP {ip} bloqueado com sucesso"
    }
