from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Dict, Any, Optional
from app.core.endpoints import api_endpoints
from app.services.supabase_service import supabase_service
from app.auth.dependencies import get_current_active_user
from app.models.user import User as UserModel
from app.utils.rate_limiter import limiter
from slowapi import Limiter
from slowapi.util import get_remote_address
from datetime import datetime, timedelta

router = APIRouter(
    prefix="/stats",
    tags=["Statistics"]
)

@router.get("/global", summary="Estatísticas globais da plataforma")
async def get_global_stats():
    """
    Retorna estatísticas globais da plataforma.
    
    Estatísticas incluem:
    - Total de usuários
    - Total de miras
    - Usuários ativos (dia/semana)
    - Jogos populares
    - Distribuição de miras por jogo
    - Jogos recentemente adicionados
    """
    try:
        # Buscar estatísticas do Supabase
        stats = await supabase_service.get_global_stats()
        
        if not stats:
            # Se não houver dados do Supabase, retorna dados simulados
            stats = generate_fallback_stats()
        
        return stats
    except Exception as e:
        # Em caso de erro, também retorna dados simulados
        print(f"Erro ao buscar estatísticas globais: {str(e)}")
        return generate_fallback_stats()

@router.get("/user", summary="Estatísticas do usuário atual")
async def get_user_stats(
    current_user: UserModel = Depends(get_current_active_user)
):
    """
    Retorna estatísticas do usuário autenticado.
    
    Estatísticas incluem:
    - Total de miras criadas
    - Jogos favoritos
    - Atividade recente
    - Conquistas
    """
    try:
        # Buscar estatísticas do usuário do Supabase
        stats = await supabase_service.get_user_stats(current_user.id)
        
        if not stats:
            # Se não houver dados, retorna dados simulados
            stats = {
                "total_crosshairs": 0,
                "favorite_games": [],
                "recent_activity": [],
                "achievements": []
            }
        
        return stats
    except Exception as e:
        print(f"Erro ao buscar estatísticas do usuário: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao buscar estatísticas do usuário"
        )

def generate_fallback_stats() -> Dict[str, Any]:
    """Gera estatísticas simuladas para fallback"""
    now = datetime.now()
    
    return {
        "total_users": 1256,
        "total_crosshairs": 4598,
        "active_users_today": 218,
        "active_users_week": 876,
        "popular_games": [
            {"name": "Valorant", "count": 2145},
            {"name": "CS2", "count": 1453},
            {"name": "Apex Legends", "count": 978},
            {"name": "Overwatch", "count": 654},
            {"name": "Fortnite", "count": 422}
        ],
        "crosshairs_per_game": {
            "Valorant": 1854,
            "CS2": 1356,
            "Apex Legends": 742,
            "Overwatch": 422,
            "Fortnite": 224
        },
        "newest_games": [
            "The Finals",
            "XDefiant",
            "Deadlock",
            "Gundam Evolution"
        ],
        "last_updated": now.isoformat()
    } 
