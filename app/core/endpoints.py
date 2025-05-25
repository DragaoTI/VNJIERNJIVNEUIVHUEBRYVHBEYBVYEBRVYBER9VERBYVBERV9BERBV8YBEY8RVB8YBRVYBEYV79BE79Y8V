"""
Definição centralizada de todos os endpoints da API.
Este arquivo serve como fonte única de verdade para todos os endpoints disponíveis.
"""
from typing import Dict, Any, List, Optional, Union

class EndpointDefinition:
    """Classe para representar um endpoint com metadados"""
    def __init__(
        self, 
        path: str, 
        methods: List[str], 
        description: str, 
        requires_auth: bool = False,
        requires_admin: bool = False,
        rate_limit: Optional[str] = None,
        implemented: bool = True,
        tags: Optional[List[str]] = None
    ):
        self.path = path
        self.methods = methods
        self.description = description
        self.requires_auth = requires_auth
        self.requires_admin = requires_admin
        self.rate_limit = rate_limit
        self.implemented = implemented
        self.tags = tags or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte a definição para um dicionário"""
        return {
            "path": self.path,
            "methods": self.methods,
            "description": self.description,
            "requires_auth": self.requires_auth,
            "requires_admin": self.requires_admin,
            "rate_limit": self.rate_limit,
            "implemented": self.implemented,
            "tags": self.tags
        }


class ApiEndpoints:
    """Classe que define todos os endpoints da API"""
    def __init__(self):
        self.PREFIX = "/api/v1"
        
        # Endpoints de autenticação
        self.AUTH_LOGIN = EndpointDefinition(
            path=f"{self.PREFIX}/auth/login",
            methods=["POST"],
            description="Autenticação de usuário",
            rate_limit="5/minute",
            tags=["auth"]
        )
        
        self.AUTH_LOGOUT = EndpointDefinition(
            path=f"{self.PREFIX}/auth/logout",
            methods=["POST"],
            description="Logout de usuário",
            requires_auth=True,
            tags=["auth"]
        )
        
        self.AUTH_SIGNUP = EndpointDefinition(
            path=f"{self.PREFIX}/auth/signup",
            methods=["POST"],
            description="Registro de novo usuário",
            rate_limit="3/minute",
            tags=["auth"]
        )
        
        self.AUTH_REFRESH = EndpointDefinition(
            path=f"{self.PREFIX}/auth/refresh",
            methods=["POST"],
            description="Atualização de token",
            requires_auth=True,
            tags=["auth"]
        )
        
        self.AUTH_PASSWORD_RESET = EndpointDefinition(
            path=f"{self.PREFIX}/auth/password-reset",
            methods=["POST"],
            description="Solicitação de reset de senha",
            rate_limit="3/10minutes",
            tags=["auth"]
        )
        
        # Endpoints de usuário
        self.USER_PROFILE = EndpointDefinition(
            path=f"{self.PREFIX}/users/profile",
            methods=["GET", "PUT"],
            description="Perfil do usuário",
            requires_auth=True,
            tags=["users"]
        )
        
        self.USER_SETTINGS = EndpointDefinition(
            path=f"{self.PREFIX}/users/settings",
            methods=["GET", "PUT"],
            description="Configurações do usuário",
            requires_auth=True,
            tags=["users"]
        )
        
        # Endpoints de miras (crosshairs)
        self.CROSSHAIRS_LIST = EndpointDefinition(
            path=f"{self.PREFIX}/crosshairs",
            methods=["GET"],
            description="Listagem de miras",
            tags=["crosshairs"]
        )
        
        self.CROSSHAIR_DETAIL = EndpointDefinition(
            path=f"{self.PREFIX}/crosshairs/{{id}}",
            methods=["GET"],
            description="Detalhes de uma mira específica",
            tags=["crosshairs"]
        )
        
        self.CROSSHAIR_CREATE = EndpointDefinition(
            path=f"{self.PREFIX}/crosshairs",
            methods=["POST"],
            description="Criação de nova mira",
            requires_auth=True,
            tags=["crosshairs"]
        )
        
        self.CROSSHAIR_UPDATE = EndpointDefinition(
            path=f"{self.PREFIX}/crosshairs/{{id}}",
            methods=["PUT"],
            description="Atualização de mira",
            requires_auth=True,
            tags=["crosshairs"]
        )
        
        self.CROSSHAIR_DELETE = EndpointDefinition(
            path=f"{self.PREFIX}/crosshairs/{{id}}",
            methods=["DELETE"],
            description="Exclusão de mira",
            requires_auth=True,
            tags=["crosshairs"]
        )
        
        # Endpoints de estatísticas
        self.STATS_GLOBAL = EndpointDefinition(
            path=f"{self.PREFIX}/stats/global",
            methods=["GET"],
            description="Estatísticas globais da plataforma",
            implemented=True,  # Agora está implementado
            tags=["stats"]
        )
        
        self.STATS_USER = EndpointDefinition(
            path=f"{self.PREFIX}/stats/user",
            methods=["GET"],
            description="Estatísticas do usuário",
            requires_auth=True,
            tags=["stats"]
        )
        
        # Endpoints de administração
        self.ADMIN_DASHBOARD = EndpointDefinition(
            path=f"{self.PREFIX}/admin/dashboard",
            methods=["GET"],
            description="Dashboard de administração",
            requires_auth=True,
            requires_admin=True,
            tags=["admin"]
        )
        
        self.ADMIN_USERS = EndpointDefinition(
            path=f"{self.PREFIX}/admin/users",
            methods=["GET"],
            description="Listagem de usuários para administração",
            requires_auth=True,
            requires_admin=True,
            tags=["admin"]
        )
        
        # Endpoints de autenticação em dois fatores
        self.TWO_FACTOR_SETUP = EndpointDefinition(
            path=f"{self.PREFIX}/2fa/setup",
            methods=["POST"],
            description="Configuração de autenticação em dois fatores",
            requires_auth=True,
            tags=["2fa"]
        )
        
        self.TWO_FACTOR_VERIFY = EndpointDefinition(
            path=f"{self.PREFIX}/2fa/verify",
            methods=["POST"],
            description="Verificação de token 2FA",
            requires_auth=True,
            tags=["2fa"]
        )
        
        # Endpoint de verificação de saúde
        self.HEALTH = EndpointDefinition(
            path="/health",
            methods=["GET"],
            description="Verificação de saúde da API",
            tags=["system"]
        )
        
        # Endpoint de segurança
        self.SECURITY_STATS = EndpointDefinition(
            path=f"{self.PREFIX}/XDGSaFWcm_security/stats",
            methods=["GET"],
            description="Estatísticas de segurança",
            requires_auth=True,
            requires_admin=True,
            tags=["security"]
        )
    
    def get_all_endpoints(self) -> Dict[str, EndpointDefinition]:
        """Retorna todos os endpoints definidos"""
        endpoints = {}
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if isinstance(attr, EndpointDefinition):
                endpoints[attr_name] = attr
        return endpoints
    
    def get_implemented_endpoints(self) -> Dict[str, EndpointDefinition]:
        """Retorna apenas os endpoints implementados"""
        return {
            name: endpoint 
            for name, endpoint in self.get_all_endpoints().items() 
            if endpoint.implemented
        }
    
    def get_endpoints_by_tag(self, tag: str) -> Dict[str, EndpointDefinition]:
        """Retorna endpoints filtrados por tag"""
        return {
            name: endpoint 
            for name, endpoint in self.get_all_endpoints().items() 
            if tag in endpoint.tags
        }


# Cria uma instância única para ser importada em outros módulos
api_endpoints = ApiEndpoints() 
