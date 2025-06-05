import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path

# Carrega variáveis de ambiente
load_dotenv(Path('.') / '.env')

# Configurações da API
API_PREFIX = "/api/v1"
API_TITLE = "CrosshairLab API"
API_DESCRIPTION = "API para o aplicativo CrosshairLab"
API_VERSION = "1.0.0"
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

# Importações dos routers
# from .routers import users, crosshairs, auth
from .routers.admin.router import router as admin_router

# Cria a aplicação FastAPI
app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if ENVIRONMENT != "production" else None,
)

# Configuração de CORS
allowed_origins = [
    "https://crosshairlab.app",
    "https://www.crosshairlab.app",
]

# Em ambiente de desenvolvimento, permite localhost
if ENVIRONMENT == "development":
    allowed_origins.extend([
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:8000",
    ])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rota de verificação
@app.get("/")
async def root():
    return {"message": "CrosshairLab API", "status": "online", "version": API_VERSION}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Incluir routers
# app.include_router(auth.router, prefix=API_PREFIX)
# app.include_router(users.router, prefix=API_PREFIX)
# app.include_router(crosshairs.router, prefix=API_PREFIX)
app.include_router(admin_router, prefix=API_PREFIX)

# Inicializa o cliente Supabase
from .supabase_client import init_supabase
init_supabase()

if __name__ == "__main__":
    import uvicorn
    
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", 8000))
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=ENVIRONMENT == "development"
    )
