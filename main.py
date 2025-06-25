from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from .supabase_client import get_client

app = FastAPI(title="CrosshairLab API (Simplificada)")

# CORS básico
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

class RegisterData(BaseModel):
    email: EmailStr
    password: str

class LoginData(RegisterData):
    pass

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/register", response_model=TokenResponse)
async def register(data: RegisterData):
    supabase = get_client()
    resp = supabase.auth.sign_up({"email": data.email, "password": data.password})
    if resp.user is None:
        raise HTTPException(400, resp)
    return TokenResponse(
        access_token=resp.session.access_token if resp.session else "",
        refresh_token=resp.session.refresh_token if resp.session else None,
    )

@app.post("/login", response_model=TokenResponse)
async def login(data: LoginData):
    supabase = get_client()
    resp = supabase.auth.sign_in_with_password({"email": data.email, "password": data.password})
    if resp.user is None or resp.session is None:
        raise HTTPException(401, "Credenciais inválidas")
    return TokenResponse(access_token=resp.session.access_token, refresh_token=resp.session.refresh_token)

@app.get("/me")
async def me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    supabase = get_client()
    resp = supabase.auth.get_user(credentials.credentials)
    if resp.user is None:
        raise HTTPException(401, "Token inválido")
    return {"id": resp.user.id, "email": resp.user.email} 
