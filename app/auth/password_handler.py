from passlib.context import CryptContext
import re
from typing import Dict, List, Optional, Tuple
import secrets
from app.core.config import settings

# Configura o contexto de criptografia com algoritmos seguros
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    argon2__rounds=settings.PASSWORD_ARGON2_ROUNDS if hasattr(settings, "PASSWORD_ARGON2_ROUNDS") else 4,
    argon2__memory_cost=settings.PASSWORD_ARGON2_MEMORY_COST if hasattr(settings, "PASSWORD_ARGON2_MEMORY_COST") else 65536,
    bcrypt__rounds=settings.PASSWORD_BCRYPT_ROUNDS if hasattr(settings, "PASSWORD_BCRYPT_ROUNDS") else 12,
    deprecated="auto",
)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha fornecida corresponde ao hash armazenado
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        return False

def get_password_hash(password: str) -> str:
    """
    Gera um hash seguro para a senha fornecida
    """
    return pwd_context.hash(password)

def check_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Verifica a força da senha com base em critérios predefinidos
    Retorna uma tupla (senha_válida, lista_de_problemas)
    """
    problems = []
    
    # Verifica o comprimento mínimo
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        problems.append(f"A senha deve ter pelo menos {settings.PASSWORD_MIN_LENGTH} caracteres")
    
    # Verifica se contém pelo menos uma letra maiúscula
    if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        problems.append("A senha deve conter pelo menos uma letra maiúscula")
    
    # Verifica se contém pelo menos uma letra minúscula
    if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        problems.append("A senha deve conter pelo menos uma letra minúscula")
    
    # Verifica se contém pelo menos um número
    if settings.PASSWORD_REQUIRE_DIGITS and not re.search(r'\d', password):
        problems.append("A senha deve conter pelo menos um número")
    
    # Verifica se contém pelo menos um caractere especial
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        problems.append("A senha deve conter pelo menos um caractere especial")
    
    # Verifica se não contém sequências óbvias
    common_sequences = ['123456', 'abcdef', 'qwerty', 'password', 'admin', '111111', '000000']
    if any(seq in password.lower() for seq in common_sequences):
        problems.append("A senha não deve conter sequências óbvias")
    
    # Verifica padrões de repetição
    if re.search(r'(.)\1{2,}', password):  # Três ou mais caracteres iguais consecutivos
        problems.append("A senha não deve conter mais de dois caracteres idênticos consecutivos")
    
    return (len(problems) == 0, problems)

def generate_secure_password(length: int = 16) -> str:
    """
    Gera uma senha aleatória forte
    """
    if length < 12:
        length = 12  # Força um comprimento mínimo de 12 para segurança
    
    # Define conjuntos de caracteres
    uppercase_letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # Sem I e O para evitar confusão
    lowercase_letters = "abcdefghijkmnopqrstuvwxyz"  # Sem l para evitar confusão
    digits = "23456789"  # Sem 0 e 1 para evitar confusão
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Garante pelo menos um caractere de cada conjunto
    password = [
        secrets.choice(uppercase_letters),
        secrets.choice(lowercase_letters),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]
    
    # Preenche o restante da senha com caracteres aleatórios
    all_chars = uppercase_letters + lowercase_letters + digits + special_chars
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Embaralha a senha para evitar previsibilidade no padrão
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def needs_rehash(hashed_password: str) -> bool:
    """
    Verifica se o hash da senha precisa ser atualizado 
    devido a mudanças nas configurações de segurança
    """
    return pwd_context.needs_update(hashed_password) 