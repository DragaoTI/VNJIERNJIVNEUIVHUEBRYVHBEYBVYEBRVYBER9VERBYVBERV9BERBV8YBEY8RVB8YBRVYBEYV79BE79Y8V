import sys
import os
from pathlib import Path

# Adiciona o diretório pai ao path para importar módulos da API
sys.path.append(str(Path(__file__).parent.parent))

# Importa o cliente Supabase
from supabase_client import init_supabase, get_supabase

def create_tables():
    """
    Cria as tabelas necessárias no Supabase se elas não existirem.
    """
    try:
        # Inicializa o cliente Supabase
        supabase = init_supabase()
        print("Conexão com o Supabase estabelecida com sucesso!")
        
        # Cria a tabela users se não existir
        supabase.table('users').select('count', count='exact').execute()
        print("Tabela 'users' verificada.")
        
        # Cria a tabela user_profiles se não existir
        supabase.table('user_profiles').select('count', count='exact').execute()
        print("Tabela 'user_profiles' verificada.")
        
        # Cria a tabela crosshairs se não existir
        supabase.table('crosshairs').select('count', count='exact').execute()
        print("Tabela 'crosshairs' verificada.")
        
        print("Todas as tabelas foram verificadas com sucesso!")
        return True
        
    except Exception as e:
        print(f"Erro ao verificar tabelas: {str(e)}")
        return False

def init_tables_sql():
    """
    Executa SQL para criar as tabelas necessárias.
    Só deve ser usado se as tabelas ainda não existirem.
    """
    try:
        # Inicializa o cliente Supabase
        supabase = init_supabase()
        
        # SQL para criar as tabelas
        sql = """
-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_pro BOOLEAN DEFAULT FALSE,
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    twofa_secret TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Tabela de perfis de usuário
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    preferences JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Tabela de miras
CREATE TABLE IF NOT EXISTS crosshairs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    data JSONB NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_crosshairs_owner ON crosshairs(owner_id);
CREATE INDEX IF NOT EXISTS idx_crosshairs_public ON crosshairs(is_public);
CREATE INDEX IF NOT EXISTS idx_user_profiles_user ON user_profiles(user_id);
        """
        
        # Executa o SQL (isso exigiria permissões de admin/service_role)
        # Descomentar se necessário e se tiver permissões adequadas
        # result = supabase.execute_sql(sql)
        # print("SQL para criação de tabelas executado com sucesso!")
        
        print("""
Para criar as tabelas manualmente, execute o seguinte SQL no Editor SQL do Supabase:

""" + sql)
        
        return True
        
    except Exception as e:
        print(f"Erro ao executar SQL: {str(e)}")
        return False

if __name__ == "__main__":
    # Primeiro, verifica se as tabelas existem
    tables_exist = create_tables()
    
    # Se as tabelas não existirem, mostra o SQL para criá-las
    if not tables_exist:
        print("\nAlgumas tabelas podem não existir. Mostrando SQL para criação...")
        init_tables_sql() 
