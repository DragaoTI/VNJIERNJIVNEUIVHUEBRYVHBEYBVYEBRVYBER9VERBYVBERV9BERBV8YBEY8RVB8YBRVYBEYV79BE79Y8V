import sys
import os
from pathlib import Path

# Adiciona o diretório pai ao path para importar módulos da API
sys.path.append(str(Path(__file__).parent.parent))

# Importa o cliente Supabase
from supabase_client import init_supabase, get_supabase

def create_tables():
    """
    Verifica se as tabelas necessárias para os códigos promocionais existem.
    """
    try:
        # Inicializa o cliente Supabase
        supabase = init_supabase()
        print("Conexão com o Supabase estabelecida com sucesso!")
        
        # Verifica a tabela de códigos promocionais
        supabase.table('promo_codes').select('count', count='exact').execute()
        print("Tabela 'promo_codes' verificada.")
        
        # Verifica a tabela de usos de códigos promocionais
        supabase.table('promo_code_uses').select('count', count='exact').execute()
        print("Tabela 'promo_code_uses' verificada.")
        
        # Verifica a tabela de logs de ações administrativas
        supabase.table('admin_action_logs').select('count', count='exact').execute()
        print("Tabela 'admin_action_logs' verificada.")
        
        print("Todas as tabelas foram verificadas com sucesso!")
        return True
        
    except Exception as e:
        print(f"Erro ao verificar tabelas: {str(e)}")
        return False

def init_tables_sql():
    """
    Exibe o SQL para criar as tabelas necessárias para os códigos promocionais.
    """
    sql = """
-- Tabela de códigos promocionais
CREATE TABLE IF NOT EXISTS promo_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT NOT NULL UNIQUE,
    reward_type TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    remaining_uses INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Tabela de usos de códigos promocionais
CREATE TABLE IF NOT EXISTS promo_code_uses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    promo_code_id UUID NOT NULL REFERENCES promo_codes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(promo_code_id, user_id)
);

-- Tabela de logs de ações administrativas
CREATE TABLE IF NOT EXISTS admin_action_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id UUID NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_promo_codes_code ON promo_codes(code);
CREATE INDEX IF NOT EXISTS idx_promo_codes_reward_type ON promo_codes(reward_type);
CREATE INDEX IF NOT EXISTS idx_promo_codes_is_active ON promo_codes(is_active);
CREATE INDEX IF NOT EXISTS idx_promo_code_uses_promo_code_id ON promo_code_uses(promo_code_id);
CREATE INDEX IF NOT EXISTS idx_promo_code_uses_user_id ON promo_code_uses(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_action_logs_admin_id ON admin_action_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_action_logs_entity_type_id ON admin_action_logs(entity_type, entity_id);
"""
    
    print("""
Para criar as tabelas de códigos promocionais, execute o seguinte SQL no Editor SQL do Supabase:

""" + sql)
    
    return sql

if __name__ == "__main__":
    # Primeiro, verifica se as tabelas existem
    tables_exist = create_tables()
    
    # Se as tabelas não existirem, mostra o SQL para criá-las
    if not tables_exist:
        print("\nAlgumas tabelas podem não existir. Mostrando SQL para criação...")
        init_tables_sql() 
