#!/bin/bash

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Iniciando setup do ambiente...${NC}"

# Verifica se Python 3.8+ está instalado
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 não encontrado. Por favor, instale o Python 3.8 ou superior.${NC}"
    exit 1
fi

# Cria e ativa ambiente virtual
echo -e "${YELLOW}Criando ambiente virtual...${NC}"
python3 -m venv venv
source venv/bin/activate

# Atualiza pip
echo -e "${YELLOW}Atualizando pip...${NC}"
pip install --upgrade pip

# Instala dependências
echo -e "${YELLOW}Instalando dependências...${NC}"
pip install -r requirements.txt

# Verifica instalação
echo -e "${YELLOW}Verificando instalação...${NC}"
python3 -c "import fastapi; import uvicorn; import pydantic; import supabase; print('Dependências principais instaladas com sucesso!')"

# Cria diretórios necessários
echo -e "${YELLOW}Criando diretórios necessários...${NC}"
mkdir -p logs
mkdir -p app/core/keys

# Verifica variáveis de ambiente
echo -e "${YELLOW}Verificando variáveis de ambiente...${NC}"
if [ ! -f .env ]; then
    echo -e "${YELLOW}Criando arquivo .env...${NC}"
    cat > .env << EOL
# Configurações básicas
APP_NAME="CrosshairLab API"
ENVIRONMENT="development"
DEBUG=true

# Supabase
SUPABASE_URL=""
SUPABASE_KEY=""

# JWT
JWT_ALGORITHM="RS256"
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# Rate Limiting
RATE_LIMIT_LOGIN_ATTEMPTS="5/minute"
RATE_LIMIT_API_CALLS="100/minute"
RATE_LIMIT_IP_BLOCK_DURATION=3600

# Logging
LOG_LEVEL="INFO"
LOG_FORMAT="json"
LOG_FILE="api.log"
LOG_MAX_SIZE=10485760
LOG_BACKUP_COUNT=5

# Cache
CACHE_ENABLED=true
CACHE_TTL=300
CACHE_MAX_SIZE=1000
EOL
    echo -e "${YELLOW}Arquivo .env criado. Por favor, configure as variáveis necessárias.${NC}"
fi

# Gera chaves JWT se não existirem
echo -e "${YELLOW}Verificando chaves JWT...${NC}"
if [ ! -f app/core/keys/private.pem ] || [ ! -f app/core/keys/public.pem ]; then
    echo -e "${YELLOW}Gerando chaves JWT...${NC}"
    openssl genrsa -out app/core/keys/private.pem 2048
    openssl rsa -in app/core/keys/private.pem -pubout -out app/core/keys/public.pem
fi

# Configura pre-commit hooks
echo -e "${YELLOW}Configurando pre-commit hooks...${NC}"
if [ -d .git ]; then
    pip install pre-commit
    pre-commit install
fi

echo -e "${GREEN}Setup concluído com sucesso!${NC}"
echo -e "${YELLOW}Próximos passos:${NC}"
echo "1. Configure as variáveis no arquivo .env"
echo "2. Ative o ambiente virtual: source venv/bin/activate"
echo "3. Execute a aplicação: uvicorn app.main:app --reload" 