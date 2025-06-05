import os
import sys

# Adiciona o diretório atual ao PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importa o app do módulo main.py dentro da pasta api
from api.main import app

# Este arquivo serve apenas como um ponto de entrada para o Uvicorn
