#!/usr/bin/env python
"""
Script para verificar o ambiente Render e diagnosticar problemas.
"""
import os
import sys
import inspect
import importlib.util

def check_python_path():
    """Verifica o PYTHONPATH."""
    print("\n=== PYTHONPATH ===")
    for path in sys.path:
        print(f"  {path}")

def check_file_existence():
    """Verifica se os arquivos principais existem."""
    print("\n=== Verificando arquivos principais ===")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    files_to_check = [
        "main.py",
        "api/main.py",
        "api/__init__.py",
    ]
    
    for file_path in files_to_check:
        full_path = os.path.join(current_dir, file_path)
        exists = os.path.exists(full_path)
        print(f"  {file_path}: {'Existe' if exists else 'NÃO EXISTE'}")
        
        if exists:
            print(f"    Tamanho: {os.path.getsize(full_path)} bytes")
            with open(full_path, 'r') as f:
                first_line = f.readline().strip()
                print(f"    Primeira linha: {first_line}")

def check_imports():
    """Tenta importar módulos importantes."""
    print("\n=== Testando importações ===")
    
    modules_to_check = [
        "api",
        "api.main",
        "fastapi",
        "uvicorn",
    ]
    
    for module_name in modules_to_check:
        try:
            module = importlib.import_module(module_name)
            print(f"  {module_name}: Importado com sucesso")
            if module_name == "api.main":
                if hasattr(module, "app"):
                    print(f"    app encontrado em {module_name}")
                else:
                    print(f"    app NÃO encontrado em {module_name}")
        except ImportError as e:
            print(f"  {module_name}: FALHA NA IMPORTAÇÃO - {e}")

def check_env_vars():
    """Verifica variáveis de ambiente."""
    print("\n=== Variáveis de ambiente ===")
    important_vars = [
        "PORT",
        "ENVIRONMENT",
        "DEBUG",
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "JWT_SECRET",
    ]
    
    for var in important_vars:
        value = os.environ.get(var)
        if value:
            # Oculta valores sensíveis
            if var in ["SUPABASE_URL", "SUPABASE_KEY", "JWT_SECRET"]:
                print(f"  {var}: [DEFINIDO]")
            else:
                print(f"  {var}: {value}")
        else:
            print(f"  {var}: [NÃO DEFINIDO]")

if __name__ == "__main__":
    print("=== Verificação do Ambiente Render ===")
    print(f"Python: {sys.version}")
    print(f"Diretório atual: {os.getcwd()}")
    
    check_python_path()
    check_file_existence()
    check_imports()
    check_env_vars()
    
    print("\nVerificação concluída.") 
