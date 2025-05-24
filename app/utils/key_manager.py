import base64
import os
import json
import time
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import secrets
from app.core.config import settings
from app.utils.encryption import DataEncryption

class KeyManager:
    """
    Gerenciador de chaves de criptografia para rotação segura de chaves
    """
    
    def __init__(self, rotation_interval: int = 86400, key_file: Optional[str] = None):
        """
        Inicializa o gerenciador de chaves
        
        Args:
            rotation_interval: Intervalo de rotação de chaves em segundos (padrão: 1 dia)
            key_file: Arquivo para armazenar as chaves (opcional)
        """
        self.current_key_id = None
        self.keys = {}
        self.rotation_interval = rotation_interval
        self.key_file = key_file
        self._lock = threading.Lock()
        
        # Carrega chaves existentes ou gera uma nova
        self._load_or_create_keys()
        
        # Inicia o thread de rotação de chaves se em produção
        if settings.ENVIRONMENT == "production":
            self._start_key_rotation_thread()
    
    def _load_or_create_keys(self) -> None:
        """
        Carrega chaves de um arquivo ou cria uma nova chave
        """
        with self._lock:
            if self.key_file and os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'r') as f:
                        keys_data = json.load(f)
                    
                    # Carrega as chaves
                    self.keys = keys_data.get('keys', {})
                    self.current_key_id = keys_data.get('current_key_id')
                    
                    # Verifica se a chave atual existe
                    if not self.current_key_id or self.current_key_id not in self.keys:
                        # Gera uma nova chave se a atual não for válida
                        self._generate_new_key()
                except Exception as e:
                    print(f"Erro ao carregar chaves: {str(e)}")
                    self._generate_new_key()
            else:
                # Não há arquivo de chaves, então gera uma nova
                self._generate_new_key()
    
    def _generate_new_key(self) -> str:
        """
        Gera uma nova chave de criptografia
        
        Returns:
            ID da nova chave
        """
        with self._lock:
            # Cria um novo ID de chave baseado em UUID
            new_key_id = str(uuid.uuid4())
            
            # Gera uma chave segura usando secrets
            key_bytes = secrets.token_bytes(32)  # 256 bits
            key_base64 = base64.urlsafe_b64encode(key_bytes).decode()
            
            # Armazena a nova chave com metadados
            self.keys[new_key_id] = {
                'key': key_base64,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(seconds=self.rotation_interval*2)).isoformat(),
                'active': True
            }
            
            # Define a nova chave como atual
            self.current_key_id = new_key_id
            
            # Salva as chaves no arquivo, se configurado
            self._save_keys()
            
            return new_key_id
    
    def _save_keys(self) -> None:
        """
        Salva as chaves em um arquivo, se configurado
        """
        if not self.key_file:
            return
            
        with self._lock:
            try:
                keys_data = {
                    'current_key_id': self.current_key_id,
                    'keys': self.keys,
                    'last_updated': datetime.utcnow().isoformat()
                }
                
                # Cria o diretório se não existir
                os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
                
                # Salva as chaves em um arquivo temporário primeiro
                temp_file = f"{self.key_file}.tmp"
                with open(temp_file, 'w') as f:
                    json.dump(keys_data, f)
                
                # Renomeia o arquivo temporário para o arquivo final
                # Isso ajuda a evitar corrupção se houver uma falha durante a escrita
                os.replace(temp_file, self.key_file)
            except Exception as e:
                print(f"Erro ao salvar chaves: {str(e)}")
    
    def _start_key_rotation_thread(self) -> None:
        """
        Inicia um thread para rotação periódica das chaves
        """
        rotation_thread = threading.Thread(
            target=self._key_rotation_worker,
            daemon=True
        )
        rotation_thread.start()
    
    def _key_rotation_worker(self) -> None:
        """
        Worker para rotação periódica das chaves
        """
        while True:
            # Dorme pelo intervalo de rotação
            time.sleep(self.rotation_interval)
            
            try:
                # Gera uma nova chave
                self.rotate_keys()
            except Exception as e:
                print(f"Erro na rotação de chaves: {str(e)}")
    
    def rotate_keys(self) -> str:
        """
        Realiza a rotação de chaves, gerando uma nova chave atual
        
        Returns:
            ID da nova chave
        """
        with self._lock:
            # Marca as chaves expiradas
            now = datetime.utcnow()
            for key_id, key_data in self.keys.items():
                expires_at = datetime.fromisoformat(key_data['expires_at'])
                if expires_at < now:
                    key_data['active'] = False
            
            # Gera uma nova chave
            new_key_id = self._generate_new_key()
            
            # Remove chaves muito antigas (2x o intervalo de rotação)
            cutoff_time = now - timedelta(seconds=self.rotation_interval*4)
            self.keys = {
                k: v for k, v in self.keys.items()
                if datetime.fromisoformat(v['created_at']) > cutoff_time or k == self.current_key_id
            }
            
            # Salva as alterações
            self._save_keys()
            
            return new_key_id
    
    def get_current_key(self) -> Tuple[str, str]:
        """
        Obtém a chave de criptografia atual
        
        Returns:
            Tupla (key_id, key_value)
        """
        with self._lock:
            if not self.current_key_id or self.current_key_id not in self.keys:
                self._generate_new_key()
            
            return (self.current_key_id, self.keys[self.current_key_id]['key'])
    
    def get_key_by_id(self, key_id: str) -> Optional[str]:
        """
        Obtém uma chave pelo seu ID
        
        Args:
            key_id: ID da chave
            
        Returns:
            Valor da chave ou None se não encontrada
        """
        with self._lock:
            if key_id in self.keys:
                return self.keys[key_id]['key']
            return None
    
    def encrypt_data(self, data: Any) -> Dict[str, Any]:
        """
        Criptografa dados usando a chave atual
        
        Args:
            data: Dados a serem criptografados
            
        Returns:
            Dicionário com key_id e dados criptografados
        """
        key_id, key_value = self.get_current_key()
        encryptor = DataEncryption(key_value)
        
        # Criptografa os dados
        encrypted_data = encryptor.encrypt(data)
        
        return {
            'key_id': key_id,
            'data': encrypted_data
        }
    
    def decrypt_data(self, encrypted_package: Dict[str, Any]) -> Any:
        """
        Descriptografa dados usando a chave correspondente
        
        Args:
            encrypted_package: Pacote com key_id e dados criptografados
            
        Returns:
            Dados descriptografados
        """
        key_id = encrypted_package.get('key_id')
        encrypted_data = encrypted_package.get('data')
        
        if not key_id or not encrypted_data:
            raise ValueError("Pacote de dados criptografados inválido")
        
        # Obtém a chave pelo ID
        key_value = self.get_key_by_id(key_id)
        if not key_value:
            raise ValueError(f"Chave não encontrada para ID: {key_id}")
        
        # Descriptografa os dados
        encryptor = DataEncryption(key_value)
        return encryptor.decrypt(encrypted_data)

# Instância global do gerenciador de chaves
key_file_path = None
if hasattr(settings, "KEY_MANAGER_FILE"):
    key_file_path = settings.KEY_MANAGER_FILE

key_manager = KeyManager(
    rotation_interval=getattr(settings, "KEY_ROTATION_INTERVAL", 86400),
    key_file=key_file_path
) 