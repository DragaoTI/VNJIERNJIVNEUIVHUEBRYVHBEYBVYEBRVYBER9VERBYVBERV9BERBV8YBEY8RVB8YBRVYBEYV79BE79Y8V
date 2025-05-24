from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from typing import Dict, Any, Optional, Union
from app.core.config import settings

class DataEncryption:
    """
    Classe para criptografar e descriptografar dados sensíveis usando Fernet
    com derivação de chave segura (PBKDF2HMAC).
    """
    
    def __init__(self, key: Optional[str] = None):
        """
        Inicializa o encriptador com uma chave.
        Se nenhuma chave for fornecida, utiliza a chave da configuração ou gera uma nova.
        """
        if key:
            self.key = key
        else:
            # Usa a chave das configurações ou gera uma nova
            self.key = settings.ENCRYPTION_KEY
            
            if not self.key:
                # Gera e exibe uma nova chave - para ser configurada nas variáveis de ambiente
                self.key = self._generate_key()
                print(f"[AVISO] Nenhuma chave de criptografia encontrada!")
                print(f"[AVISO] Adicione a seguinte chave à sua configuração:")
                print(f"ENCRYPTION_KEY={self.key}")
        
        # Deriva a chave Fernet a partir da chave fornecida
        salt = b'crosshairlab_salt_key'  # Salt fixo para reprodutibilidade
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_bytes = self.key.encode()
        key_derived = base64.urlsafe_b64encode(kdf.derive(key_bytes))
        
        # Cria o encriptador Fernet
        self.fernet = Fernet(key_derived)
    
    def _generate_key(self) -> str:
        """
        Gera uma nova chave de criptografia segura.
        """
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def encrypt(self, data: Union[str, Dict[str, Any], bytes]) -> str:
        """
        Criptografa dados em formato string, dicionário ou bytes.
        Retorna a string criptografada em base64.
        """
        if isinstance(data, dict):
            # Converte dicionário para JSON
            data_str = json.dumps(data)
        elif isinstance(data, str):
            data_str = data
        elif isinstance(data, bytes):
            data_str = data.decode('utf-8')
        else:
            raise ValueError("Tipo de dado não suportado para criptografia")
        
        # Criptografa os dados
        encrypted_data = self.fernet.encrypt(data_str.encode())
        
        # Retorna como string base64
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Descriptografa dados em formato string base64.
        Retorna a string original.
        """
        try:
            # Decodifica base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            
            # Descriptografa
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            
            # Retorna como string
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Erro ao descriptografar dados: {str(e)}")
    
    def decrypt_to_dict(self, encrypted_data: str) -> Dict[str, Any]:
        """
        Descriptografa dados e converte para dicionário.
        Útil para dados JSON criptografados.
        """
        decrypted_str = self.decrypt(encrypted_data)
        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError:
            raise ValueError("Os dados descriptografados não são um JSON válido")
    
    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """
        Criptografa um arquivo e salva o resultado.
        Se output_path for None, sobrescreve o arquivo original.
        Retorna o caminho do arquivo criptografado.
        """
        if not output_path:
            output_path = file_path + ".enc"
        
        try:
            # Lê o arquivo
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Criptografa
            encrypted_data = self.fernet.encrypt(data)
            
            # Salva
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return output_path
        except Exception as e:
            raise ValueError(f"Erro ao criptografar arquivo: {str(e)}")
    
    def decrypt_file(self, encrypted_file_path: str, output_path: Optional[str] = None) -> str:
        """
        Descriptografa um arquivo e salva o resultado.
        Se output_path for None, usa o nome do arquivo sem a extensão .enc.
        Retorna o caminho do arquivo descriptografado.
        """
        if not output_path:
            if encrypted_file_path.endswith(".enc"):
                output_path = encrypted_file_path[:-4]
            else:
                output_path = encrypted_file_path + ".dec"
        
        try:
            # Lê o arquivo criptografado
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Descriptografa
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Salva
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return output_path
        except Exception as e:
            raise ValueError(f"Erro ao descriptografar arquivo: {str(e)}")

# Instância global para uso em toda a aplicação
encryption = DataEncryption() 