import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAMANHO_SALT = 16
TAMANHO_IV = 12
TAMANHO_CHAVE = 32
ITERACOES_KDF = 100_000

def gerar_salt(tamanho: int = TAMANHO_SALT) -> bytes:
    return os.urandom(tamanho)

def gerar_iv(tamanho: int = TAMANHO_IV) -> bytes:
    return os.urandom(tamanho)

def derivar_chave(senha: str, salt: bytes, comprimento: int = TAMANHO_CHAVE) -> bytes:
    """Deriva uma chave usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=comprimento,
        salt=salt,
        iterations=ITERACOES_KDF,
    )
    return kdf.derive(senha.encode("utf-8"))

def cifrar_aes_gcm(chave: bytes, dados: bytes, iv: bytes = None) -> tuple:
    """Cifra dados usando AES-GCM."""
    if iv is None:
        iv = gerar_iv()
    aes = AESGCM(chave)
    texto_cifrado = aes.encrypt(iv, dados, None)
    return texto_cifrado, iv

def decifrar_aes_gcm(chave: bytes, texto_cifrado: bytes, iv: bytes) -> bytes:
    """Decifra dados usando AES-GCM."""
    aes = AESGCM(chave)
    return aes.decrypt(iv, texto_cifrado, None)

def calcular_hash(dados: bytes) -> str:
    """Calcula o hash SHA-256."""
    return hashlib.sha256(dados).hexdigest()
