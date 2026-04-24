"""
Primitivas criptográficas do Mini-Blockchain.

- PBKDF2-HMAC-SHA256 para derivação de chaves (sem chaves fixas no código)
- AES-256-GCM para cifragem autenticada (confidencialidade + integridade)
- SHA-256 para encadeamento da blockchain

Nenhuma função usa variáveis globais para chave ou IV.
Todas as chaves são derivadas sob demanda a partir da senha do usuário.
"""
import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAMANHO_SALT = 16        # 128 bits
TAMANHO_IV = 12          # 96 bits — padrão NIST SP 800-38D para AES-GCM
TAMANHO_CHAVE = 32       # 256 bits (AES-256)
ITERACOES_KDF = 100_000  # NIST SP 800-132 recomenda ≥ 10.000


def gerar_salt(tamanho: int = TAMANHO_SALT) -> bytes:
    """Gera salt criptograficamente seguro."""
    return os.urandom(tamanho)


def gerar_iv(tamanho: int = TAMANHO_IV) -> bytes:
    """Gera IV único e aleatório para AES-GCM."""
    return os.urandom(tamanho)


def derivar_chave(senha: str, salt: bytes, comprimento: int = TAMANHO_CHAVE) -> bytes:
    """PBKDF2-HMAC-SHA256. Determinística: mesma senha+salt → mesma chave."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=comprimento,
        salt=salt,
        iterations=ITERACOES_KDF,
    )
    return kdf.derive(senha.encode("utf-8"))


def cifrar_aes_gcm(chave: bytes, dados: bytes, iv: bytes = None) -> tuple:
    """
    Cifragem autenticada AES-256-GCM.
    A tag (16 bytes) é incluída no texto_cifrado pela biblioteca.
    Retorna (texto_cifrado_com_tag, iv).
    """
    if iv is None:
        iv = gerar_iv()
    aes = AESGCM(chave)
    texto_cifrado = aes.encrypt(iv, dados, None)
    return texto_cifrado, iv


def decifrar_aes_gcm(chave: bytes, texto_cifrado: bytes, iv: bytes) -> bytes:
    """
    Decifragem + verificação de autenticidade AES-256-GCM.
    Lança InvalidTag se os dados foram adulterados.
    """
    aes = AESGCM(chave)
    return aes.decrypt(iv, texto_cifrado, None)


def calcular_hash(dados: bytes) -> str:
    """SHA-256 como string hexadecimal de 64 caracteres."""
    return hashlib.sha256(dados).hexdigest()
