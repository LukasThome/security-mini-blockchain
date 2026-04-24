"""
Cadastro e autenticação de usuários com senha + TOTP.

TOTP implementado manualmente conforme RFC 6238 (HMAC-SHA1 + janela de tempo).
Chave de sessão derivada com PBKDF2 para cifragem/decifragem dos blocos do usuário.
"""
import os
import struct
import time
import hmac
import hashlib
import json
from criptografia import derivar_chave, gerar_salt, cifrar_aes_gcm, decifrar_aes_gcm

_CONTEXTO_VERIFICACAO = b":verificacao"
_CONTEXTO_SESSAO = b":sessao"


def gerar_segredo_totp() -> bytes:
    """Segredo TOTP aleatório de 20 bytes (160 bits)."""
    return os.urandom(20)


def _hotp(segredo: bytes, contador: int, digitos: int = 6) -> str:
    """
    HMAC-based One-Time Password (RFC 4226).
    HMAC-SHA1 truncado para `digitos` dígitos decimais.
    """
    contador_bytes = struct.pack('>Q', contador)
    mac = hmac.new(segredo, contador_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    codigo = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(codigo % (10 ** digitos)).zfill(digitos)


def calcular_totp(segredo: bytes, passo: int = 30, digitos: int = 6) -> str:
    """TOTP = HOTP(segredo, T) onde T = floor(tempo_unix / passo). RFC 6238."""
    contador = int(time.time()) // passo
    return _hotp(segredo, contador, digitos)


def verificar_totp(segredo: bytes, codigo: str, passo: int = 30, digitos: int = 6) -> bool:
    """
    Verifica TOTP com janela de ±1 passo (±30s).
    Usa hmac.compare_digest para prevenir timing attacks.
    """
    t_atual = int(time.time()) // passo
    for delta in (-1, 0, 1):
        esperado = _hotp(segredo, t_atual + delta, digitos)
        if hmac.compare_digest(esperado.encode(), codigo.strip().encode()):
            return True
    return False


def cadastrar_usuario(nome_usuario: str, senha: str) -> tuple:
    """
    Cria registro cifrado do usuário.

    Retorna (registro, segredo_totp) onde:
      registro     : dict a ser salvo (salt em texto puro, resto cifrado com AES-GCM)
      segredo_totp : bytes exibido ao usuário para configurar o autenticador TOTP

    Campos do registro:
      salt          → único campo em texto puro
      dados_cifrados → AES-GCM({ hash_senha, segredo_totp })
      iv            → IV do AES-GCM
    """
    salt = gerar_salt()
    segredo_totp = gerar_segredo_totp()
    chave_armazenamento = derivar_chave(senha, salt)
    hash_senha = derivar_chave(senha, salt + _CONTEXTO_VERIFICACAO)

    dados_sensiveis = json.dumps({
        "hash_senha": hash_senha.hex(),
        "segredo_totp": segredo_totp.hex(),
    }).encode("utf-8")

    texto_cifrado, iv = cifrar_aes_gcm(chave_armazenamento, dados_sensiveis)

    registro = {
        "nome_usuario": nome_usuario,
        "salt": salt.hex(),
        "dados_cifrados": texto_cifrado.hex(),
        "iv": iv.hex(),
    }
    return registro, segredo_totp


def _decifrar_registro(registro: dict, senha: str) -> dict | None:
    """Decifra dados internos do registro. Retorna None se senha errada ou dado adulterado."""
    try:
        salt = bytes.fromhex(registro["salt"])
        chave = derivar_chave(senha, salt)
        texto_cifrado = bytes.fromhex(registro["dados_cifrados"])
        iv = bytes.fromhex(registro["iv"])
        dados = decifrar_aes_gcm(chave, texto_cifrado, iv)
        return json.loads(dados.decode("utf-8"))
    except Exception:
        return None


def autenticar(registro: dict, senha: str, codigo_totp: str) -> bytes | None:
    """
    Autentica usuário com senha + TOTP.
    Retorna chave_de_sessao (bytes) se bem-sucedido, None caso contrário.
    A chave é determinística: mesmo usuário+senha → mesma chave de sessão.
    """
    dados = _decifrar_registro(registro, senha)
    if dados is None:
        return None

    salt = bytes.fromhex(registro["salt"])

    hash_esperado = bytes.fromhex(dados["hash_senha"])
    hash_fornecido = derivar_chave(senha, salt + _CONTEXTO_VERIFICACAO)
    if not hmac.compare_digest(hash_esperado, hash_fornecido):
        return None

    segredo_totp = bytes.fromhex(dados["segredo_totp"])
    if not verificar_totp(segredo_totp, codigo_totp):
        return None

    return derivar_chave(senha, salt + _CONTEXTO_SESSAO)
