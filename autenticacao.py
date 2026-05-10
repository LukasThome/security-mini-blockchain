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
    return os.urandom(20)

def _hotp(segredo: bytes, contador: int, digitos: int = 6) -> str:
    contador_bytes = struct.pack('>Q', contador)
    mac = hmac.new(segredo, contador_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    codigo = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(codigo % (10 ** digitos)).zfill(digitos)

def calcular_totp(segredo: bytes, passo: int = 30, digitos: int = 6) -> str:
    contador = int(time.time()) // passo
    return _hotp(segredo, contador, digitos)

def verificar_totp(segredo: bytes, codigo: str, passo: int = 30, digitos: int = 6) -> bool:
    t_atual = int(time.time()) // passo
    for delta in (-1, 0, 1):
        esperado = _hotp(segredo, t_atual + delta, digitos)
        if hmac.compare_digest(esperado.encode(), codigo.strip().encode()):
            return True
    return False

def cadastrar_usuario(nome_usuario: str, senha: str) -> tuple:
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
    try:
        salt = bytes.fromhex(registro["salt"])
        chave = derivar_chave(senha, salt)
        texto_cifrado = bytes.fromhex(registro["dados_cifrados"])
        iv = bytes.fromhex(registro["iv"])
        dados = decifrar_aes_gcm(chave, texto_cifrado, iv)
        return json.loads(dados.decode("utf-8"))
    except:
        return None

def autenticar(registro: dict, senha: str, codigo_totp: str) -> bytes | None:
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
