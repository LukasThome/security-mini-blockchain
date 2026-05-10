import json
import time
from criptografia import cifrar_aes_gcm, decifrar_aes_gcm, calcular_hash, gerar_iv

HASH_GENESIS = "0" * 64

def criar_bloco(dados: str, dono: str, chave_sessao: bytes, hash_anterior: str) -> dict:
    iv = gerar_iv()
    texto_cifrado, iv_usado = cifrar_aes_gcm(chave_sessao, dados.encode("utf-8"), iv)
    return {
        "dono": dono,
        "timestamp": time.time(),
        "hash_anterior": hash_anterior,
        "iv": iv_usado.hex(),
        "dados_cifrados": texto_cifrado.hex(),
    }

def hash_bloco(bloco: dict) -> str:
    conteudo = json.dumps({
        "dono": bloco["dono"],
        "timestamp": bloco["timestamp"],
        "hash_anterior": bloco["hash_anterior"],
        "iv": bloco["iv"],
        "dados_cifrados": bloco["dados_cifrados"],
    }, sort_keys=True).encode("utf-8")
    return calcular_hash(conteudo)

def adicionar_bloco(cadeia: list, dados: str, dono: str, chave_sessao: bytes) -> list:
    hash_ant = hash_bloco(cadeia[-1]) if cadeia else HASH_GENESIS
    return cadeia + [criar_bloco(dados, dono, chave_sessao, hash_ant)]

def validar_cadeia(cadeia: list) -> bool:
    if not cadeia:
        return True
    if cadeia[0]["hash_anterior"] != HASH_GENESIS:
        return False
    for i in range(1, len(cadeia)):
        if cadeia[i]["hash_anterior"] != hash_bloco(cadeia[i - 1]):
            return False
    return True

def ler_blocos_usuario(cadeia: list, nome_usuario: str, chave_sessao: bytes) -> list:
    resultados = []
    for bloco in cadeia:
        if bloco["dono"] != nome_usuario:
            continue
        try:
            iv = bytes.fromhex(bloco["iv"])
            texto_cifrado = bytes.fromhex(bloco["dados_cifrados"])
            dados = decifrar_aes_gcm(chave_sessao, texto_cifrado, iv)
            resultados.append(dados.decode("utf-8"))
        except:
            resultados.append(None)
    return resultados

def verificar_integridade_bloco(bloco: dict, hash_anterior: str, chave_sessao: bytes) -> bool:
    if bloco["hash_anterior"] != hash_anterior:
        return False
    try:
        iv = bytes.fromhex(bloco["iv"])
        texto_cifrado = bytes.fromhex(bloco["dados_cifrados"])
        decifrar_aes_gcm(chave_sessao, texto_cifrado, iv)
        return True
    except:
        return False
