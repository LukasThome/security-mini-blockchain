"""
Persistência de usuários e blockchain em arquivos JSON.

Regra de segurança:
  Apenas o campo 'salt' é armazenado em texto puro.
  Todos os demais dados sensíveis são cifrados com AES-GCM antes de salvar.
"""
import os
import json


def salvar_usuario(registro: dict, diretorio: str = "usuarios") -> None:
    os.makedirs(diretorio, exist_ok=True)
    caminho = os.path.join(diretorio, f"{registro['nome_usuario']}.json")
    with open(caminho, "w", encoding="utf-8") as arq:
        json.dump(registro, arq, indent=2)


def carregar_usuario(nome_usuario: str, diretorio: str = "usuarios") -> dict | None:
    caminho = os.path.join(diretorio, f"{nome_usuario}.json")
    if not os.path.exists(caminho):
        return None
    with open(caminho, encoding="utf-8") as arq:
        return json.load(arq)


def salvar_blockchain(cadeia: list, caminho: str = "blockchain.json") -> None:
    with open(caminho, "w", encoding="utf-8") as arq:
        json.dump(cadeia, arq, indent=2)


def carregar_blockchain(caminho: str = "blockchain.json") -> list:
    if not os.path.exists(caminho):
        return []
    with open(caminho, encoding="utf-8") as arq:
        return json.load(arq)
