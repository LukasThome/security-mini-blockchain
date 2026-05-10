import os
import json

def salvar_usuario(registro: dict, diretorio: str = "usuarios") -> None:
    """Salva o registro do usuário em um arquivo JSON."""
    os.makedirs(diretorio, exist_ok=True)
    caminho = os.path.join(diretorio, f"{registro['nome_usuario']}.json")
    with open(caminho, "w", encoding="utf-8") as arq:
        json.dump(registro, arq, indent=2)

def carregar_usuario(nome_usuario: str, diretorio: str = "usuarios") -> dict | None:
    """Carrega o registro do usuário a partir de um arquivo JSON."""
    caminho = os.path.join(diretorio, f"{nome_usuario}.json")
    if not os.path.exists(caminho):
        return None
    with open(caminho, encoding="utf-8") as arq:
        return json.load(arq)

def salvar_blockchain(cadeia: list, caminho: str = "blockchain.json") -> None:
    """Salva a cadeia de blocos em um arquivo JSON."""
    with open(caminho, "w", encoding="utf-8") as arq:
        json.dump(cadeia, arq, indent=2)

def carregar_blockchain(caminho: str = "blockchain.json") -> list:
    """Carrega a cadeia de blocos de um arquivo JSON."""
    if not os.path.exists(caminho):
        return []
    with open(caminho, encoding="utf-8") as arq:
        return json.load(arq)
