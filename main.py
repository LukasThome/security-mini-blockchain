"""
Mini-Blockchain Simétrica com Autenticação de Usuário
Disciplina: Segurança da Informação — UFSC

Uso:
  python3 main.py
"""
import dataclasses
from autenticacao import cadastrar_usuario, autenticar, calcular_totp, gerar_segredo_totp
from blockchain import adicionar_bloco, validar_cadeia, ler_blocos_usuario, hash_bloco, HASH_GENESIS
from armazenamento import salvar_usuario, carregar_usuario, salvar_blockchain, carregar_blockchain


@dataclasses.dataclass
class Sessao:
    nome_usuario: str
    chave_sessao: bytes


def _menu_principal() -> str:
    print("\n=== Mini-Blockchain ===")
    print("1. Cadastrar usuário")
    print("2. Login")
    print("3. Adicionar bloco")
    print("4. Ler meus blocos")
    print("5. Validar cadeia")
    print("6. Listar todos os blocos")
    print("0. Sair")
    return input("Opção: ").strip()


def _cadastrar():
    nome = input("Username: ").strip()
    if not nome:
        print("Username inválido.")
        return
    if carregar_usuario(nome):
        print("Usuário já existe.")
        return
    senha = input("Senha: ").strip()
    registro, segredo_totp = cadastrar_usuario(nome, senha)
    salvar_usuario(registro)
    print(f"\nCadastro realizado!")
    print(f"Segredo TOTP (configure no autenticador): {segredo_totp.hex()}")
    print("(Em produção, este segredo seria exibido como QR code)")


def _login() -> Sessao | None:
    nome = input("Username: ").strip()
    registro = carregar_usuario(nome)
    if not registro:
        print("Usuário não encontrado.")
        return None
    senha = input("Senha: ").strip()
    codigo = input("Código TOTP (6 dígitos): ").strip()
    chave = autenticar(registro, senha, codigo)
    if chave is None:
        print("Autenticação falhou.")
        return None
    print(f"Login bem-sucedido! Bem-vindo, {nome}.")
    return Sessao(nome_usuario=nome, chave_sessao=chave)


def _adicionar_bloco(sessao: Sessao):
    cadeia = carregar_blockchain()
    dados = input("Dados do bloco: ").strip()
    if not dados:
        print("Dados inválidos.")
        return
    nova_cadeia = adicionar_bloco(cadeia, dados, sessao.nome_usuario, sessao.chave_sessao)
    salvar_blockchain(nova_cadeia)
    print(f"Bloco adicionado! Total de blocos: {len(nova_cadeia)}")


def _ler_meus_blocos(sessao: Sessao):
    cadeia = carregar_blockchain()
    blocos = ler_blocos_usuario(cadeia, sessao.nome_usuario, sessao.chave_sessao)
    if not blocos:
        print("Nenhum bloco seu na cadeia.")
        return
    print(f"\nSeus blocos ({len(blocos)}):")
    for i, dado in enumerate(blocos, 1):
        if dado is None:
            print(f"  [{i}] ⚠ BLOCO ADULTERADO")
        else:
            print(f"  [{i}] {dado}")


def _validar_cadeia():
    cadeia = carregar_blockchain()
    if validar_cadeia(cadeia):
        print(f"Cadeia válida. ({len(cadeia)} blocos)")
    else:
        print("CADEIA INVÁLIDA — integridade comprometida!")


def _listar_blocos():
    cadeia = carregar_blockchain()
    if not cadeia:
        print("Cadeia vazia.")
        return
    print(f"\nTodos os blocos ({len(cadeia)}):")
    for i, bloco in enumerate(cadeia):
        print(f"  [{i}] dono={bloco['dono']}  hash_ant={bloco['hash_anterior'][:12]}...")


def main():
    sessao = None
    while True:
        opcao = _menu_principal()
        if opcao == "0":
            break
        elif opcao == "1":
            _cadastrar()
        elif opcao == "2":
            sessao = _login()
        elif opcao in ("3", "4"):
            if sessao is None:
                print("Faça login primeiro.")
            elif opcao == "3":
                _adicionar_bloco(sessao)
            else:
                _ler_meus_blocos(sessao)
        elif opcao == "5":
            _validar_cadeia()
        elif opcao == "6":
            _listar_blocos()


if __name__ == "__main__":
    main()
