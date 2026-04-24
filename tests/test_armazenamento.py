"""
Testes para persistência em arquivos (armazenamento.py).

Cobre:
  - salvar_usuario / carregar_usuario : round-trip, usuário inexistente
  - salvar_blockchain / carregar_blockchain : round-trip, vazia, ordem, campos
  - Segurança: arquivo de usuário não expõe dados sensíveis em texto puro
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from autenticacao import cadastrar_usuario
from criptografia import derivar_chave, gerar_salt
from blockchain import adicionar_bloco
from armazenamento import (
    salvar_usuario, carregar_usuario,
    salvar_blockchain, carregar_blockchain,
)


@pytest.fixture
def registro_alice(tmp_path):
    registro, _ = cadastrar_usuario("alice", "senha_segura_123")
    return registro


@pytest.fixture
def chave_alice():
    return derivar_chave("senha_alice", gerar_salt())


@pytest.fixture
def cadeia_simples(chave_alice):
    cadeia = []
    cadeia = adicionar_bloco(cadeia, "tx1", "alice", chave_alice)
    cadeia = adicionar_bloco(cadeia, "tx2", "alice", chave_alice)
    return cadeia


# ---------------------------------------------------------------------------
# salvar_usuario / carregar_usuario
# ---------------------------------------------------------------------------
class TestArmazenamentoUsuario:
    def test_salvar_e_carregar_round_trip(self, registro_alice, tmp_path):
        salvar_usuario(registro_alice, str(tmp_path))
        carregado = carregar_usuario("alice", str(tmp_path))
        assert carregado == registro_alice

    def test_usuario_inexistente_retorna_none(self, tmp_path):
        resultado = carregar_usuario("nao_existe", str(tmp_path))
        assert resultado is None

    def test_cria_diretorio_se_nao_existir(self, registro_alice, tmp_path):
        novo_dir = str(tmp_path / "novo_subdir")
        salvar_usuario(registro_alice, novo_dir)
        assert os.path.isdir(novo_dir)

    def test_arquivo_criado_com_nome_correto(self, registro_alice, tmp_path):
        salvar_usuario(registro_alice, str(tmp_path))
        assert os.path.exists(os.path.join(str(tmp_path), "alice.json"))

    def test_arquivo_nao_contem_senha_em_texto_puro(self, registro_alice, tmp_path):
        """Senha nunca deve aparecer em texto puro no arquivo salvo."""
        salvar_usuario(registro_alice, str(tmp_path))
        conteudo = open(os.path.join(str(tmp_path), "alice.json")).read()
        assert "senha_segura_123" not in conteudo

    def test_arquivo_contem_salt_em_texto_puro(self, registro_alice, tmp_path):
        """Salt deve ser o único campo sensível em texto puro."""
        salvar_usuario(registro_alice, str(tmp_path))
        dados = json.loads(open(os.path.join(str(tmp_path), "alice.json")).read())
        assert "salt" in dados
        bytes.fromhex(dados["salt"])  # deve ser hex válido

    def test_arquivo_contem_dados_cifrados(self, registro_alice, tmp_path):
        """Dados sensíveis devem estar presentes mas cifrados."""
        salvar_usuario(registro_alice, str(tmp_path))
        dados = json.loads(open(os.path.join(str(tmp_path), "alice.json")).read())
        assert "dados_cifrados" in dados
        assert "iv" in dados

    def test_dois_usuarios_arquivos_separados(self, tmp_path):
        r_alice, _ = cadastrar_usuario("alice", "senha_a")
        r_bob, _ = cadastrar_usuario("bob", "senha_b")
        salvar_usuario(r_alice, str(tmp_path))
        salvar_usuario(r_bob, str(tmp_path))
        assert os.path.exists(os.path.join(str(tmp_path), "alice.json"))
        assert os.path.exists(os.path.join(str(tmp_path), "bob.json"))
        assert carregar_usuario("alice", str(tmp_path)) == r_alice
        assert carregar_usuario("bob", str(tmp_path)) == r_bob


# ---------------------------------------------------------------------------
# salvar_blockchain / carregar_blockchain
# ---------------------------------------------------------------------------
class TestArmazenamentoBlockchain:
    def test_blockchain_vazia_retorna_lista_vazia(self, tmp_path):
        caminho = str(tmp_path / "chain.json")
        assert carregar_blockchain(caminho) == []

    def test_salvar_e_carregar_round_trip(self, cadeia_simples, tmp_path):
        caminho = str(tmp_path / "chain.json")
        salvar_blockchain(cadeia_simples, caminho)
        carregada = carregar_blockchain(caminho)
        assert len(carregada) == len(cadeia_simples)

    def test_preserva_ordem_dos_blocos(self, cadeia_simples, tmp_path):
        caminho = str(tmp_path / "chain.json")
        salvar_blockchain(cadeia_simples, caminho)
        carregada = carregar_blockchain(caminho)
        for original, carregado in zip(cadeia_simples, carregada):
            assert original["hash_anterior"] == carregado["hash_anterior"]
            assert original["dono"] == carregado["dono"]

    def test_preserva_todos_os_campos(self, cadeia_simples, tmp_path):
        caminho = str(tmp_path / "chain.json")
        salvar_blockchain(cadeia_simples, caminho)
        carregada = carregar_blockchain(caminho)
        campos = ("dono", "timestamp", "hash_anterior", "iv", "dados_cifrados")
        for bloco in carregada:
            for campo in campos:
                assert campo in bloco

    def test_arquivo_inexistente_retorna_lista_vazia(self, tmp_path):
        caminho = str(tmp_path / "nao_existe.json")
        assert carregar_blockchain(caminho) == []

    def test_dados_cifrados_preservados_intactos(self, cadeia_simples, tmp_path):
        """Os dados cifrados não devem ser alterados pela serialização."""
        caminho = str(tmp_path / "chain.json")
        salvar_blockchain(cadeia_simples, caminho)
        carregada = carregar_blockchain(caminho)
        for original, carregado in zip(cadeia_simples, carregada):
            assert original["dados_cifrados"] == carregado["dados_cifrados"]
            assert original["iv"] == carregado["iv"]
