"""
Testes para a mini-blockchain (blockchain.py).

Cobre:
  - criar_bloco              : campos obrigatórios, cifrado, IV único
  - hash_bloco               : determinismo, sensibilidade a alterações
  - adicionar_bloco          : encadeamento, crescimento da cadeia
  - validar_cadeia           : cadeia correta/adulterada/hash_prev errado
  - ler_blocos_usuario       : dono lê seus dados; outro usuário não decifra
  - verificar_integridade_bloco: hash e tag AES-GCM corretos
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from criptografia import derivar_chave, gerar_salt
from blockchain import (
    criar_bloco, hash_bloco, adicionar_bloco,
    validar_cadeia, ler_blocos_usuario,
    verificar_integridade_bloco, HASH_GENESIS,
)


@pytest.fixture
def chave_alice():
    return derivar_chave("senha_alice", gerar_salt())


@pytest.fixture
def chave_bob():
    return derivar_chave("senha_bob", gerar_salt())


@pytest.fixture
def cadeia_com_dois_usuarios(chave_alice, chave_bob):
    cadeia = []
    cadeia = adicionar_bloco(cadeia, "transacao_alice_1", "alice", chave_alice)
    cadeia = adicionar_bloco(cadeia, "transacao_bob_1", "bob", chave_bob)
    cadeia = adicionar_bloco(cadeia, "transacao_alice_2", "alice", chave_alice)
    return cadeia


# ---------------------------------------------------------------------------
# criar_bloco
# ---------------------------------------------------------------------------
class TestCriarBloco:
    def test_campos_obrigatorios(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        for campo in ("dono", "timestamp", "hash_anterior", "iv", "dados_cifrados"):
            assert campo in bloco, f"Campo '{campo}' ausente"

    def test_dono_correto(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert bloco["dono"] == "alice"

    def test_hash_anterior_correto(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert bloco["hash_anterior"] == HASH_GENESIS

    def test_timestamp_presente(self, chave_alice):
        import time
        antes = time.time()
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        depois = time.time()
        assert antes <= bloco["timestamp"] <= depois

    def test_dados_cifrados_diferentes_do_original(self, chave_alice):
        bloco = criar_bloco("minha transacao", "alice", chave_alice, HASH_GENESIS)
        assert bloco["dados_cifrados"] != "minha transacao"
        assert "minha transacao" not in bloco["dados_cifrados"]

    def test_iv_unico_por_bloco(self, chave_alice):
        """Dois blocos com os mesmos dados devem ter IVs diferentes."""
        b1 = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        b2 = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert b1["iv"] != b2["iv"]

    def test_iv_e_dados_sao_hex(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        bytes.fromhex(bloco["iv"])           # não lança = hex válido
        bytes.fromhex(bloco["dados_cifrados"])


# ---------------------------------------------------------------------------
# hash_bloco
# ---------------------------------------------------------------------------
class TestHashBloco:
    def test_retorna_string_hex_64(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        h = hash_bloco(bloco)
        assert isinstance(h, str) and len(h) == 64

    def test_deterministica(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert hash_bloco(bloco) == hash_bloco(bloco)

    def test_campo_alterado_muda_hash(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        hash_original = hash_bloco(bloco)
        bloco_modificado = dict(bloco, dono="bob")
        assert hash_bloco(bloco_modificado) != hash_original

    def test_dados_adulterados_muda_hash(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        hash_original = hash_bloco(bloco)
        bloco_adulterado = dict(bloco, dados_cifrados="0000" + bloco["dados_cifrados"])
        assert hash_bloco(bloco_adulterado) != hash_original


# ---------------------------------------------------------------------------
# adicionar_bloco
# ---------------------------------------------------------------------------
class TestAdicionarBloco:
    def test_cadeia_vazia_cresce(self, chave_alice):
        cadeia = adicionar_bloco([], "tx1", "alice", chave_alice)
        assert len(cadeia) == 1

    def test_cadeia_cresce_sequencialmente(self, chave_alice):
        cadeia = []
        cadeia = adicionar_bloco(cadeia, "tx1", "alice", chave_alice)
        cadeia = adicionar_bloco(cadeia, "tx2", "alice", chave_alice)
        cadeia = adicionar_bloco(cadeia, "tx3", "alice", chave_alice)
        assert len(cadeia) == 3

    def test_primeiro_bloco_hash_anterior_genesis(self, chave_alice):
        cadeia = adicionar_bloco([], "tx1", "alice", chave_alice)
        assert cadeia[0]["hash_anterior"] == HASH_GENESIS

    def test_segundo_bloco_encadeia_no_primeiro(self, chave_alice):
        cadeia = []
        cadeia = adicionar_bloco(cadeia, "tx1", "alice", chave_alice)
        cadeia = adicionar_bloco(cadeia, "tx2", "alice", chave_alice)
        assert cadeia[1]["hash_anterior"] == hash_bloco(cadeia[0])

    def test_nao_modifica_cadeia_original(self, chave_alice):
        """adicionar_bloco deve retornar nova cadeia, não modificar a original."""
        cadeia_original = []
        nova_cadeia = adicionar_bloco(cadeia_original, "tx", "alice", chave_alice)
        assert len(cadeia_original) == 0
        assert len(nova_cadeia) == 1


# ---------------------------------------------------------------------------
# validar_cadeia
# ---------------------------------------------------------------------------
class TestValidarCadeia:
    def test_cadeia_vazia_valida(self):
        assert validar_cadeia([]) is True

    def test_cadeia_com_um_bloco_valida(self, chave_alice):
        cadeia = adicionar_bloco([], "tx1", "alice", chave_alice)
        assert validar_cadeia(cadeia) is True

    def test_cadeia_multiplos_blocos_valida(self, cadeia_com_dois_usuarios):
        assert validar_cadeia(cadeia_com_dois_usuarios) is True

    def test_hash_anterior_adulterado_invalida(self, cadeia_com_dois_usuarios):
        """Alterar hash_anterior quebra a cadeia."""
        cadeia = [dict(b) for b in cadeia_com_dois_usuarios]
        cadeia[1] = dict(cadeia[1], hash_anterior="0" * 64)
        assert validar_cadeia(cadeia) is False

    def test_dados_adulterados_muda_hash_e_invalida(self, cadeia_com_dois_usuarios):
        """Adulterar dados_cifrados muda o hash do bloco e quebra o encadeamento."""
        cadeia = [dict(b) for b in cadeia_com_dois_usuarios]
        cadeia[0] = dict(cadeia[0], dados_cifrados="cafe" * 100)
        assert validar_cadeia(cadeia) is False

    def test_remover_bloco_invalida(self, cadeia_com_dois_usuarios):
        cadeia_truncada = cadeia_com_dois_usuarios[:1] + cadeia_com_dois_usuarios[2:]
        assert validar_cadeia(cadeia_truncada) is False

    def test_primeiro_bloco_hash_anterior_invalido(self, chave_alice):
        cadeia = adicionar_bloco([], "tx", "alice", chave_alice)
        cadeia_mod = [dict(cadeia[0], hash_anterior="hash_invalido")]
        assert validar_cadeia(cadeia_mod) is False


# ---------------------------------------------------------------------------
# ler_blocos_usuario
# ---------------------------------------------------------------------------
class TestLerBlocosUsuario:
    def test_dono_le_seus_dados(self, cadeia_com_dois_usuarios, chave_alice):
        blocos = ler_blocos_usuario(cadeia_com_dois_usuarios, "alice", chave_alice)
        assert len(blocos) == 2
        assert "transacao_alice_1" in blocos
        assert "transacao_alice_2" in blocos

    def test_outro_usuario_nao_decifra(self, cadeia_com_dois_usuarios, chave_bob):
        """Bob não consegue decifrar blocos de Alice (chave errada → InvalidTag)."""
        blocos_alice_por_bob = ler_blocos_usuario(
            cadeia_com_dois_usuarios, "alice", chave_bob
        )
        # Deve retornar None para cada bloco (falha de decifração)
        assert all(b is None for b in blocos_alice_por_bob)

    def test_usuario_sem_blocos_retorna_vazio(self, cadeia_com_dois_usuarios, chave_alice):
        blocos = ler_blocos_usuario(cadeia_com_dois_usuarios, "carlos", chave_alice)
        assert blocos == []

    def test_retorna_lista(self, cadeia_com_dois_usuarios, chave_alice):
        assert isinstance(ler_blocos_usuario(cadeia_com_dois_usuarios, "alice", chave_alice), list)

    def test_bloco_adulterado_retorna_none_na_lista(self, chave_alice):
        cadeia = adicionar_bloco([], "tx_original", "alice", chave_alice)
        cadeia_adulterada = [dict(cadeia[0], dados_cifrados="dead" * 50)]
        blocos = ler_blocos_usuario(cadeia_adulterada, "alice", chave_alice)
        assert blocos == [None]


# ---------------------------------------------------------------------------
# verificar_integridade_bloco
# ---------------------------------------------------------------------------
class TestVerificarIntegridadeBloco:
    def test_bloco_integro_retorna_true(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert verificar_integridade_bloco(bloco, HASH_GENESIS, chave_alice) is True

    def test_hash_anterior_errado_retorna_false(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert verificar_integridade_bloco(bloco, "a" * 64, chave_alice) is False

    def test_dados_adulterados_retorna_false(self, chave_alice):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        bloco_adulterado = dict(bloco, dados_cifrados="cafe" * 50)
        assert verificar_integridade_bloco(bloco_adulterado, HASH_GENESIS, chave_alice) is False

    def test_chave_errada_retorna_false(self, chave_alice, chave_bob):
        bloco = criar_bloco("dados", "alice", chave_alice, HASH_GENESIS)
        assert verificar_integridade_bloco(bloco, HASH_GENESIS, chave_bob) is False
