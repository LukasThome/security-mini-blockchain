"""
Testes para cadastro, TOTP e autenticação (autenticacao.py).

Cobre:
  - gerar_segredo_totp   : aleatoriedade e tamanho
  - calcular_totp        : formato, determinismo no mesmo instante
  - verificar_totp       : código correto passa, errado falha, expirado falha
  - cadastrar_usuario    : campos do registro, dado cifrado, salt em texto puro
  - autenticar           : senha+TOTP corretos → chave; erros → None
  - chave de sessão      : determinística, distinta da chave de armazenamento
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch
from autenticacao import (
    gerar_segredo_totp, calcular_totp, verificar_totp,
    cadastrar_usuario, autenticar, _decifrar_registro,
    _CONTEXTO_SESSAO,
)
from criptografia import derivar_chave

TEMPO_FIXO = 1_700_000_000  # timestamp fixo para testes TOTP determinísticos


# ---------------------------------------------------------------------------
# gerar_segredo_totp
# ---------------------------------------------------------------------------
class TestGerarSegredoTotp:
    def test_retorna_bytes(self):
        assert isinstance(gerar_segredo_totp(), bytes)

    def test_tamanho_20_bytes(self):
        """RFC 4226 recomenda segredo de ao menos 160 bits (20 bytes)."""
        assert len(gerar_segredo_totp()) == 20

    def test_duas_chamadas_diferentes(self):
        assert gerar_segredo_totp() != gerar_segredo_totp()


# ---------------------------------------------------------------------------
# calcular_totp
# ---------------------------------------------------------------------------
class TestCalcularTotp:
    def test_retorna_string(self):
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            assert isinstance(calcular_totp(gerar_segredo_totp()), str)

    def test_seis_digitos(self):
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(gerar_segredo_totp())
            assert len(codigo) == 6

    def test_apenas_digitos(self):
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(gerar_segredo_totp())
            assert codigo.isdigit()

    def test_deterministica_mesmo_tempo(self):
        """Mesmo segredo + mesmo instante → mesmo código."""
        segredo = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            c1 = calcular_totp(segredo)
            c2 = calcular_totp(segredo)
        assert c1 == c2

    def test_segredos_diferentes_codigos_diferentes(self):
        """Segredos distintos → códigos distintos (com altíssima probabilidade)."""
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            c1 = calcular_totp(gerar_segredo_totp())
            c2 = calcular_totp(gerar_segredo_totp())
        assert c1 != c2


# ---------------------------------------------------------------------------
# verificar_totp
# ---------------------------------------------------------------------------
class TestVerificarTotp:
    def test_codigo_correto_aceito(self):
        segredo = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            assert verificar_totp(segredo, codigo) is True

    def test_codigo_errado_rejeitado(self):
        segredo = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            assert verificar_totp(segredo, "000000") is False

    def test_codigo_de_outro_segredo_rejeitado(self):
        s1 = gerar_segredo_totp()
        s2 = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo_s1 = calcular_totp(s1)
            assert verificar_totp(s2, codigo_s1) is False

    def test_codigo_expirado_rejeitado(self):
        """Código gerado 10.000 segundos atrás deve ser inválido."""
        segredo = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO + 10_000
            assert verificar_totp(segredo, codigo) is False

    def test_aceita_codigo_do_passo_anterior(self):
        """Janela de tolerância: ±1 passo de 30 segundos."""
        segredo = gerar_segredo_totp()
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo_anterior = calcular_totp(segredo)
        # Avançar 29 segundos (ainda dentro da janela)
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO + 29
            assert verificar_totp(segredo, codigo_anterior) is True


# ---------------------------------------------------------------------------
# cadastrar_usuario
# ---------------------------------------------------------------------------
class TestCadastrarUsuario:
    @pytest.fixture
    def registro_alice(self):
        registro, segredo = cadastrar_usuario("alice", "senha_segura_123")
        return registro, segredo

    def test_retorna_tupla(self, registro_alice):
        registro, segredo = registro_alice
        assert isinstance(registro, dict)
        assert isinstance(segredo, bytes)

    def test_segredo_totp_20_bytes(self, registro_alice):
        _, segredo = registro_alice
        assert len(segredo) == 20

    def test_registro_tem_campo_salt(self, registro_alice):
        registro, _ = registro_alice
        assert "salt" in registro

    def test_registro_tem_dados_cifrados(self, registro_alice):
        registro, _ = registro_alice
        assert "dados_cifrados" in registro

    def test_registro_tem_iv(self, registro_alice):
        registro, _ = registro_alice
        assert "iv" in registro

    def test_salt_em_texto_puro(self, registro_alice):
        """Salt deve ser string hexadecimal, não cifrada."""
        registro, _ = registro_alice
        # Deve ser convertível de hex sem erro
        salt_bytes = bytes.fromhex(registro["salt"])
        assert len(salt_bytes) > 0

    def test_dados_cifrados_nao_contem_senha(self, registro_alice):
        """Senha nunca deve aparecer em texto puro no registro."""
        registro, _ = registro_alice
        conteudo = str(registro)
        assert "senha_segura_123" not in conteudo

    def test_dois_cadastros_salts_diferentes(self):
        """Cada cadastro deve gerar salt único."""
        r1, _ = cadastrar_usuario("alice", "senha")
        r2, _ = cadastrar_usuario("alice", "senha")
        assert r1["salt"] != r2["salt"]

    def test_dados_decifraveis_com_senha_correta(self, registro_alice):
        """Dados cifrados devem ser decifráveis com a senha usada no cadastro."""
        registro, _ = registro_alice
        dados = _decifrar_registro(registro, "senha_segura_123")
        assert dados is not None
        assert "hash_senha" in dados
        assert "segredo_totp" in dados

    def test_dados_nao_decifraveis_com_senha_errada(self, registro_alice):
        registro, _ = registro_alice
        dados = _decifrar_registro(registro, "senha_errada")
        assert dados is None


# ---------------------------------------------------------------------------
# autenticar
# ---------------------------------------------------------------------------
class TestAutenticar:
    @pytest.fixture
    def registro_e_totp(self):
        registro, segredo_totp = cadastrar_usuario("bob", "senha_bob_456")
        return registro, segredo_totp

    def test_senha_correta_totp_valido_retorna_bytes(self, registro_e_totp):
        registro, segredo = registro_e_totp
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            chave = autenticar(registro, "senha_bob_456", codigo)
        assert isinstance(chave, bytes)

    def test_chave_sessao_32_bytes(self, registro_e_totp):
        registro, segredo = registro_e_totp
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            chave = autenticar(registro, "senha_bob_456", codigo)
        assert len(chave) == 32

    def test_senha_errada_retorna_none(self, registro_e_totp):
        registro, segredo = registro_e_totp
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            chave = autenticar(registro, "senha_ERRADA", codigo)
        assert chave is None

    def test_totp_invalido_retorna_none(self, registro_e_totp):
        registro, _ = registro_e_totp
        chave = autenticar(registro, "senha_bob_456", "000000")
        assert chave is None

    def test_chave_sessao_deterministica(self, registro_e_totp):
        """Mesmo usuário + mesma senha → mesma chave de sessão."""
        registro, segredo = registro_e_totp
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            c1 = autenticar(registro, "senha_bob_456", codigo)
            codigo = calcular_totp(segredo)
            c2 = autenticar(registro, "senha_bob_456", codigo)
        assert c1 == c2

    def test_chave_sessao_diferente_da_chave_armazenamento(self, registro_e_totp):
        """Chave de sessão != chave usada para cifrar o registro."""
        registro, segredo = registro_e_totp
        salt = bytes.fromhex(registro["salt"])
        chave_armazenamento = derivar_chave("senha_bob_456", salt)
        with patch("autenticacao.time") as t:
            t.time.return_value = TEMPO_FIXO
            codigo = calcular_totp(segredo)
            chave_sessao = autenticar(registro, "senha_bob_456", codigo)
        assert chave_sessao != chave_armazenamento
