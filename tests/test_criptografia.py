"""
Testes para as primitivas criptográficas (criptografia.py).

Cobre:
  - gerar_salt / gerar_iv   : aleatoriedade e tamanho corretos
  - derivar_chave            : determinismo, sensibilidade a salt e senha
  - cifrar_aes_gcm           : confidencialidade, unicidade de IV, retorno correto
  - decifrar_aes_gcm         : correção, detecção de adulteração
  - calcular_hash            : determinismo, formato, sensibilidade a dados
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptography.exceptions import InvalidTag
from criptografia import (
    gerar_salt, gerar_iv, derivar_chave,
    cifrar_aes_gcm, decifrar_aes_gcm, calcular_hash,
    TAMANHO_SALT, TAMANHO_IV, TAMANHO_CHAVE,
)


# ---------------------------------------------------------------------------
# gerar_salt
# ---------------------------------------------------------------------------
class TestGerarSalt:
    def test_retorna_bytes(self):
        assert isinstance(gerar_salt(), bytes)

    def test_tamanho_padrao(self):
        assert len(gerar_salt()) == TAMANHO_SALT

    def test_tamanho_customizado(self):
        assert len(gerar_salt(tamanho=32)) == 32

    def test_duas_chamadas_diferentes(self):
        """Salt deve ser aleatório — colisão improvável."""
        assert gerar_salt() != gerar_salt()


# ---------------------------------------------------------------------------
# gerar_iv
# ---------------------------------------------------------------------------
class TestGerarIv:
    def test_retorna_bytes(self):
        assert isinstance(gerar_iv(), bytes)

    def test_tamanho_padrao(self):
        """IV padrão para AES-GCM: 12 bytes (96 bits)."""
        assert len(gerar_iv()) == TAMANHO_IV

    def test_tamanho_customizado(self):
        assert len(gerar_iv(tamanho=16)) == 16

    def test_duas_chamadas_diferentes(self):
        assert gerar_iv() != gerar_iv()


# ---------------------------------------------------------------------------
# derivar_chave
# ---------------------------------------------------------------------------
class TestDerivarChave:
    def test_retorna_bytes(self):
        salt = gerar_salt()
        assert isinstance(derivar_chave("senha", salt), bytes)

    def test_comprimento_padrao(self):
        salt = gerar_salt()
        assert len(derivar_chave("senha", salt)) == TAMANHO_CHAVE

    def test_comprimento_customizado(self):
        salt = gerar_salt()
        assert len(derivar_chave("senha", salt, comprimento=16)) == 16

    def test_deterministica_mesma_entrada(self):
        """KDF deve ser determinística: mesma senha + mesmo salt → mesma chave."""
        salt = gerar_salt()
        c1 = derivar_chave("minha_senha", salt)
        c2 = derivar_chave("minha_senha", salt)
        assert c1 == c2

    def test_salt_diferente_chave_diferente(self):
        salt_a = gerar_salt()
        salt_b = gerar_salt()
        assert derivar_chave("senha", salt_a) != derivar_chave("senha", salt_b)

    def test_senha_diferente_chave_diferente(self):
        salt = gerar_salt()
        assert derivar_chave("senha_a", salt) != derivar_chave("senha_b", salt)

    def test_contexto_diferente_chave_diferente(self):
        """Sufixo no salt gera chave diferente (contexto de uso)."""
        salt = gerar_salt()
        c_armazenamento = derivar_chave("senha", salt)
        c_sessao = derivar_chave("senha", salt + b":sessao")
        assert c_armazenamento != c_sessao


# ---------------------------------------------------------------------------
# cifrar_aes_gcm / decifrar_aes_gcm
# ---------------------------------------------------------------------------
class TestCifrarDecifrar:
    @pytest.fixture
    def chave(self):
        return derivar_chave("senha_teste", gerar_salt())

    def test_cifrar_retorna_tupla(self, chave):
        resultado = cifrar_aes_gcm(chave, b"dados")
        assert isinstance(resultado, tuple)
        assert len(resultado) == 2

    def test_texto_cifrado_diferente_do_original(self, chave):
        texto_cifrado, _ = cifrar_aes_gcm(chave, b"dados secretos")
        assert texto_cifrado != b"dados secretos"

    def test_decifrar_retorna_original(self, chave):
        original = b"mensagem de teste"
        texto_cifrado, iv = cifrar_aes_gcm(chave, original)
        assert decifrar_aes_gcm(chave, texto_cifrado, iv) == original

    def test_cifrar_com_iv_externo(self, chave):
        """IV externo deve ser usado e retornado."""
        iv_externo = gerar_iv()
        _, iv_retornado = cifrar_aes_gcm(chave, b"dados", iv=iv_externo)
        assert iv_retornado == iv_externo

    def test_iv_diferente_texto_cifrado_diferente(self, chave):
        """Mesmo plaintext + chave, IV diferentes → cifrados diferentes."""
        tc1, _ = cifrar_aes_gcm(chave, b"dados", iv=gerar_iv())
        tc2, _ = cifrar_aes_gcm(chave, b"dados", iv=gerar_iv())
        assert tc1 != tc2

    def test_chave_errada_levanta_excecao(self, chave):
        texto_cifrado, iv = cifrar_aes_gcm(chave, b"dados")
        chave_errada = derivar_chave("outra_senha", gerar_salt())
        with pytest.raises(Exception):
            decifrar_aes_gcm(chave_errada, texto_cifrado, iv)

    def test_dados_adulterados_levanta_excecao(self, chave):
        """AES-GCM detecta qualquer alteração no ciphertext (integridade)."""
        texto_cifrado, iv = cifrar_aes_gcm(chave, b"dados")
        adulterado = bytes([texto_cifrado[0] ^ 0xFF]) + texto_cifrado[1:]
        with pytest.raises((InvalidTag, Exception)):
            decifrar_aes_gcm(chave, adulterado, iv)

    def test_iv_errado_levanta_excecao(self, chave):
        texto_cifrado, _ = cifrar_aes_gcm(chave, b"dados")
        iv_errado = gerar_iv()
        with pytest.raises(Exception):
            decifrar_aes_gcm(chave, texto_cifrado, iv_errado)

    def test_cifrar_dados_vazios(self, chave):
        """Deve suportar cifragem de dados vazios."""
        texto_cifrado, iv = cifrar_aes_gcm(chave, b"")
        assert decifrar_aes_gcm(chave, texto_cifrado, iv) == b""

    def test_cifrar_dados_longos(self, chave):
        dados = b"x" * 10_000
        texto_cifrado, iv = cifrar_aes_gcm(chave, dados)
        assert decifrar_aes_gcm(chave, texto_cifrado, iv) == dados


# ---------------------------------------------------------------------------
# calcular_hash
# ---------------------------------------------------------------------------
class TestCalcularHash:
    def test_retorna_string(self):
        assert isinstance(calcular_hash(b"dados"), str)

    def test_comprimento_sha256(self):
        """SHA-256 em hex = 64 caracteres."""
        assert len(calcular_hash(b"dados")) == 64

    def test_apenas_hex(self):
        resultado = calcular_hash(b"dados")
        assert all(c in "0123456789abcdef" for c in resultado)

    def test_deterministica(self):
        assert calcular_hash(b"dados") == calcular_hash(b"dados")

    def test_dados_diferentes_hash_diferente(self):
        assert calcular_hash(b"aaaa") != calcular_hash(b"bbbb")

    def test_hash_bytes_vazios(self):
        """SHA-256 de bytes vazios é conhecido."""
        esperado = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert calcular_hash(b"") == esperado
