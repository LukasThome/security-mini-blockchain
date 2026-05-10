# Roteiro de Apresentação — Lucas Thome da Silva
## Mini-Blockchain Simétrica com Autenticação de Usuário

**Tema:** Visão Geral do Sistema + Autenticação de Dois Fatores (TOTP) + Derivação de Chave (KDF)

---

## Abertura (fala inicial — ~1 min)

> "Nosso trabalho implementa uma mini-blockchain multiusuário com foco em segurança real. Cada usuário precisa se autenticar com **dois fatores** antes de registrar qualquer dado, e todos os dados na cadeia são cifrados individualmente. Vou apresentar a visão geral do sistema, explicar como funciona a autenticação e mostrar como as chaves criptográficas são derivadas com segurança."

---

## Parte 1 — Visão Geral do Sistema (~3 min)

### O que o sistema faz

O sistema é dividido em 4 módulos principais:

| Módulo | Responsabilidade |
|--------|-----------------|
| `criptografia.py` | Primitivas: PBKDF2, AES-GCM, SHA-256, geração de salt/IV |
| `autenticacao.py` | Cadastro, login, TOTP |
| `blockchain.py` | Criação de blocos, encadeamento, validação |
| `armazenamento.py` | Persistência em JSON |

**Falar:**
- "O sistema não tem chaves fixas em nenhum lugar do código — tudo é derivado sob demanda a partir da senha do usuário."
- "O salt é o único dado armazenado em texto puro. Tudo o mais vai cifrado para o disco."
- "A blockchain é compartilhada entre usuários, mas cada bloco é cifrado com a chave do dono — outros usuários não conseguem ler."

### Fluxo de uso

```
Cadastrar → Login (senha + TOTP) → Adicionar bloco → Ler blocos → Validar cadeia
```

---

## Parte 2 — TOTP: Autenticação de Dois Fatores (~5 min)

### Por que dois fatores?

> "Senha sozinha é vulnerável a vazamentos e força bruta. O TOTP adiciona um segundo fator: algo que o usuário **tem** (o segredo compartilhado), não só algo que **sabe**."

### Como o TOTP funciona (RFC 6238)

```
T = floor(tempo_unix_atual / 30)   ← contador baseado em tempo

HOTP(segredo, T):
  1. contador_bytes = T em big-endian (8 bytes)
  2. mac = HMAC-SHA1(segredo, contador_bytes)
  3. offset = mac[19] & 0x0F
  4. código = (mac[offset..offset+3] & 0x7FFFFFFF) % 10^6
  5. zfill(6) → sempre 6 dígitos
```

**Mostrar o código:**

```python
def _hotp(segredo: bytes, contador: int, digitos: int = 6) -> str:
    contador_bytes = struct.pack('>Q', contador)
    mac = hmac.new(segredo, contador_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    codigo = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(codigo % (10 ** digitos)).zfill(digitos)

def calcular_totp(segredo: bytes, passo: int = 30, digitos: int = 6) -> str:
    contador = int(time.time()) // passo
    return _hotp(segredo, contador, digitos)
```

### Janela de tolerância (±1 passo)

> "Clientes e servidores podem ter relógios levemente dessincronizados. Aceitamos ±30 segundos para compensar isso."

```python
def verificar_totp(segredo, codigo, passo=30, digitos=6):
    t_atual = int(time.time()) // passo
    for delta in (-1, 0, 1):
        esperado = _hotp(segredo, t_atual + delta, digitos)
        if hmac.compare_digest(esperado.encode(), codigo.strip().encode()):
            return True
    return False
```

**Destacar:** `hmac.compare_digest` evita **timing attacks** — a função leva o mesmo tempo independentemente de onde os strings diferem.

### Armazenamento seguro do segredo TOTP

> "O segredo TOTP nunca vai para o disco em texto puro. Ele é cifrado junto com o hash da senha dentro do AES-GCM."

```python
dados_sensiveis = json.dumps({
    "hash_senha": hash_senha.hex(),
    "segredo_totp": segredo_totp.hex(),    # cifrado junto
}).encode("utf-8")
texto_cifrado, iv = cifrar_aes_gcm(chave_armazenamento, dados_sensiveis)
```

---

## Parte 3 — Derivação de Chave com PBKDF2 (~5 min)

### O problema: senha ≠ chave

> "Senhas têm entropia baixa. 'senha123' tem uns 20 bits de entropia. Uma chave AES-256 precisa de 256 bits de entropia. Não dá para usar a senha diretamente como chave."

**PBKDF2** (Password-Based Key Derivation Function 2) resolve isso:

```
chave = PBKDF2(senha, salt, iterações=100.000, comprimento=32 bytes)
```

### O código

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITERACOES_KDF = 100_000
TAMANHO_CHAVE = 32  # 256 bits

def derivar_chave(senha: str, salt: bytes, comprimento: int = TAMANHO_CHAVE) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=comprimento,
        salt=salt,
        iterations=ITERACOES_KDF,
    )
    return kdf.derive(senha.encode("utf-8"))
```

### Por que 100.000 iterações?

> "Cada iteração adiciona custo computacional para o atacante. Com 100.000 iterações, derivar uma chave leva ~100ms numa CPU moderna — aceitável para login, mas inviável para força bruta em larga escala."

| Iterações | Tempo por tentativa | Tentativas/seg (1 CPU) |
|-----------|--------------------|-----------------------|
| 1.000 | ~1ms | ~1.000 |
| 100.000 | ~100ms | ~10 |
| 1.000.000 | ~1s | ~1 |

> "O NIST SP 800-132 recomenda no mínimo 1.000 iterações. Usamos 100× esse mínimo."

### O papel do salt

> "O salt é um valor aleatório gerado por usuário. Ele garante que dois usuários com a mesma senha tenham **chaves completamente diferentes**."

```python
def gerar_salt(tamanho: int = 16) -> bytes:
    return os.urandom(tamanho)   # 128 bits de aleatoriedade criptográfica
```

**Sem salt:** `PBKDF2("senha123") == PBKDF2("senha123")` → atacante pré-computa uma tabela (rainbow table).

**Com salt:** `PBKDF2("senha123", salt_alice) != PBKDF2("senha123", salt_bob)` → cada usuário precisa de ataque independente.

---

## Encerramento da sua parte (~30 seg)

> "Em resumo: o TOTP garante que mesmo que alguém descubra a senha, não consegue entrar sem o código de 6 dígitos que muda a cada 30 segundos; o PBKDF2 com 100 mil iterações torna força bruta inviável; e o salt elimina rainbow tables. O Luiz vai mostrar como as chaves são separadas por contexto e como isso se aplica na blockchain."

---

## Possíveis perguntas da banca

**P: Por que SHA-1 no TOTP se SHA-1 é considerado quebrado?**
> R: A RFC 6238 define SHA-1. O HMAC-SHA1 ainda é seguro para esse uso porque as colisões de SHA-1 não comprometem o HMAC. Versões mais novas (HOTP com SHA-256) existem mas SHA-1 é o padrão amplamente suportado.

**P: O que impede um atacante de reutilizar um código TOTP capturado?**
> R: O código muda a cada 30 segundos. Um código usado com sucesso não invalida os outros da janela — mas na prática a janela é curta o suficiente para que a reutilização seja inviável.

**P: Como o segredo TOTP é entregue ao usuário?**
> R: No cadastro, o sistema retorna o segredo em hexadecimal. Em produção, seria um QR code para o Google Authenticator ou similar.

**P: Por que não usar bcrypt ou Argon2 em vez de PBKDF2?**
> R: bcrypt e Argon2 são alternativas mais modernas e resistentes a ataques com hardware dedicado (GPU/ASIC). Para este trabalho, PBKDF2 atende ao requisito do enunciado e é o padrão NIST. Em produção, Argon2id seria preferível.

**P: O salt precisa ser secreto?**
> R: Não. O salt precisa ser único e imprevisível, mas não secreto. A segurança vem do custo computacional das iterações, não do sigilo do salt.

**P: O que acontece se dois usuários tiverem o mesmo salt?**
> R: Estatisticamente impossível com `os.urandom(16)` — são 2^128 possibilidades. Se acontecesse, as chaves derivadas de senhas iguais seriam idênticas, quebrando o isolamento entre usuários.
