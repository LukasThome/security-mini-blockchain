# Relatório — Mini-Blockchain Simétrica com Autenticação de Usuário

**Disciplina:** Segurança da Informação (INE5680) — UFSC

---

## 1. Visão geral

O sistema implementa uma mini-blockchain multiusuário onde:
- Cada usuário autentica com **senha + TOTP** (dois fatores)
- Os dados de cada bloco são cifrados individualmente com **AES-256-GCM**
- A cadeia é protegida por **encadeamento SHA-256** (`hash_anterior`)
- Nenhuma chave ou IV é fixo no código — tudo derivado sob demanda

---

## 2. Módulos e suas funções

### `criptografia.py` — Primitivas

| Função | Descrição |
|--------|-----------|
| `gerar_salt()` | `os.urandom(16)` — salt criptograficamente seguro |
| `gerar_iv()` | `os.urandom(12)` — IV único por bloco (96 bits, padrão NIST) |
| `derivar_chave()` | PBKDF2-HMAC-SHA256, 100.000 iterações |
| `cifrar_aes_gcm()` | AES-256-GCM, retorna (ciphertext+tag, iv) |
| `decifrar_aes_gcm()` | AES-256-GCM, lança `InvalidTag` se adulterado |
| `calcular_hash()` | SHA-256 em hexadecimal |

### `autenticacao.py` — Cadastro e Login

| Função | Descrição |
|--------|-----------|
| `gerar_segredo_totp()` | `os.urandom(20)` — segredo HMAC de 160 bits |
| `_hotp()` | RFC 4226: HMAC-SHA1 truncado para N dígitos |
| `calcular_totp()` | RFC 6238: HOTP com contador temporal |
| `verificar_totp()` | Janela de ±1 passo, timing-safe |
| `cadastrar_usuario()` | Cria registro cifrado, retorna (registro, segredo_totp) |
| `autenticar()` | Verifica senha + TOTP, retorna chave de sessão |

### `blockchain.py` — Cadeia

| Função | Descrição |
|--------|-----------|
| `criar_bloco()` | Cifra dados com AES-GCM, gera IV único |
| `hash_bloco()` | SHA-256 do bloco serializado (sort_keys) |
| `adicionar_bloco()` | Encadeia pelo hash do bloco anterior |
| `validar_cadeia()` | Verifica encadeamento de hashes |
| `ler_blocos_usuario()` | Decifra apenas blocos do usuário autenticado |

### `armazenamento.py` — Persistência

Leitura e escrita de arquivos JSON. Apenas `salt` em texto puro; resto cifrado.

---

## 3. TOTP — Autenticação de Dois Fatores

**TOTP** (Time-based One-Time Password) é definido pela RFC 6238 e se baseia no HOTP (RFC 4226).

### Funcionamento

```
T = floor(tempo_unix_atual / passo)    # passo = 30 segundos

HOTP(segredo, T):
  1. contador_bytes = T em big-endian de 8 bytes
  2. mac = HMAC-SHA1(segredo, contador_bytes)
  3. offset = mac[19] & 0x0F
  4. código = (mac[offset..offset+4] & 0x7FFFFFFF) % 10^6
  5. zfill(6) para garantir 6 dígitos
```

### Código correspondente

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

### Verificação com janela de tolerância

A verificação aceita ±1 passo (±30 segundos) para compensar dessincronização de relógio entre cliente e servidor:

```python
def verificar_totp(segredo: bytes, codigo: str, passo: int = 30, digitos: int = 6) -> bool:
    t_atual = int(time.time()) // passo
    for delta in (-1, 0, 1):
        esperado = _hotp(segredo, t_atual + delta, digitos)
        if hmac.compare_digest(esperado.encode(), codigo.strip().encode()):
            return True
    return False
```

`hmac.compare_digest` é usado para evitar **timing attacks**: ele leva o mesmo tempo independentemente de onde os strings diferem.

### Armazenamento seguro do segredo TOTP

O segredo TOTP **nunca é armazenado em texto puro**. Ele é incluído nos `dados_cifrados` do registro do usuário:

```python
dados_sensiveis = json.dumps({
    "hash_senha": hash_senha.hex(),
    "segredo_totp": segredo_totp.hex(),    # cifrado junto
}).encode("utf-8")
texto_cifrado, iv = cifrar_aes_gcm(chave_armazenamento, dados_sensiveis)
```

---

## 4. Derivação de Chave Simétrica (KDF)

### PBKDF2-HMAC-SHA256

**PBKDF2** (Password-Based Key Derivation Function 2) transforma uma senha (entropia baixa) em uma chave criptográfica segura.

```
chave = PBKDF2(senha, salt, iterações=100.000, comprimento=32)
```

### Por que 100.000 iterações?

Cada iteração aumenta o custo computacional para um atacante tentar senhas. Com 100.000 iterações, derivar uma chave leva ~100ms numa CPU moderna — aceitável para login, mas inviável para força bruta em larga escala.

### Dois contextos de chave

O sistema deriva **chaves diferentes** para propósitos diferentes, usando sufixos no salt:

```python
# Chave para cifrar o registro do usuário (dados em repouso)
chave_armazenamento = derivar_chave(senha, salt)

# Chave para verificar a senha (evitar reutilização de chave)
hash_senha = derivar_chave(senha, salt + b":verificacao")

# Chave de sessão para cifrar/decifrar blocos da blockchain
chave_sessao = derivar_chave(senha, salt + b":sessao")
```

Isso garante que a **chave de sessão ≠ chave de armazenamento**, mesmo com a mesma senha e salt.

### Apenas o salt em texto puro

```json
{
  "nome_usuario": "alice",
  "salt": "a3f8...hex...",         ← único campo sem cifragem
  "dados_cifrados": "9b2c...hex...", ← AES-GCM({hash_senha, segredo_totp})
  "iv": "1d4e...hex..."
}
```

O `salt` em texto puro é necessário para que o usuário possa derivar a chave ao fazer login. Não é um dado secreto — sua função é garantir que dois usuários com a mesma senha tenham chaves diferentes.

---

## 5. Criptografia por Bloco e Encadeamento da Blockchain

### Estrutura de um bloco

```json
{
  "dono": "alice",
  "timestamp": 1700000000.0,
  "hash_anterior": "sha256_do_bloco_anterior",
  "iv": "hex_do_iv_unico",
  "dados_cifrados": "hex_do_aes_gcm_ciphertext"
}
```

### AES-256-GCM por bloco

Cada bloco usa um **IV único gerado aleatoriamente** (`os.urandom(12)`), garantindo que dois blocos com o mesmo conteúdo produzam cifrados completamente diferentes.

```python
def criar_bloco(dados: str, dono: str, chave_sessao: bytes, hash_anterior: str) -> dict:
    iv = gerar_iv()                                           # IV único
    texto_cifrado, iv_usado = cifrar_aes_gcm(
        chave_sessao, dados.encode("utf-8"), iv
    )
    return {
        "dono": dono,
        "timestamp": time.time(),
        "hash_anterior": hash_anterior,
        "iv": iv_usado.hex(),
        "dados_cifrados": texto_cifrado.hex(),
    }
```

**AES-GCM garante duas propriedades simultaneamente:**
- **Confidencialidade**: dados ilegíveis sem a chave
- **Integridade**: qualquer alteração no ciphertext invalida a tag de autenticação

```python
def decifrar_aes_gcm(chave, texto_cifrado, iv):
    aes = AESGCM(chave)
    return aes.decrypt(iv, texto_cifrado, None)  # lança InvalidTag se adulterado
```

### Encadeamento da blockchain

```
bloco[0]: hash_anterior = "000...0" (HASH_GENESIS)
bloco[1]: hash_anterior = SHA256(bloco[0])
bloco[2]: hash_anterior = SHA256(bloco[1])
...
```

O hash de cada bloco é calculado sobre todos os seus campos:

```python
def hash_bloco(bloco: dict) -> str:
    conteudo = json.dumps({
        "dono":           bloco["dono"],
        "timestamp":      bloco["timestamp"],
        "hash_anterior":  bloco["hash_anterior"],
        "iv":             bloco["iv"],
        "dados_cifrados": bloco["dados_cifrados"],
    }, sort_keys=True).encode("utf-8")
    return calcular_hash(conteudo)
```

`sort_keys=True` garante serialização determinística (independente de ordem de inserção no dict).

### Validação da cadeia

```python
def validar_cadeia(cadeia: list) -> bool:
    if not cadeia:
        return True
    if cadeia[0]["hash_anterior"] != HASH_GENESIS:
        return False
    for i in range(1, len(cadeia)):
        if cadeia[i]["hash_anterior"] != hash_bloco(cadeia[i - 1]):
            return False
    return True
```

Qualquer adulteração — mesmo em um único byte — altera o hash do bloco afetado, e todos os blocos subsequentes passam a ter `hash_anterior` inválido.

### Separação de dados entre usuários

```python
def ler_blocos_usuario(cadeia, nome_usuario, chave_sessao):
    for bloco in cadeia:
        if bloco["dono"] != nome_usuario:
            continue                          # ignora blocos de outros
        try:
            dados = decifrar_aes_gcm(chave_sessao, ...)
            resultados.append(dados)
        except Exception:
            resultados.append(None)           # chave errada ou adulteração
```

Sem a `chave_sessao` correta, a tentativa de decifrar blocos de outro usuário lança `InvalidTag`. Não há compartilhamento de chaves entre usuários.

---

## 6. Resumo das garantias de segurança

| Requisito | Solução |
|-----------|---------|
| Sem chaves fixas no código | PBKDF2 deriva chave de senha+salt em tempo de execução |
| IV único por bloco | `os.urandom(12)` gerado a cada bloco |
| Criptografia autenticada | AES-256-GCM (confidencialidade + integridade) |
| Autenticação forte | Senha (PBKDF2) + TOTP (RFC 6238) |
| Dados em repouso | Registro cifrado; apenas salt em plaintext |
| Sem variáveis globais de chave/IV | Toda chave derivada localmente na função |
| Integridade da cadeia | Encadeamento SHA-256 (`hash_anterior`) |

---

## 7. Referências

- RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm
- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm
- NIST SP 800-132 — Recommendation for Password-Based Key Derivation
- NIST SP 800-38D — Recommendation for Block Cipher Modes: GCM
- Python `cryptography` library: https://cryptography.io
- Auxiliar de pesquisa: Claude (Anthropic) — apoio na estruturação e revisão do código
