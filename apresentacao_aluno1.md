# Roteiro de Apresentação — Aluno 1
## Mini-Blockchain Simétrica com Autenticação de Usuário

**Tema:** Visão Geral do Sistema + Autenticação de Dois Fatores (TOTP)

---

## Abertura (fala inicial — ~1 min)

> "Nosso trabalho implementa uma mini-blockchain multiusuário com foco em segurança real. Cada usuário precisa se autenticar com **dois fatores** antes de registrar qualquer dado, e todos os dados na cadeia são cifrados individualmente. Vou apresentar a visão geral do sistema e explicar como funciona a autenticação."

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

## Encerramento da sua parte (~30 seg)

> "Em resumo: o TOTP garante que mesmo que alguém descubra a senha do usuário, não consegue autenticar sem o código de 6 dígitos que muda a cada 30 segundos. O próximo aluno vai explicar como as chaves criptográficas são derivadas a partir da senha."

---

## Possíveis perguntas da banca

**P: Por que SHA-1 no TOTP se SHA-1 é considerado quebrado?**
> R: A RFC 6238 define SHA-1. O HMAC-SHA1 ainda é seguro para esse uso porque as colisões de SHA-1 não comprometem o HMAC. Versões mais novas (HOTP com SHA-256) existem mas SHA-1 é o padrão amplamente suportado.

**P: O que impede um atacante de reutilizar um código TOTP capturado?**
> R: O código muda a cada 30 segundos. Um código usado com sucesso não invalida os outros da janela — mas na prática a janela é curta o suficiente para que a reutilização seja inviável.

**P: Como o segredo TOTP é entregue ao usuário?**
> R: No cadastro, o sistema retorna o segredo em hexadecimal. Em produção, seria um QR code para o Google Authenticator ou similar.
