# Roteiro de Apresentação — Aluno 2
## Mini-Blockchain Simétrica com Autenticação de Usuário

**Tema:** Derivação de Chave Simétrica (KDF) + Segurança em Repouso

---

## Abertura (transição do aluno 1 — ~30 seg)

> "O aluno anterior mostrou como o TOTP garante o segundo fator de autenticação. Agora vou explicar como o sistema transforma a senha do usuário em uma chave criptográfica segura, e como os dados são protegidos em repouso."

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

## Parte 4 — Separação de Contextos de Chave (~3 min)

### Por que derivar chaves diferentes?

> "Reutilizar a mesma chave para propósitos diferentes é uma falha clássica. Se um contexto é comprometido, os outros também são."

O sistema deriva **três chaves distintas** da mesma senha e salt, usando sufixos:

```python
# Chave para cifrar o registro do usuário (dados em repouso)
chave_armazenamento = derivar_chave(senha, salt)

# Chave para verificar a senha (evita reutilização de chave)
hash_senha = derivar_chave(senha, salt + b":verificacao")

# Chave de sessão — usada para cifrar blocos da blockchain
chave_sessao = derivar_chave(senha, salt + b":sessao")
```

**Resultado:**
- `chave_armazenamento` ≠ `hash_senha` ≠ `chave_sessao`
- Mesmo com a mesma senha e salt de entrada

### Estrutura do arquivo de usuário

```json
{
  "nome_usuario": "alice",
  "salt": "a3f8c2...hex...",          ← único campo sem cifragem
  "dados_cifrados": "9b2c4e...hex...", ← AES-GCM({hash_senha, segredo_totp})
  "iv": "1d4e7a...hex..."
}
```

**Por que o salt pode ficar em texto puro?**

> "O salt não é um dado secreto. Sua função é ser único por usuário, não secreto. Precisamos dele para derivar a chave ao fazer login — portanto ele tem que estar acessível. A segurança vem das iterações do PBKDF2 e da entropia da senha, não do sigilo do salt."

### Fluxo completo de autenticação

```
Login:
  1. Ler registro do arquivo → extrair salt (plaintext)
  2. derivar_chave(senha, salt) → chave_armazenamento
  3. Decifrar dados_cifrados com AES-GCM → {hash_senha, segredo_totp}
  4. Verificar: derivar_chave(senha, salt + ":verificacao") == hash_senha
  5. Verificar: código_totp válido com segredo_totp
  6. Retornar: derivar_chave(senha, salt + ":sessao") → chave_sessao
```

> "A chave de sessão é o que o usuário usa para cifrar e decifrar blocos na blockchain. Ela nunca é armazenada — sempre recalculada ao fazer login."

---

## Encerramento da sua parte (~30 seg)

> "Em resumo: PBKDF2 protege contra força bruta, o salt protege contra rainbow tables, e a separação de contextos garante isolamento entre propósitos. O próximo aluno vai mostrar como isso se aplica na blockchain — como os blocos são cifrados e como a integridade da cadeia é protegida."

---

## Possíveis perguntas da banca

**P: Por que não usar bcrypt ou Argon2 em vez de PBKDF2?**
> R: bcrypt e Argon2 são alternativas mais modernas e resistentes a ataques com hardware dedicado (GPU/ASIC). Para este trabalho, PBKDF2 atende ao requisito do enunciado e é o padrão NIST. Em produção, Argon2id seria preferível.

**P: O salt precisa ser secreto?**
> R: Não. O salt precisa ser único e imprevisível, mas não secreto. A segurança vem do custo computacional das iterações, não do sigilo do salt.

**P: O que acontece se dois usuários tiverem o mesmo salt?**
> R: Estatisticamente impossível com `os.urandom(16)` — são 2^128 possibilidades. Se acontecesse, as chaves derivadas de senhas iguais seriam idênticas, quebrando o isolamento entre usuários.

**P: A chave de sessão é armazenada em algum lugar?**
> R: Não. Ela existe apenas em memória durante a sessão ativa. Ao encerrar o programa, some. No próximo login, é recalculada.
