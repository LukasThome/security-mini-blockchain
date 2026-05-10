# Roteiro de Apresentação — Luiz Fernando
## Mini-Blockchain Simétrica com Autenticação de Usuário

**Tema:** Separação de Contextos de Chave + AES-256-GCM + Encadeamento da Blockchain + Demo ao Vivo

---

## Abertura (transição de Lucas — ~30 seg)

> "O Lucas explicou como o usuário se autentica e como a senha é transformada em chave. Agora vou mostrar como o sistema usa essa chave em diferentes contextos de forma isolada, como cada bloco é cifrado na blockchain, como a cadeia garante integridade, e vou fazer uma demonstração ao vivo."

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

## Parte 5 — AES-256-GCM por Bloco (~4 min)

### Estrutura de um bloco

```json
{
  "dono":          "alice",
  "timestamp":     1700000000.0,
  "hash_anterior": "sha256_do_bloco_anterior",
  "iv":            "hex_do_iv_unico",
  "dados_cifrados": "hex_do_aes_gcm_ciphertext"
}
```

> "Os dados ficam cifrados no bloco. Sem a chave de sessão do dono, ninguém consegue ler."

### Por que AES-GCM?

> "AES-GCM é um modo de cifragem autenticada. Ele garante **duas propriedades ao mesmo tempo**:"

| Propriedade | O que garante |
|-------------|---------------|
| **Confidencialidade** | Dados ilegíveis sem a chave |
| **Integridade** | Qualquer alteração invalida a tag de autenticação |

> "Se alguém modificar um único byte do ciphertext, o AES-GCM detecta na hora."

### IV único por bloco

```python
def gerar_iv(tamanho: int = 12) -> bytes:
    return os.urandom(12)   # 96 bits — padrão NIST para AES-GCM
```

> "Cada bloco recebe um IV diferente gerado aleatoriamente. Isso garante que dois blocos com o mesmo conteúdo produzam ciphertexts completamente diferentes."

**Regra fundamental do AES-GCM:** nunca reutilizar (chave, IV). Aqui isso é garantido porque o IV é `os.urandom(12)` — 2^96 possibilidades.

### O código de cifragem

```python
def criar_bloco(dados: str, dono: str, chave_sessao: bytes, hash_anterior: str) -> dict:
    iv = gerar_iv()                                               # IV único
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

---

## Parte 6 — Encadeamento da Blockchain (~4 min)

### Como o encadeamento funciona

```
bloco[0]: hash_anterior = "000...0"  (HASH_GENESIS — 64 zeros)
bloco[1]: hash_anterior = SHA256(bloco[0])
bloco[2]: hash_anterior = SHA256(bloco[1])
...
```

> "Cada bloco carrega o hash do bloco anterior. Se alguém alterar um bloco, o hash muda, e todos os blocos seguintes ficam com `hash_anterior` inválido."

### O hash do bloco

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

> "`sort_keys=True` garante serialização determinística — o hash é sempre o mesmo independentemente de como o dict foi construído."

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

> "Essa função percorre toda a cadeia verificando o encadeamento. Adulteração em qualquer bloco é detectada."

### Isolamento entre usuários

```python
def ler_blocos_usuario(cadeia, nome_usuario, chave_sessao):
    for bloco in cadeia:
        if bloco["dono"] != nome_usuario:
            continue              # pula blocos de outros usuários
        try:
            dados = decifrar_aes_gcm(chave_sessao, ...)
            resultados.append(dados)
        except Exception:
            resultados.append(None)   # chave errada → InvalidTag
```

> "Mesmo que Alice tente usar a chave de sessão dela para ler os blocos de Bob, o AES-GCM lança `InvalidTag`. Não há compartilhamento de chaves entre usuários."

---

## Parte 7 — Demo ao Vivo (~3 min)

**Executar:** `python3 main.py`

### Roteiro da demo

```
1. Cadastrar usuário "alice" com senha "Senha@2024"
   → Sistema mostra segredo TOTP

2. Login: inserir senha + código TOTP atual
   → Autenticação com dois fatores

3. Adicionar bloco: "Transferência de R$100 para Bob"
   → Bloco cifrado adicionado à cadeia

4. Ler blocos: mostrar dado decifrado de "alice"

5. Validar cadeia: mostrar "Cadeia válida ✓"

6. (opcional) Mostrar blockchain.json aberto no editor
   → dados_cifrados são bytes opacos — ilegíveis sem a chave
```

**Ponto de destaque na demo:**
> "Reparem que o arquivo `blockchain.json` armazena apenas ciphertext. Não dá para ver o conteúdo sem a senha do usuário."

---

## Parte 8 — Resumo das Garantias (~1 min)

| Requisito | Solução |
|-----------|---------|
| Sem chaves fixas no código | PBKDF2 deriva chave de senha+salt em tempo de execução |
| IV único por bloco | `os.urandom(12)` gerado a cada bloco |
| Criptografia autenticada | AES-256-GCM (confidencialidade + integridade) |
| Autenticação forte | Senha (PBKDF2) + TOTP (RFC 6238) |
| Dados em repouso | Registro cifrado; apenas salt em plaintext |
| Integridade da cadeia | Encadeamento SHA-256 (`hash_anterior`) |

---

## Encerramento geral (~30 seg)

> "O sistema implementa segurança em camadas: o usuário só entra com dois fatores, as chaves nunca ficam no código, cada bloco tem cifragem autenticada própria, e a blockchain detecta qualquer adulteração. Abrimos para perguntas."

---

## Possíveis perguntas da banca

**P: A chave de sessão é armazenada em algum lugar?**
> R: Não. Ela existe apenas em memória durante a sessão ativa. Ao encerrar o programa, some. No próximo login, é recalculada.

**P: O que acontece se alguém alterar o campo `dono` de um bloco?**
> R: O campo `dono` entra no cálculo do `hash_bloco`. Alterar qualquer campo — incluindo `dono` — invalida o `hash_anterior` de todos os blocos seguintes. A `validar_cadeia` detecta.

**P: AES-GCM não protege o campo `dono` de leitura — é um problema?**
> R: O campo `dono` é o username em texto puro para permitir filtragem sem decifrar. Em um sistema de produção, poderíamos cifrar também, mas precisaríamos de outro mecanismo de indexação. Para este trabalho, o campo `dono` não é dado sensível.

**P: Por que SHA-256 para o encadeamento e não SHA-3?**
> R: SHA-256 é amplamente padronizado, validado e sem vulnerabilidades conhecidas para este uso. SHA-3 seria igualmente seguro, mas SHA-256 é suficiente e mais comum.

**P: A blockchain é distribuída?**
> R: Não — é uma blockchain local (arquivo JSON). O objetivo do trabalho é demonstrar os mecanismos criptográficos, não a distribuição. Em uma blockchain real, a imutabilidade vem do consenso distribuído, não de um único arquivo.

**P: Quantos testes foram escritos?**
> R: 106 testes automatizados com pytest, cobrindo KDF, AES-GCM, TOTP, cadastro, autenticação, blockchain e armazenamento. Todo o desenvolvimento seguiu TDD — testes antes da implementação.
