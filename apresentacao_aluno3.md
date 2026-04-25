# Roteiro de Apresentação — Aluno 3
## Mini-Blockchain Simétrica com Autenticação de Usuário

**Tema:** Criptografia por Bloco + Encadeamento da Blockchain + Demo ao Vivo

---

## Abertura (transição do aluno 2 — ~30 seg)

> "O aluno anterior explicou como as chaves são derivadas com segurança. Agora vou mostrar onde essas chaves são usadas: na blockchain. Vou cobrir como cada bloco é cifrado, como a cadeia garante integridade, e vou fazer uma demonstração ao vivo."

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
