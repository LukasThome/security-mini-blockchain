# Mini-Blockchain Simétrica com Autenticação de Usuário

**Disciplina:** Segurança da Informação (INE5680) — UFSC  
**Prazo:** ver enunciado

Sistema multiusuário de blockchain onde cada usuário autentica com senha + TOTP e registra transações criptografadas com AES-256-GCM.

---

## Requisitos

```bash
pip3 install cryptography
```

---

## Como executar

```bash
python3 main.py
```

Menu interativo com as opções:
1. Cadastrar usuário
2. Login (senha + TOTP)
3. Adicionar bloco
4. Ler meus blocos (decifrados)
5. Validar integridade da cadeia
6. Listar todos os blocos (sem decifrar dados de outros)

---

## Estrutura do projeto

```
practice_two/
├── criptografia.py      # Primitivas: PBKDF2, AES-GCM, SHA-256, gerar salt/IV
├── autenticacao.py      # Cadastro, login, TOTP (RFC 6238)
├── blockchain.py        # Bloco, cadeia, validação, leitura
├── armazenamento.py     # Persistência em arquivos JSON
├── main.py              # Menu interativo
└── tests/
    ├── test_criptografia.py
    ├── test_autenticacao.py
    ├── test_blockchain.py
    └── test_armazenamento.py
```

---

## Arquivos gerados em tempo de execução

| Arquivo | Conteúdo |
|---|---|
| `usuarios/<nome>.json` | Registro cifrado do usuário (salt + dados AES-GCM) |
| `blockchain.json` | Cadeia de blocos (dados de cada bloco cifrados individualmente) |

---

## Garantias de segurança

| Propriedade | Como é garantida |
|---|---|
| Confidencialidade | AES-256-GCM por bloco, chave derivada por PBKDF2 |
| Integridade dos dados | Tag de autenticação AES-GCM (detecta adulteração) |
| Integridade da cadeia | SHA-256 encadeado (`hash_anterior`) |
| Autenticação forte | Senha + TOTP (dois fatores) |
| Sem chaves fixas | Toda chave derivada on-demand de senha+salt |
| Armazenamento seguro | Apenas `salt` em texto puro; resto cifrado |

---

## Testes

```bash
python3 -m pytest tests/ -v
```

**106 testes** cobrindo: KDF, AES-GCM, TOTP, cadastro, autenticação, blockchain e armazenamento.

---

## Casos de teste sugeridos pelo enunciado

```
# Login correto + TOTP válido → sucesso
# Login com TOTP inválido → falha
# Login com senha incorreta → falha
# Usuário A adiciona bloco → cifrado corretamente
# Usuário A lê blockchain → decifra só seus blocos
# Tentativa de modificar ciphertext → falha de integridade (AES-GCM)
# Alterar hash_prev → erro de validação da cadeia
# Mesma senha + mesmo salt → mesma chave (KDF determinística)
# Salt diferente → chave diferente
```

Todos esses cenários têm testes automatizados em `tests/`.
