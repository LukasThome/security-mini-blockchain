# Mini-Blockchain com Autenticação de Usuário

**Disciplina:** Segurança da Informação (INE5680) — UFSC

Sistema multiusuário de blockchain onde cada usuário autentica com senha e TOTP. As transações são cifradas com AES-256-GCM.

## Requisitos

```bash
pip3 install cryptography
```

## Como executar

```bash
python3 main.py
```

## Estrutura do projeto

- `criptografia.py`: Primitivas de criptografia (KDF, AES-GCM, SHA-256).
- `autenticacao.py`: Cadastro e login com TOTP.
- `blockchain.py`: Lógica da blockchain e gerenciamento de blocos.
- `armazenamento.py`: Persistência em JSON.
- `main.py`: Interface CLI.

## Segurança

- **Confidencialidade:** AES-256-GCM por bloco.
- **Integridade:** Tag de autenticação do GCM e encadeamento SHA-256.
- **Autenticação:** Dois fatores (Senha + TOTP).
- **Chaves:** Derivadas via PBKDF2 (sem chaves fixas).
