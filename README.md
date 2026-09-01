# ☁️ Cloud IAM Auditor

> **CLI Python que audita permissões IAM em AWS, identifica principals com privilégios excessivos e gera relatórios de segurança acionáveis.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-IAM-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/iam/)
[![Security](https://img.shields.io/badge/Security-DevSecOps-EB042F?logo=security)](https://aws.amazon.com/security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 O problema

Políticas IAM mal configuradas são a **#1 causa de incidentes de segurança na cloud**. Um principal (usuário, role, ou service) com permissões demais pode ser a porta de entrada para um atacante.

Auditar IAM manualmente no Console AWS é demorado, propenso a erros e difícil de acompanhar mudanças.

## 💡 A solução

Uma **CLI single-command** que:

- 🔍 Lista todos os IAM principals (users, roles, groups)
- 📋 Coleta políticas inline e gerenciadas attached
- ⚠️ Identifica permissões perigosas (`*:*`, `Admin*`, `PassRole`, etc.)
- 🚨 Detecta roles assumíveis publicamente ou por outras contas
- 📊 Gera relatório estruturado (JSON + HTML + CSV)
- ✅ Ignora recursos protegidos (você configura allowlists)

---

## ⚡ Features

- 🔎 **Enumeração completa** — users, roles, groups, policies managed
- 🚨 **Detecção de privilégios excessivos** — wildcard actions, `*`, `Admin`, `PowerUser`
- 🔗 **Análise de PassRole** — roles que podem ser passadas para serviços perigosos
- 🌐 **Trust policy auditing** — roles assumíveis de fora da conta ou anonimamente
- 📊 **Relatório multi-formato** — JSON, CSV, HTML
- 🎯 **Suppress list** — permite ignorar recursos合法的 known-good
- ⚡ **Parallel fetching** — usa asyncio para coletar dados rápido

---

## 🛠️ Stack

| Camada | Tecnologia |
|---|---|
| **Linguagem** | Python 3.10+ |
| **SDK AWS** | `boto3` |
| **HTTP async** | `aiohttp` (para APIs que usam REST) |
| **CLI** | `click` |
| **Output** | `rich` (tabelas no terminal), JSON, CSV |
| **Testes** | `pytest`, ` moto` (mock AWS) |

---

## 📂 Estrutura

```
cloud-iam-auditor/
├── iam_auditor/
│   ├── __init__.py
│   ├── cli.py            # Click CLI entry point
│   ├── collector.py      # Coleta dados IAM (async, boto3 paginators)
│   ├── analyzer.py       # Analisa políticas e detecta issues
│   ├── reporter.py       # Gera relatórios (JSON, CSV, HTML)
│   ├── rules.py          # Regras de detecção de issues
│   └── config.py         # Config (profiles, regions, suppress list)
├── tests/
│   ├── conftest.py
│   ├── test_analyzer.py
│   └── test_collector.py
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## 🚀 Como usar

### 1. Instale

```bash
git clone https://github.com/caiodevlab/cloud-iam-auditor
cd cloud-iam-auditor
pip install -r requirements.txt
```

### 2. Configure credenciais AWS

```bash
# Recomendado: perfil nomeado (não usar default para produção)
aws configure --profile seguranca

# Ou variáveis de ambiente
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### 3. Execute o scan

```bash
# Scan rápido (todos os perfis da conta padrão)
python -m iam_auditor.cli audit

# Scan com perfil específico
python -m iam_auditor.cli audit --profile minha-conta --region us-east-1

# Scan completo com todos os formatos de saída
python -m iam_auditor.cli audit \
  --profile minha-conta \
  --output report.json \
  --output report.html \
  --output report.csv \
  --severity HIGH,CRITICAL

#dry-run: mostra o que faria sem executar
python -m iam_auditor.cli audit --dry-run
```

### 4. Saída no terminal

```
╭─────────────────────────────────────────────────────────────╮
│  Cloud IAM Auditor v0.1.0                                  │
╠═════════════════════════════════════════════════════════════╣
│  Account: 123456789012 (minha-conta)                       │
│  Region:  us-east-1                                        │
│  Scanned: 12 users | 23 roles | 5 groups                  │
│  Duration: 4.2s                                            │
╠═════════════════════════════════════════════════════════════╣
│  CRITICAL: 2    HIGH: 5    MEDIUM: 8    LOW: 3            │
╰─────────────────────────────────────────────────────────────╯

🚨 CRITICAL
  ⚠ Role: "lambda-admin-role"        [Attach:AdministratorAccess]
  ⚠ User: "backup-service"           [Inline: *:*]

✅ LOW
  ✓ Role: "cloudwatch-readonly"       [Attach:ReadOnlyAccess]
```

---

## 🔍 O que é verificado

### CRITICAL
- Policy com `Effect: Allow` + `Action: "*"`
- Role com `*:*` (qualquer serviço, qualquer ação)
- Usuário com `AdministratorAccess` ou `PowerUserAccess`
- Policy inline com `NotAction` que bloqueia só `Delete*`

### HIGH
- `iam:PassRole` em roles sem restrição de serviço
- `sts:AssumeRole` com `Principal: "*"`
- Políticas gerenciadas known-dangerous (ex: `*FullAccess`)
- Usuário com múltiplas chaves de acesso ativas

### MEDIUM
- Role assumível por outras contas sem necessidade clara
- Policy antiga com versão descontinuada
- Usuário sem MFA habilitado

### LOW
- Usuário semÚltimo Acesso verificado
- Grupo vazio
- Policy gerenciada sem tags

---

## ⚙️ Configuração — suppress list

Crie `~/.iam_auditor/config.yaml` para ignorar recursos known-good:

```yaml
suppress:
  roles:
    - "AWSReservedSSO_*"          # SSO roles, esperados
    - "aws-reserved*"              # roles reservadas AWS
  users:
    - "aws-reserved*"             # usuários reservados AWS
  policies:
    - "AWS*Policy"                 # políticas AWS gerenciadas
    - "service-role/*"            # roles de serviço
```

---

## 📝 Licença

MIT — use, modifique, distribua.

---

<p align="center">
  Feito com ☕ por <a href="https://github.com/caiodevlab">@caiodevlab</a>
</p>
