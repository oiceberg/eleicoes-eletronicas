# 🗳️ README | Sistema de Eleições Eletrônicas da AGESP

Este documento é o guia completo para configuração, utilização e auditoria do Sistema de Eleições Eletrônicas. O sistema combina um script **Python** (para geração de credenciais e envio de e-mails) com scripts do **Google Apps Script** (para validação e apuração em tempo real na nuvem).

-----

## 1\. Visão Geral do Projeto

O sistema opera em um fluxo híbrido local/nuvem:

1.  **Backend Local (Python):** Lê a lista de eleitores, gera chaves criptográficas (HMAC-SHA256), atualiza a planilha do Google Sheets via API e envia e-mails personalizados com as credenciais.
2.  **Frontend de Votação (Google Forms):** Coleta os votos e as credenciais (ID e Chave Privada) dos eleitores.
3.  **Core de Validação (Google Sheets + Apps Script):** Processa cada voto em tempo real, valida a autenticidade das chaves contra o banco de dados e gera a apuração automaticamente (incluindo Método de Borda e regras estatísticas).

-----

## 2\. Estrutura de Arquivos

O projeto deve ser organizado da seguinte forma. **Arquivos sensíveis (`.json`, `.toml`, `.csv` reais) são ignorados pelo Git** para segurança.

```text
/
├── src/
│   └── eleicoes.py           # 🐍 Script principal (Geração, API Google e E-mail)
├── gs/
│   ├── Planilha.js           # 📜 Script para a PLANILHA (Validação e Apuração)
│   └── Formulario.js         # 📜 Script para o FORMULÁRIO (Limpeza de dados)
├── config/
│   ├── env.toml              # ⚙️ Configurações e Segredos (Renomear de .example)
│   └── credentials.json      # 🔑 Chave de Acesso Google Service Account (NÃO COMITAR)
├── data/
│   ├── eleitores.csv         # 👥 Entrada: Lista de eleitores (Nome;Email)
│   ├── enviados.csv          # 📝 Log: Histórico de chaves geradas
│   └── eleicoes.log.csv      # 📝 Log: Registro de execução do sistema
├── templates/
│   └── template.html         # 📧 Modelo visual do e-mail enviado
├── .gitignore                # Regras de exclusão do Git
├── requirements.txt          # Dependências Python
└── README.md                 # Este arquivo
```

-----

## 3\. Pré-requisitos e Instalação

### 3.1. Python

Instale as dependências listadas no `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3.2. Configuração do Google Cloud (O "Passo Difícil")

Para que o Python converse com a Planilha, você precisa de uma **Service Account**:

1.  Acesse o [Google Cloud Console](https://console.cloud.google.com/).
2.  Crie um novo Projeto.
3.  Vá em **APIs e Serviços \> Biblioteca** e ative a **Google Sheets API**.
4.  Vá em **IAM e Administrador \> Contas de serviço** e clique em **Criar conta de serviço**.
5.  Dê um nome e crie. Na lista de contas, clique nos três pontos da conta criada \> **Gerenciar chaves**.
6.  Clique em **Adicionar chave \> Criar nova chave \> JSON**.
7.  O download de um arquivo `.json` começará.
8.  **Mova este arquivo** para a pasta `config/` do projeto e renomeie-o para `credentials.json` (ou mantenha o nome original e atualize a referência).
9.  **IMPORTANTE:** Abra o JSON, copie o `client_email` (algo como `projeto@...iam.gserviceaccount.com`).
10. Vá na sua **Planilha de Votação** no Google Sheets, clique em **Compartilhar** e adicione esse e-mail como **Editor**.

-----

## 4\. Configuração dos Arquivos

### 4.1. Arquivos de Exemplo

Na pasta `config/` e `data/`, você encontrará arquivos terminados em `.example`.

1.  Renomeie `config/env.toml.example` para **`config/env.toml`**.
2.  Renomeie `data/eleitores.csv.example` para **`data/eleitores.csv`**.

### 4.2. Editando o `env.toml`

Abra o `config/env.toml` e preencha as variáveis:

  * `master_key`: Uma frase secreta usada para gerar as chaves criptográficas. **Nunca a altere depois de começar a enviar as chaves.**
  * `smtp_pass`: A senha do seu servidor de e-mail.

-----

## 5\. Configuração do Google Apps Script

Este passo conecta a lógica de validação à sua planilha e formulário.

### 5.1. Na Planilha de Votação (Google Sheets)

1.  Vá em **Extensões \> Apps Script**.
2.  Apague o código padrão e cole o conteúdo do arquivo **`gs/Planilha.js`**.
3.  **Configurar Propriedades do Script (Segredos na Nuvem):**
      * No editor, clique na engrenagem (Configurações do Projeto).
      * Role até **Propriedades do Script** e adicione:
          * Chave: `MK` | Valor: *(A mesma master\_key que você colocou no env.toml)*
          * Chave: `QTD_CANDIDATOS_EXEC` | Valor: *(Ex: 10 - O número de candidatos/pontos máximos)*
4.  **Configurar Gatilhos (Triggers):**
      * Clique no ícone de relógio (Acionadores).
      * Adicione um acionador para a função `onFormSubmit`: Evento `Da planilha` -\> `Ao enviar o formulário`.
      * Adicione um acionador para a função `onSpreadsheetEdit`: Evento `Da planilha` -\> `Ao editar`.
      * Adicione um acionador para a função `processLastResponse`: Evento `Da planilha` -\> `Ao alterar`.

### 5.2. No Formulário (Google Forms)

1.  Vá em **três pontinhos \> Editor de script**.
2.  Cole o conteúdo do arquivo **`gs/Formulario.js`**.
3.  Configure um acionador para limpar as respostas após o envio (para a segurança dos dados).

-----

## 6\. Executando o Sistema

### 6.1. Definir Credenciais no Terminal

Antes de rodar o script, você precisa dizer ao Google onde está sua chave JSON. No terminal (na raiz do projeto):

**Windows (Git Bash/Mingw):**

```bash
export GOOGLE_APPLICATION_CREDENTIALS="./config/credentials.json"
```

*(Se o nome do seu JSON for diferente, ajuste o caminho).*

### 6.2. Rodar o Script Python

O script `src/eleicoes.py` gerencia tudo.

**Modo de Teste (Simulação):**
Gera chaves, atualiza a planilha, mas **não** envia e-mails reais (mostra no terminal).

```bash
python src/eleicoes.py TODOS
```

**Modo de Produção (Envio Real):**
Envia os e-mails para os eleitores.

```bash
python src/eleicoes.py TODOS --production
```

**Reenviar para um único eleitor:**

```bash
python src/eleicoes.py email@exemplo.com --resend --production
```

-----

## 7\. Entendendo a Auditoria e Apuração

A aba `validacao_automatica` na planilha é gerada automaticamente.

  * **Credenciais (Col D):** Verifica criptograficamente se a chave usada pertence ao eleitor.
  * **Contador (Col F):** Garante que, se o eleitor votar mais de uma vez, apenas o **primeiro voto válido com conteúdo** seja contabilizado.
  * **Validação (Col G):** O status final do voto (`VÁLIDO - ...`, `Voto Repetido`, etc).

A aba `Apuração` exibe:

  * **Tabelas de Pontuação:** Resultado final usando Método de Borda (Executivo) e voto simples (Fiscal).
