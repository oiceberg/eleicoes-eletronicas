# 🗳️ README | Sistema de Eleições Eletrônicas da AGESP

GitHub Project: https://github.com/oiceberg/eleicoes-eletronicas/

Este repositório contém uma solução completa para realização de eleições eletrônicas seguras, auditáveis e híbridas (Local + Nuvem).

Este sistema foi desenvolvido em conformidade com as regras estabelecidas no **Regimento Eleitoral da AGESP (Associação dos Gestores Públicos do Estado de São Paulo)** para as Eleições realizadas em 2025 ao Conselho Executivo e ao Conselho Fiscal e de Ética da entidade, disponível em https://agesp.org.br/assembleia-geral-aprova-regimento-eleitoral-e-convoca-eleicoes-para-2025/.

O sistema utiliza **Python** para a gestão criptográfica de credenciais e disparo de e-mails, e **Google Apps Script** para a validação, integridade e apuração dos votos em tempo real.

-----

## 1\. Visão Geral da Arquitetura

O projeto foi desenhado sobre três pilares: **Segurança, Anonimidade e Auditoria**.

1.  **Backend Local (`src/eleicoes.py`):** Responsável pela "Autoridade Certificadora". Ele detém a lista de eleitores e a Chave Mestra (`MASTER_KEY`). Gera pares de chaves únicas para cada eleitor e as distribui via canal seguro (E-mail SMTP). Nenhuma chave privada é armazenada permanentemente de forma associada ao nome do eleitor após o envio.
2.  **Frontend de Votação (Google Forms + `gs/Formulario.js`):** Interface de coleta. Possui um script de segurança que apaga os dados do formulário imediatamente após o envio, garantindo que o sigilo do voto não seja comprometido pelo armazenamento padrão do Google Forms.
3.  **Core de Processamento (`gs/Planilha.js`):** O "Motor de Apuração". Recebe os dados brutos na planilha, recalcula as assinaturas criptográficas para validar a autenticidade do voto e aplica as regras de negócio (pontos conforme o Método de Borda modificado, unicidade do voto etc.).

-----

## 2\. Explicação Técnica: Como funciona a engrenagem

Para desenvolvedores e auditores, este é o fluxo detalhado de execução dos scripts:

### 2.1. O Backend (Python)

Quando executamos `python src/eleicoes.py`:

1.  **Auditoria de Integridade (Fail-Fast):** Antes de qualquer lógica, o script calcula o hash **SHA-256** de todos os arquivos críticos do projeto (`.py`, `.js`, `.csv`, `.toml`). Isso garante que o código sendo executado é exatamente o código auditado. Um "Meta Hash" do arquivo de auditoria é gerado ao final.
2.  **Sanity Check:** Carrega a lista de eleitores e interrompe imediatamente se encontrar e-mails mal formatados.
3.  **Anonimato e Ordem de Registro:** Se houver mais de um eleitor, a lista de processamento é **embaralhada de forma criptograficamente segura** usando o módulo `secrets` do Python. Isso previne qualquer correlação entre a ordem da lista de eleitores de entrada (ex: alfabética) e a ordem de registro das chaves na planilha, **garantindo o anonimato**.
4.  **Criptografia (HMAC-SHA256):**
    * Para cada eleitor, gera um **ID Público** (6 números aleatórios).
    * Gera uma **Chave Privada** (**12 caracteres alfanuméricos aleatórios**).
    * Calcula a **Chave Pública** usando HMAC-SHA256: **`HMAC(Mensagem=Chave Privada, Chave=MASTER_KEY)`**.
5.  **Sincronização com a Nuvem:**
    * Conecta-se à API do Google Sheets.
    * Invalida chaves antigas (se houver reenvio).
    * Registra apenas o **ID** e a **Chave Pública** na aba `Credenciais`. A **Chave Privada** possui **existência efêmera**, sendo gerada localmente, utilizada para calcular a Chave Pública e enviada por e-mail, residindo, a partir de então, apenas na caixa de entrada do eleitor.
    * A **Chave Privada nunca é registrada** na planilha ou em qualquer outro lugar, nem localmente, nem na nuvem.
6.  **O "Cutucão" (Trigger Flag - Disparo Único):**
    * **Após atualizar todas as Chaves Públicas** na aba `Credenciais`, o Python escreve um ***timestamp*** (carimbo de data/hora) na célula `config_automatica!A1`. Este passo é executado **apenas uma vez** para evitar o consumo excessivo da cota de processamento do Apps Script.
    * **Motivação Técnica (Contorno de API):**
        * Esta abordagem é necessária porque a API do Google Sheets **não permite que um script externo (o Python) chame diretamente uma função customizada do Google Apps Script** (como a `triggerApuracao`).
        * Ao invés disso, utilizamos a própria planilha como um **agente de comunicação**. A edição dessa célula ativa o gatilho nativo do Apps Script configurado como **"Ao alterar"** (`onChange`). O gatilho `onChange` é necessário porque o gatilho **"Ao editar"** (`onEdit`) não é disparado por alterações feitas via API.
        * O `onChange` aciona a função `triggerApuracao` dentro da segurança da nuvem do Google, que inicia o recálculo imediato de todas as estatísticas.
7.  **Disparo de Credenciais:** Envia o ID e a Chave Privada (que só existem na memória do script neste momento) para o e-mail do eleitor via SMTP TLS seguro.

### 2.2. A Segurança do Formulário (`Formulario.js`)

O Google Forms nativamente armazena as respostas associadas ao usuário logado. Para manter o sigilo dos votos e mitigar isso:

  * O script `onFormSubmit` é acionado a cada voto.
  * Ele executa `FormApp.getActiveForm().deleteAllResponses()`.
  * **Resultado:** O formulário atua apenas como um "túnel". Os dados chegam na planilha, mas são instantaneamente destruídos na origem.

### 2.3. O Core de Validação (`Planilha.js`)

É aqui que a mágica da validação acontece na nuvem:

1.  **Recepção do Voto:** O eleitor insere seu ID e sua Chave Privada no formulário.
2.  **Verificação de Assinatura (Zero Knowledge) e Limpeza Criptográfica:**
      * O script lê a Chave Privada submetida (na aba `Respostas`).
      * Imediatamente, ele usa a mesma `MASTER_KEY` (configurada nas Propriedades do Script) para **recalcular o HMAC-SHA256**, gerando a Chave Pública esperada.
      * **Limpeza Criptográfica:** Após a validação, o script **substitui** a Chave Privada original na célula de registro pela **Chave Pública** recém-calculada. O voto validado (na aba `validacao_automatica`) é então registrado com o ID, a Chave Pública e os Votos, garantindo que a **Chave Privada não permaneça armazenada** em qualquer registro permanente na planilha.
      * Se o hash calculado bater com a **Chave Pública registrada na aba `Credenciais`**, o voto é autêntico. Se não, é fraude ou erro de digitação.
3.  **Controle de Unicidade:** O sistema verifica se aquele ID já votou. Se houver múltiplos votos válidos, apenas o **primeiro** "Voto Válido" é contabilizado. Os demais são marcados como "Voto Repetido" ou "Voto Branco".
4.  **Apuração (Método de Borda):**
      * Calcula automaticamente a pontuação para o Conselho Executivo (peso posicional).
      * Computa votos simples para o Conselho Fiscal.
      * Gera estatísticas (MTPCE, Nota de Corte) formatando números inteiros corretamente e mantendo precisão decimal apenas onde necessário.

-----

## 3\. Estrutura do Projeto

```text
/
├── src/
│   └── eleicoes.py           # 🐍 Script principal (Cripto, API Google e E-mail)
├── gs/
│   ├── Formulario.js         # 📜 Script do FORMULÁRIO (Limpeza de dados/Segurança)
│   └── Planilha.js           # 📜 Script da PLANILHA (Cripto, Validação e Apuração)
├── config/
│   ├── env.toml              # ⚙️ Segredos (MASTER_KEY e SMTP_PASSWORD) - NÃO COMITAR
│   └── credentials.json      # 🔑 Chave de Serviço Google (JSON) - NÃO COMITAR
├── data/
│   ├── eleitores.csv         # 👥 Input: Lista de eleitores (Nome Completo;Endereço de e-mail)
│   ├── enviados.csv          # 📝 Log Local: Histórico de Envios (Registro de Chaves Válidas)
│   ├── eleicoes.log.csv      # 📝 Log Local: Registro técnico detalhado da execução
│   └── audit_hashes.csv      # 🔐 Auditoria: Hashes SHA-256 dos arquivos na execução
├── templates/
│   └── template.html         # 📧 Template HTML do e-mail
├── .gitignore                # Regras de segurança do Git
├── requirements.txt          # Dependências Python
└── README.md                 # Este arquivo
```

-----

## 4\. Instalação e Configuração

### 4.1. Pré-requisitos

  * Python 3.11+ (Nota: para versões antigas, pode ser necessário o pacote `tomli` e o bloco `try/except` no `eleicoes.py`.)
  * Conta Google Cloud (para ativar a Sheets API)

### 4.2. Instalação

```bash
pip install -r requirements.txt
```

### 4.3. Configuração de Segredos (`config/env.toml`)

Crie o arquivo `config/env.toml` na raiz (baseado no exemplo). **Nota:** As chaves devem estar na raiz do arquivo (formato flat), e em caixa alta:

```toml
# config/env.toml
MASTER_KEY = "SUA_FRASE_SECRETA_CRIPTOGRAFICA_AQUI"
SMTP_PASSWORD = "SUA_SENHA_SMTP_DO_EMAIL"
```

### 4.4. 🔑 Credenciais do Google (Service Account)

Para que o script Python possa ler e escrever dados na planilha online (via Google Sheets API), ele precisa de uma credencial de acesso seguro: o arquivo **Service Account JSON**.

Siga os passos para obter e configurar este arquivo:

#### 1\. Criar a Service Account no Google Cloud

1.  Acesse o **Google Cloud Console** e crie um novo projeto (ou selecione o projeto onde a sua planilha reside).
2.  Navegue até **APIs e Serviços** \> **Credenciais**.
3.  Clique em **Criar credenciais** e selecione **Conta de Serviço (Service Account)**.
4.  Dê um nome e descrição claros (ex: `agesp-eleicoes-service`). Clique em **Criar e continuar**.
5.  Em "Conceder a esta conta de serviço acesso ao projeto", você pode pular a etapa ou dar o papel de **Editor de Projetos** (se o projeto for dedicado a esta eleição).
6.  Clique em **Concluído**.

#### 2\. Gerar a Chave JSON

1.  Na tela de **Credenciais**, encontre a conta de serviço que você acabou de criar.
2.  Clique no nome da conta de serviço e vá para a aba **Chaves**.
3.  Clique em **Adicionar chave** \> **Criar nova chave**.
4.  Selecione o tipo **JSON** e clique em **Criar**.
5.  O arquivo JSON será baixado automaticamente para o seu computador.

#### 3\. Configuração Local e Compartilhamento

1.  **Mova/Renomeie** o arquivo JSON baixado para o caminho `config/credentials.json` no seu projeto.
2.  Abra o arquivo `config/credentials.json` e localize o valor do campo **`client_email`**.
3.  Abra sua planilha do Google Sheets e use a função **Compartilhar** para conceder acesso de **Editor** a este `client_email` (o e-mail da Service Account).

Com isso, o Python está autenticado para operar na planilha online.

-----

## 5\. Configuração do Google Apps Script

### 5.1. Na Planilha (Core)

Copie o código de `gs/Planilha.js` para o editor de script da planilha.

**Configurações do Projeto (Script Properties):**
Defina as seguintes propriedades (File \> Project Properties \> Script Properties):

  * `MK`: A mesma string usada em `MASTER_KEY` no `env.toml`.
  * `QTD_CANDIDATOS_EXEC`: Número inteiro (ex: `10`) para cálculo do Método de Borda.

**Acionadores (Triggers) Obrigatórios:**
Configure manualmente os seguintes gatilhos:

| Função | Origem do Evento | Tipo de Evento | Descrição |
| :--- | :--- | :--- | :--- |
| `onFormSubmit` | Da planilha | **Ao enviar o formulário** | Processa o voto assim que chega. |
| `triggerApuracao` | Da planilha | **Ao alterar** | Acionado pelo Python (via flag cell) para atualizar a apuração. |

### 5.2. No Formulário (Segurança)

Copie o código de `gs/Formulario.js` para o editor de script do formulário.

  * Adicione um gatilho para `onFormSubmit` -\> **Ao enviar o formulário**.

-----

## 6\. 🚀 Executando o Sistema

O script principal é `src/eleicoes.py`. Ele requer um argumento para o **Destinatário** (`TODOS` ou um endereço de e-mail específico) e uma *flag* opcional para o **Modo de Produção** (`--production`).

### 6.1. Modo de Teste (Simulação)

No modo de teste, o script gera e registra as credenciais na planilha, mas **não envia e-mails reais**. O conteúdo do e-mail é impresso no terminal para que você possa verificar a formatação HTML e as credenciais geradas.

| Uso | Comando |
| :--- | :--- |
| **Simulação Individual** | `python src/eleicoes.py email@exemplo.com` |
| **Simulação em Massa** | `python src/eleicoes.py TODOS` |

### 6.2. Modo de Produção (Envio Real)

Use a *flag* `--production` para disparar os e-mails reais via SMTP. O comportamento de segurança da *flag* `--resend` é crucial neste modo.

#### Opções de Envio Individual

| Uso | Comando | Comportamento |
| :--- | :--- | :--- |
| **Reenvio Individual** | `python src/eleicoes.py email@exemplo.com --production` | **Comportamento Implícito:** O script sempre gera uma **nova chave** para o alvo específico e a envia, invalidando qualquer chave anterior. |

#### Opções de Envio em Massa (TODOS)

| Uso | Comando | Comportamento (Segurança Priorizada) |
| :--- | :--- | :--- |
| **Resumo/Continuação** | `python src/eleicoes.py TODOS --production` | **Recomendado:** Envia *apenas* para os eleitores que *ainda não* constam no log (`enviados.csv`). Permite continuar o envio após uma interrupção, sem gerar chaves novas para quem já recebeu. |
| **Reenvio Forçado** | `python src/eleicoes.py TODOS --resend --production` | **ATENÇÃO:** Força a regeneração de **todas** as credenciais e o reenvio para todos os eleitores. **Isso invalida todas as chaves enviadas anteriormente.** Use apenas em caso de auditoria ou necessidade extrema. |

### 6.3. Nota Importante sobre Logs

A cada envio bem-sucedido tanto no modo **Teste** como no **Produção**, o e-mail do eleitor é registrado em `data/enviados.csv`. Esta lista é usada como base para o modo **Resumo/Continuação** (`TODOS` sem `--resend`).

-----

## 7\. Auditoria

A cada execução, o sistema gera o arquivo `data/audit_hashes.csv`. Este arquivo contém o hash SHA-256 do próprio script, das configurações e da lista de eleitores no momento do envio.

Isso permite provar matematicamente que o código que realizou a eleição não foi alterado acidental ou maliciosamente em relação ao código auditável no repositório.