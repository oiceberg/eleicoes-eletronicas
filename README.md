# 🗳️ README | Sistema de Eleições Eletrônicas da AGESP

Este documento é o guia completo para a utilização e auditoria do Sistema de Eleições Eletrônicas da AGESP.

-----

## 1\. Visão Geral do Projeto

Este sistema automatiza a criação e distribuição de chaves criptográficas para votação eletrônica, garantindo o **sigilo do voto** e a **auditabilidade** do processo. O fluxo é dividido em três módulos principais:

1.  **Geração de Chaves (`keys_generator.py`):** Cria pares de chaves pública/privada, garantindo o **desacoplamento** entre a identidade do eleitor e seu voto.
2.  **Disparo de E-mails (`mailer.py`):** Envia as chaves privadas e o link de votação de forma segura, com log e mecanismos de resiliência.
3.  **Módulo de Validação (Google Apps Script):** Código implementado na Planilha de Votação para validar a unicidade das chaves e realizar a contagem dos votos (incluindo o método de Borda modificado).

-----

## 2\. Estrutura de Arquivos

O projeto utiliza a seguinte estrutura. Note que **apenas os arquivos de exemplo (`.example`) são versionados no Git** para proteger os dados sensíveis (`.csv` e `.env` reais):

```
/
├── src/
│   ├── keys_generator.py       # Geração de chaves e arquivos de auditoria.
│   └── mailer.py               # Disparo de e-mails em massa.
├── data/
│   ├── eleitores_base.csv.example      # ⬅️ ENTRADA DE TESTE: Dummy Data (Para testes).
│   ├── envio_confidencial.csv.example  # ⬅️ ESTRUTURA: Exemplo do arquivo sigiloso de envio.
│   ├── keys_hash.csv.example           # ⬅️ ESTRUTURA: Exemplo da chave e hash para validação.
│   ├── lista_eleitores_aptos.csv.example # ⬅️ ESTRUTURA: Exemplo da lista de nomes para auditoria.
│   └── lista_chaves_validas.csv.example  # ⬅️ ESTRUTURA: Exemplo da lista de chaves públicas para auditoria.
├── apps_script/                # ⬅️ MÓDULO: Arquivos JavaScript do Google Apps Script.
├── .env                        # ⬅️ CONFIGURAÇÃO: Variáveis de ambiente (IGNORADO PELO GIT).
├── .env.example                # Exemplo de arquivo de configuração para referência.
├── requirements.txt            # Lista de dependências Python.
└── README.md
```

-----

## 3\. Pré-requisitos e Instalação

### 3.1. Requisitos de Software

  * **Python 3.x**
  * **Gerenciador de Pacotes `pip`**

### 3.2. Instalação das Dependências

Instale todas as dependências do projeto listadas no arquivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3.3. Configuração Inicial do Arquivo `.env`

Copie o arquivo `.env.example` para `.env` e preencha as credenciais. O `.env` é o único arquivo **IGNORADO** pelo Git com dados sensíveis.

-----

## 4\. Fluxo de Trabalho (Geração e Envio)

### Passo 1: Preparar a Lista Base

1.  **Modo de Teste:** O script `keys_generator.py` irá automaticamente usar o **`data/eleitores_base.csv.example`** se o arquivo oficial não for encontrado.
2.  **Modo de Produção:** Crie o arquivo **`data/eleitores_base.csv`** com a lista oficial de eleitores. **ESTE ARQUIVO NUNCA DEVE SER COMITADO NO GIT.**

### Passo 2: Gerar as Chaves Criptográficas

Execute o script **`keys_generator.py`**. Este passo gera todos os arquivos de dados confidenciais e públicos, sobrescrevendo os arquivos CSV reais na pasta `data/`.

```bash
python ./src/keys_generator.py
```

**Saídas geradas (4 arquivos principais):**

  * **`data/envio_confidencial.csv`** (SIGILOSO): Contém Nome, Email, Chave Pública e Chave Privada. Esta é a **ÚNICA ENTRADA** do `mailer.py`.
  * **`data/keys_hash.csv`** (SISTEMA/AUDITORIA): Contém a Chave Pública e o Hash da Chave Privada. **ESTE ARQUIVO DEVE SER IMPORTADO PARA A ABA `keys_hash` DA PLANILHA DE VALIDAÇÃO**.
  * **`data/lista_eleitores_aptos.csv`** (PÚBLICO): Lista de Nomes E E-mails de Eleitores (para conferência pública).
  * **`data/lista_chaves_validas.csv`** (PÚBLICO): Lista de Chaves Públicas geradas (para auditoria).

### Passo 3: Enviar os E-mails

1.  **Configure o Modo:** Ajuste a variável `SIMULACAO` no arquivo `.env`.
      * **Teste/Simulação:** `SIMULACAO=true`
      * **Produção:** `SIMULACAO=false`
2.  Execute o envio:

<!-- end list -->

```bash
python ./src/mailer.py
```

> **NOTA DE SEGURANÇA:** O script `mailer.py` controla automaticamente o log de envio.
>
>   * Em **Simulação** (`SIMULACAO=true`), ele reenvia todos os e-mails (para testes de formatação).
>   * Em **Produção** (`SIMULACAO=false`), ele **ignora automaticamente** os e-mails já registrados no `data/envios_log.csv`, garantindo que ninguém receba duplicatas.

-----

## 5\. Módulo Google Apps Script (Funções Chave na Planilha)

O código JavaScript (`apps_script_eleicoes_eletronicas.js`) deve ser copiado e colado no editor do Google Apps Script associado à sua Planilha de Votação.

| Função (Chamada na Planilha) | Módulo | Finalidade |
| :--- | :--- | :--- |
| **`EXPECTED_HASH(chave_publica)`** | Validação | Função auxiliar. Busca na aba `keys_hash` o hash pré-calculado e **esperado** da Chave Privada, utilizando a Chave Pública como índice de busca. |
| **`HASH_SHA256(chave_privada)`** | Criptografia | Função auxiliar. Gera o hash criptográfico SHA-256 de qualquer *texto*. Usada para **gerar o hash da Chave Privada** inserida pelo eleitor. |
| **`VALIDAR_CHAVES(pub, priv)`** | Validação | **Função principal de validação.** Verifica o par Chave Pública (`pub`) e Chave Privada (`priv`) fornecido pelo eleitor. Compara o hash gerado com o hash esperado na aba `keys_hash`. Retorna `TRUE` (válido) ou `FALSE` (inválido). |
| **`BORDA_SCORECARD_BY_COLNAME(...)`** | Método de Borda | Implementa o **método de Borda modificado** para a contagem de pontos do Conselho Executivo. Atribui pontuações decrescentes conforme a ordem de preferência. |
| **`FISCAL_SCORECARD_BY_COLNAME(...)`** | Contagem Simples | Realiza a contagem **simples** de votos para os Conselhos Fiscal e de Ética (método de 1 voto por candidato). |

-----

## 6\. Segurança e Melhores Práticas

  * **Pós-Envio (CRÍTICO):** Após a conclusão bem-sucedida do envio, **EXCLUA O ARQUIVO `data/envio_confidencial.csv` permanentemente.** Este arquivo contém o mapeamento `Email -> Chave Privada` e representa o maior risco de sigilo do sistema.
  * **MASTER\_SECRET:** A `MASTER_SECRET` no `.env` é o segredo central. Sua perda inviabiliza a auditoria, e seu vazamento compromete o sigilo antes da votação.
  * **Retomada:** Em caso de interrupção, o sistema retomará automaticamente de onde parou ao definir `SIMULACAO=false` e rodar novamente.# eleicoes-eletronicas
