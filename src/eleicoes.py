"""
Script Name: eleicoes.py
Versão: 1.1
Date: 2025-12-08
Authors:
    - Leandro Pires Salvador (leandrosalvador@protonmail.com, leandrosalvador@gmail.com)
    - Tiago Barreiros de Freitas (tiago4680@gmail.com)
Description:
    Sistema de processamento de credenciais e disparo de e-mails para as eleições eletrônicas da AGESP.
    O script gera chaves criptográficas (ID, Chave Privada e Chave Pública), as registra
    na planilha 'Credenciais' do Google Sheets e envia as credenciais por e-mail aos eleitores.
    Possui modo de TESTE (simulação) e modo de PRODUÇÃO (envio real).

GitHub Project: https://github.com/oiceberg/eleicoes-eletronicas/

Changelog:
- 1.0: Lançamento com funcionalidade completa, incluindo:
    - Validação de formato de e-mail (fail-fast).
    - Geração de hashes SHA-256 de arquivos críticos para auditoria em vídeo.
    - Registro de Meta Hash do arquivo de auditoria (audit_hashes.csv).
    - Invalidação automática de chaves antigas no Google Sheets.
    - Disparo de e-mails via SMTP seguro.
    - Suporte a envio individual (reenvio) ou em massa.

TODO:
- [Acompanhamento] Monitorar performance da API do Sheets com grande volume de dados.
"""

import argparse
import csv
import hmac
import os
import sys
import secrets
import string
import time
import tomllib
import smtplib
import ssl
import hashlib
import re
import requests
from dataclasses import dataclass, asdict
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr
from typing import Final, Any, Optional, List, Dict

import google.auth
from googleapiclient.discovery import build


# --- 1. CONFIGURAÇÃO E CONSTANTES ---

# Arquivos e Formatos
DELIMITER: Final[str]          = ';'
ENCODING: Final[str]           = 'utf-8-sig'
DATE_FORMAT: Final[str]        = '%d/%m/%Y %H:%M:%S'
ELEITORES_FILEPATH: Final[str] = 'data/eleitores.csv'
ENVIADOS_FILEPATH: Final[str]  = 'data/enviados.csv'
LOG_FILEPATH: Final[str]       = 'data/eleicoes.log.csv'
TEMPLATE_FILEPATH: Final[str]  = 'templates/template.html'
GS_FORMULARIO_FILEPATH: Final[str] = 'gs/Formulario.js'
GS_PLANILHA_FILEPATH: Final[str]   = 'gs/Planilha.js'
ENV_TOML_FILEPATH: Final[str]      = 'config/env.toml'
TERMINAL_LOG_FILEPATH          = 'data/terminal_log.txt'

# Google Sheets
SPREADSHEET_ID: Final[str] = '1TwS__JwRBG94R4d0WuVMXcYKKnafBuKIJWiJ6frKufw'
APPS_SCRIPT_FLAG_CELL: Final[str] = 'config_automatica!A1'
SHEET_NAME_PUB_KEY = 'Credenciais'
RANGE_PUB_KEY = f'{SHEET_NAME_PUB_KEY}!A:F'

# Caminho programático da credencial para o Google Sheets API
CREDENTIALS_FILE_NAME: Final[str] = 'credentials.json'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, '..', 'config')
CREDENTIALS_PATH: Final[str] = os.path.join(CONFIG_DIR, CREDENTIALS_FILE_NAME)

# E-mail
SMTP_HOST: Final[str] = "smtp.hostinger.com"
SMTP_PORT: Final[int] = 465
SMTP_USER: Final[str] = "comissaoeleitoral@agesp.org.br"
FROM_NAME: Final[str] = "Comissão Eleitoral AGESP"
SUBJECT: Final[str]   = "Eleições AGESP 2025 – Suas credenciais para votação"

# Google Forms
BASE_FORM_URL: Final[str] = "https://forms.gle/KxS5SK5xcv7RPhew5"

# Datas da Eleição
DATA_INICIO_VOTACAO: Final[str] = "09/12/2025" 
DATA_FIM_VOTACAO: Final[str] = "10/12/2025"

# Constantes de integração com GitHub
GITHUB_OWNER = "oiceberg"
GITHUB_REPO = "eleicoes-eletronicas"
GITHUB_BRANCH = "main"

# Mapeamento de quais arquivos locais (usando o display name) devem ser comparados com o GitHub
GITHUB_FILES_TO_COMPARE = [
    'src/eleicoes.py',
    'gs/Formulario.js',
    'gs/Planilha.js',
    'templates/template.html',
]

# Carrega Variáveis de Ambiente (Segredos)
try:
    with open('config/env.toml', 'rb') as f:
        ENV: Final[dict[str, Any]] = tomllib.load(f)
except FileNotFoundError:
    print("[ERRO FATAL] Arquivo 'config/env.toml' não encontrado.")
    exit(1)


# --- 2. MODELOS DE DADOS ---

@dataclass
class LogEntry:
    timestamp: str
    is_production: bool
    level: str  # INFO, WARN, ERROR
    email: str
    user_id: str
    message: str

@dataclass
class Eleitor:
    nome: str
    email: str

@dataclass
class RegistroEnvio:
    timestamp: str
    email: str
    user_id: str
    pub_key: str
    generation: int
    is_active: bool
    is_delivered: bool
    is_production: bool

@dataclass
class KeyPair:
    user_id: str
    priv_key: str
    pub_key: str

class Tee:
    """
    Redireciona a saída (stdout) para múltiplos fluxos (terminal e arquivo).
    """
    def __init__(self, filename, mode="a"):
        self.file = open(filename, mode, encoding=ENCODING)
        self.stdout = sys.stdout

    def write(self, data):
        # 1. Escreve no arquivo
        self.file.write(data)
        self.file.flush() # Força a escrita imediata
        
        # 2. Escreve no terminal
        self.stdout.write(data)

    def flush(self):
        # Garante que ambos os fluxos sejam liberados
        self.file.flush()
        self.stdout.flush()

    def close(self):
        # Fecha apenas o arquivo (não o stdout original)
        self.file.close()

# --- 3. SERVIÇOS EXTERNOS (GOOGLE SHEETS) ---

class GoogleSheetsService:
    """Gerencia operações no Google Sheets com controle de cota e otimização."""

    def __init__(self, spreadsheet_id: str):
        self.spreadsheet_id = spreadsheet_id
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = CREDENTIALS_PATH
        creds, _ = google.auth.default()
        self.service = build("sheets", "v4", credentials=creds)

    def write_flag_to_cell(self, cell_range: str, value: str) -> None:
        """Escreve um valor na célula flag para acionar o Apps Script via gatilho OnEdit."""
        try:
            body = {'values': [[value]]}
            self.service.spreadsheets().values().update(
                spreadsheetId=self.spreadsheet_id, 
                range=cell_range,
                valueInputOption='RAW', 
                body=body
            ).execute()
        except Exception as e:
            print(f"[ERRO SHEETS] Falha ao escrever flag na célula {cell_range}: {e}")
            raise

    def append_row(self, sheet_name: str, values: list) -> None:
        """Insere uma nova linha na planilha."""
        try:
            self.service.spreadsheets().values().append(
                spreadsheetId=self.spreadsheet_id,
                range=f'{sheet_name}!A:F',
                valueInputOption='RAW',
                insertDataOption='INSERT_ROWS',
                body={'values': [values]}
            ).execute()
        except Exception as e:
            raise Exception(f"Falha na escrita da linha no Sheets: {e}")

    def update_cell(self, range_name: str, value: Any) -> None:
        body = {'values': [[value]]}
        (
            self.service.spreadsheets()
            .values()
            .update(
                spreadsheetId=self.spreadsheet_id,
                range=range_name,
                valueInputOption='RAW',
                body=body
            )
            .execute()
        )

    def invalidate_old_key(self, user_id: str) -> bool:
        """
        Busca e invalida (is_active=FALSE) a chave antiga do usuário, se ativa.
        Retorna True se houve PELO MENOS UMA escrita.
        """
        try:
            # 1. Busca todas as chaves (API Read)
            result = self.service.spreadsheets().values().get(
                spreadsheetId=self.spreadsheet_id, range=RANGE_PUB_KEY
            ).execute()
            values = result.get('values', [])
        except Exception as e:
            print(f"[ERRO API] Falha na leitura para invalidação: {e}")
            return False

        writes_performed = False
        
        # 2. Itera sobre TODAS as linhas
        for i, row in enumerate(values):
            row_index = i + 1
            if row_index == 1 or len(row) < 3: continue 

            current_id = str(row[0]).strip()
            is_active_str = str(row[2]).strip().upper() 
            
            if current_id == user_id:
                
                # Check Crítico: Se JÁ está desativada, apenas avisa e segue
                if is_active_str == 'FALSE':
                    print(f"[PULAR] Chave antiga {user_id} (linha {row_index}) já desativada.")
                    continue 

                # 3. Se encontrada e ATIVA, realiza a invalidação (Duas chamadas API Write)
                now_str = datetime.now().strftime(DATE_FORMAT)

                try:
                    # Update C: is_active = FALSE
                    self.service.spreadsheets().values().update(
                        spreadsheetId=self.spreadsheet_id, 
                        range=f'{SHEET_NAME_PUB_KEY}!C{row_index}', 
                        valueInputOption='RAW', 
                        body={'values': [['FALSE']]}
                    ).execute()
                    
                    # Update F: t_desativacao = Timestamp
                    self.service.spreadsheets().values().update(
                        spreadsheetId=self.spreadsheet_id, 
                        range=f'{SHEET_NAME_PUB_KEY}!F{row_index}', 
                        valueInputOption='RAW', 
                        body={'values': [[now_str]]}
                    ).execute()
                    
                    print(f"[SHEETS] Chave {user_id} desativada na linha {row_index} (C e F) da tabela {SHEET_NAME_PUB_KEY}.")
                    writes_performed = True
                    
                    # 💡 DELAY EXTRA PARA TRATAR DUPLICATAS: Se múltiplas escritas ocorrerem
                    time.sleep(2.0)
                    
                except Exception as e:
                    print(f"[ERRO API] Falha ao invalidar chave {user_id} na linha {row_index}: {e}")
                    continue
        
        return writes_performed


# --- 4. FUNÇÕES DE AUDITORIA E VALIDAÇÃO ---

def fetch_github_hashes(files_to_check: list[str]) -> dict:
    """
    Busca o conteúdo raw dos arquivos no GitHub e calcula seus hashes SHA-256.
    Requer a biblioteca 'requests' instalada.
    """
    github_hashes = {}
    # A URL RAW do GitHub usa barras normais (/)
    base_url = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}"

    for display_name in files_to_check:
        # O caminho no GitHub é o próprio display_name (ex: 'src/eleicoes.py')
        file_url = f"{base_url}/{display_name}"
        
        try:
            # Faz a requisição HTTP
            response = requests.get(file_url, timeout=10)
            response.raise_for_status() # Lança exceção para status 4xx/5xx

            # Calcula o Hash SHA-256 do conteúdo raw
            file_hash = hashlib.sha256(response.content).hexdigest()
            
            github_hashes[display_name] = file_hash
            
        except requests.exceptions.RequestException as e:
            # Apenas registra o aviso e continua
            print(f"[AVISO GH] Falha ao buscar '{display_name}' no GitHub: {e}")
        
    return github_hashes

def generate_hash_of_file(filepath: str) -> Optional[str]:
    """
    Calcula o hash SHA-256 de um arquivo em disco, forçando a normalização
    das quebras de linha para LF (Unix) para garantir compatibilidade com o GitHub.
    Tenta decodificar primeiro em UTF-8 e, em caso de falha, em CP1252.
    """
    
    # Lista de codificações a serem tentadas, na ordem de preferência
    encodings_to_try = ["utf-8", "cp1252"]
    content = None
    
    for encoding in encodings_to_try:
        try:
            # 1. Abre em modo texto ('r') usando a codificação atual e newline=None
            with open(filepath, "r", encoding=encoding, newline=None) as f:
                # 2. Lê o conteúdo. Python normaliza as quebras de linha para \n (LF).
                content = f.read()
            
            # Se a leitura for bem-sucedida, saímos do loop
            break
            
        except UnicodeDecodeError:
            # Se falhar a decodificação (e.g., UTF-8 falhando com 'ç'), 
            # o loop continua para a próxima codificação.
            continue 
        except FileNotFoundError:
            # Se o arquivo não existir, retorna None e para imediatamente
            return None
        except Exception as e:
            # Outros erros (permissão, I/O)
            print(f"[ERRO HASH] Falha ao calcular hash de {filepath} (Erro fatal de I/O): {e}")
            return None
    
    # ----------------------------------------------------------------------
    
    # Verifica se conseguimos ler o conteúdo após tentar todas as codificações
    if content is None:
        print(f"[ERRO HASH] Falha ao calcular hash de {filepath}: Não foi possível decodificar o arquivo com UTF-8 ou CP1252.")
        return None

    # 3. Codifica de volta para bytes **UTF-8** para o cálculo do hash
    # O hash DEVE ser sempre calculado sobre bytes UTF-8 normalizados para garantir
    # a consistência Local vs. GitHub, independentemente da codificação original.
    try:
        content_bytes = content.encode("utf-8")
        
        # 4. Calcula o hash dos bytes normalizados
        return hashlib.sha256(content_bytes).hexdigest()
        
    except Exception as e:
        # Se falhar na codificação final para UTF-8 (improvável, mas possível)
        print(f"[ERRO HASH] Falha ao codificar conteúdo para SHA-256: {e}")
        return None

def generate_audit_hashes(is_production: bool) -> None:
    """
    Gera hashes SHA-256 dos arquivos críticos, imprime na tela e salva em CSV para auditoria.
    Inclui uma comparação explícita com os hashes do GitHub.
    Em caso de divergência, solicita confirmação para interromper a execução.
    """
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    DYNAMIC_AUDIT_FILEPATH = os.path.join('data', f"audit_hashes_{now_str}.csv")

    files_to_hash_local = [
        os.path.abspath(__file__), 
        ENV_TOML_FILEPATH, 
        CREDENTIALS_PATH, 
        ELEITORES_FILEPATH, 
        GS_FORMULARIO_FILEPATH, 
        GS_PLANILHA_FILEPATH, 
        TEMPLATE_FILEPATH, 
    ]
    
    audit_data = []
    local_hashes_map = {} # Mapa para consulta rápida

    # Calcula Hashes Locais e Prepara Dados
    for filepath in files_to_hash_local:
        file_hash = generate_hash_of_file(filepath)
        
        if file_hash:
            # Determina o nome de exibição padronizado
            if filepath == os.path.abspath(__file__):
                display_name = 'src/eleicoes.py'
            elif filepath == CREDENTIALS_PATH:
                display_name = 'config/' + os.path.basename(CREDENTIALS_PATH)
            else:
                display_name = filepath.replace(os.sep, '/')
                
            entry = {
                "timestamp": datetime.now().strftime(DATE_FORMAT),
                "arquivo": display_name,
                "hash_sha256": file_hash
            }
            audit_data.append(entry)
            local_hashes_map[display_name] = file_hash
        else:
            print(f"[AVISO] Arquivo não encontrado para auditoria: {filepath.replace(os.sep, '/')} -> Hash não gerado.")

    ### LOGGING: 1. Registra todos os hashes locais calculados
    local_log_message = "AUDITORIA: HASHES LOCAIS CALCULADOS PARA EXECUÇÃO:\n" + "\n".join(
        [f"  [L] {entry['arquivo'].ljust(35)}: {entry['hash_sha256']}" for entry in audit_data]
    )
    # Assumindo email/user_id como SYSTEM_LOG_EMAIL/SYSTEM_LOG_USER
    log_event(
        level='INFO', 
        email="", 
        user_id="", 
        message=local_log_message, 
        is_production=is_production
    )

    # Busca Hashes do GitHub para Comparação
    github_hashes_map = fetch_github_hashes(GITHUB_FILES_TO_COMPARE)

    ### LOGGING: 2. Registra a comparação Local vs. GitHub
    comparison_log_message = "AUDITORIA: RESULTADO DA COMPARAÇÃO LOCAL vs. GITHUB\n"
    all_match = True # Variável local para controle da lógica e da impressão final
    all_match_for_log = True # Variável para o log, separada para clareza
    
    for display_name in GITHUB_FILES_TO_COMPARE:
        local_hash = local_hashes_map.get(display_name, "N/A - Local")
        github_hash = github_hashes_map.get(display_name, "N/A - GitHub")
        match_status = "MATCH" if local_hash == github_hash else "DIVERGÊNCIA"
        comparison_log_message += (
            f"  [{match_status.ljust(11)}] {display_name.ljust(30)}: "
            f"LOCAL={local_hash} | GITHUB={github_hash}\n"
        )
        if match_status == "DIVERGÊNCIA":
            all_match_for_log = False
            all_match = False
    
    # Adiciona o status geral ao log
    status_geral = 'MATCH' if all_match_for_log else 'DIVERGÊNCIA' # Removemos "Execução Interrompida" daqui
    comparison_log_message += f"\n  STATUS GERAL: {status_geral}"
    
    log_level = 'WARNING' if not all_match_for_log else 'INFO' # Nível 'WARNING' se houver divergência
    log_event(
        level=log_level, 
        email="", 
        user_id="", 
        message=comparison_log_message, 
        is_production=is_production
    )
    
    # Salva Hashes Locais em CSV (Lógica Inalterada)
    try:
        with open(DYNAMIC_AUDIT_FILEPATH, mode='w', newline='', encoding=ENCODING) as f: 
            writer = csv.writer(f, delimiter=DELIMITER)
            writer.writerow(['timestamp', 'arquivo', 'hash_sha256'])
            for entry in audit_data:
                writer.writerow([entry['timestamp'], entry['arquivo'], entry['hash_sha256']])
                
    except Exception as e:
        print(f"[ERRO] Não foi possível salvar arquivo de auditoria '{DYNAMIC_AUDIT_FILEPATH}': {e}")
        sys.exit(1)

    # Calcula o Meta Hash do Arquivo de Auditoria (Lógica Inalterada)
    meta_hash = generate_hash_of_file(DYNAMIC_AUDIT_FILEPATH)
    meta_entry = None
    if meta_hash:
        meta_file_name = DYNAMIC_AUDIT_FILEPATH.replace(os.sep, '/')
        meta_entry = {
            "timestamp": datetime.now().strftime(DATE_FORMAT),
            "arquivo": meta_file_name,
            "hash_sha256": meta_hash
        }
        
        ### LOGGING: 3. Registra o Meta Hash
        meta_log_message = f"AUDITORIA: META HASH GERADO: {meta_file_name} -> {meta_hash}"
        log_event(
            level='INFO', 
            email="", 
            user_id="", 
            message=meta_log_message, 
            is_production=is_production
        )

    # Imprime o Relatório Final (Lógica Inalterada, apenas a variável all_match é usada no status_msg)

    # Definições de Largura (Otimizadas)
    COL_FILE = 23
    COL_COMP = 13
    COL_FONTE = 6
    COL_HASH = 64
    TOTAL_WIDTH = COL_FILE + 3 + COL_COMP + 3 + COL_FONTE + 3 + COL_HASH + 1
    
    # Título Principal
    print("\n" + "="*116)
    print("🔐 Relatório de Integridade Criptográfica (SHA-256) 🔐".center(116))
    print("-" * 116)
    
    # A. Verificação dos Códigos-Fonte (Local vs. GitHub)
    print("\n>>> 📋 A. VERIFICAÇÃO DOS CÓDIGOS-FONTE (Local vs. GitHub) <<<")
    print("=" * TOTAL_WIDTH)
    header = f"{'Arquivo'.ljust(COL_FILE)} | {'Comparação'.ljust(COL_COMP)}  | {'Fonte'.ljust(COL_FONTE)} | {'Hash SHA-256'}"
    print(header)
    print("=" * TOTAL_WIDTH)
    
    # A variável all_match já foi calculada acima.
    
    for display_name in GITHUB_FILES_TO_COMPARE:
        local_hash = local_hashes_map.get(display_name, "N/A - Local")
        github_hash = github_hashes_map.get(display_name, "N/A - GitHub")
        
        match = (local_hash == github_hash) and (local_hash != "N/A - Local")

        if match:
            status = "✅ MATCH     "
        else:
            status = "❌ DIVERGÊNCIA"
        
        line1 = f"{display_name.ljust(COL_FILE)} | {status.ljust(COL_COMP)} | {'Local'.ljust(COL_FONTE)} | {local_hash}"
        
        empty_col1 = " " * COL_FILE + " | "
        empty_col2_with_separator = " " * COL_COMP + "  | "
        line2 = f"{empty_col1}{empty_col2_with_separator}{'GitHub'.ljust(COL_FONTE)} | {github_hash}"
        
        print(line1)
        print(line2)
        print("-" * TOTAL_WIDTH)

    # Rodapé da Seção A
    status_msg = '✅ Todos os arquivos de código-fonte públicos correspondem.' if all_match else '❌ ALERTA: HÁ DIVERGÊNCIAS NOS CÓDIGOS-FONTE. Necessária intervenção.'
    print(f"STATUS GERAL DA COMPARAÇÃO: {status_msg}".center(TOTAL_WIDTH))
    print("=" * TOTAL_WIDTH)
    
    # B. Arquivos de Dados Sensíveis e Configuração (Apenas Local)
    LOCAL_ONLY_WIDTH = COL_FILE + 3 + COL_HASH
    print("\n>>> 💾 B. ARQUIVOS DE DADOS SENSÍVEIS E CONFIGURAÇÃO (Apenas Local) <<<")
    print("-" * LOCAL_ONLY_WIDTH) 
    
    local_only_files = [
        entry for entry in audit_data 
        if entry['arquivo'] not in GITHUB_FILES_TO_COMPARE
    ]

    for entry in local_only_files:
        print(f"{entry['arquivo'].ljust(COL_FILE)} | {entry['hash_sha256']}") 
    print("-" * LOCAL_ONLY_WIDTH, "\n")

    # C. Meta Hash
    print(f">>> 🔑 C. META HASH - Arquivo com os hashes para auditoria dos arquivos executados <<<")

    if meta_entry:
        print("-" * 104)
        print(f"{meta_entry['arquivo'].ljust(23)} | {meta_entry['hash_sha256']}")
        
    print("=" * 104)

    # -----------------------------------------------------------
    # Controle de Interrupção interativo (Substitui o sys.exit(1))
    # -----------------------------------------------------------
    if not all_match:
        
        print("\n" + "!" * 80)
        print("!!! ALERTA DE SEGURANÇA: DIVERGÊNCIA DE HASH ENCONTRADA NO CÓDIGO FONTE !!!".center(80))
        print("!!! O código executado (Local) não corresponde ao repositório (GitHub). !!!".center(80))
        print("!" * 80)
        
        # Loga o alerta de divergência antes de pedir a confirmação
        log_event(
            level='ALERTA', 
            email="", 
            user_id="", 
            message="ALERTA DE DIVERGÊNCIA DE CÓDIGO FONTE. Necessária intervenção manual.", 
            is_production=is_production
        )
        
        # Pergunta ao operador o que fazer, exigindo a palavra completa
        confirmation = input("Deseja interromper a execução? (digite 'INTERROMPER' para sair, ou 'CONTINUAR' para prosseguir): ")
        
        if confirmation.upper() != 'CONTINUAR':
            print("\n[INTERRUPÇÃO FORÇADA] Execução interrompida pelo operador devido à divergência de código-fonte.")
            log_event(
                level='CRITICAL', 
                email="", 
                user_id="", 
                message="EXECUÇÃO INTERROMPIDA PELO OPERADOR: Divergência de código confirmada e interrompida.", 
                is_production=is_production
            )
            sys.exit(1)
        
        # Se digitou 'CONTINUAR' ou qualquer outra coisa
        print("\n[CONTINUANDO] Execução prosseguindo, apesar da divergência de código-fonte (Risco aceito pelo operador).")
        log_event(
            level='WARNING', 
            email="", 
            user_id="", 
            message="EXECUÇÃO CONTINUADA PELO OPERADOR: Divergência de código ignorada para fins de teste.", 
            is_production=is_production
        )
    
    return

def is_valid_email(email: str) -> bool:
    """Valida formato básico de e-mail para evitar rejeição SMTP."""
    email = email.strip()
    if not email: return False
    # Evita erro comum de ponto final
    if email.endswith('.'): return False
    # Regex padrão simples
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None


# --- 5. PERSISTÊNCIA LOCAL (CSV) ---

def load_eleitores() -> List[Eleitor]:
    """
    Carrega a lista de eleitores do CSV e valida o formato dos e-mails.
    O script será ABORTADO imediatamente se for encontrado qualquer e-mail inválido.
    """
    if not os.path.exists(ELEITORES_FILEPATH): 
        return []
    
    eleitores_validos = []
    erros_encontrados = [] # Lista para coletar todos os erros
    
    try:
        with open(ELEITORES_FILEPATH, mode='r', encoding=ENCODING) as f:
            reader = csv.reader(f, delimiter=DELIMITER)
            next(reader, None) # Pula o cabeçalho
            
            for line_num, r in enumerate(reader, start=2):
                if len(r) < 2: continue # Pula linhas incompletas
                
                nome = r[0].strip()
                email = r[1].strip()
                
                if is_valid_email(email):
                    eleitores_validos.append(Eleitor(nome=nome, email=email))
                else:
                    # Coleta o erro em vez de apenas alertar
                    erros_encontrados.append(f"Linha {line_num}: '{email}' (Eleitor: {nome})")
                    
    except Exception as e:
        print(f"[ERRO] Falha ao ler eleitores: {e}")
        # Aborta em caso de erro de I/O
        raise SystemExit(1)
    
    # 🚨 PONTO DE ABORTO: Se encontrou erros, interrompe a execução
    if erros_encontrados:
        print("\n" + "="*80)
        print("🚨 ERRO CRÍTICO: E-MAILS INVÁLIDOS ENCONTRADOS NO CSV! 🚨")
        print("Corrija os e-mails listados abaixo antes de continuar.")
        print("-" * 80)
        for erro in erros_encontrados:
            print(f"  {erro}")
        print("="*80)
        # O valor 1 é uma convenção para indicar que o script terminou com falha
        raise SystemExit(1) 
        
    return eleitores_validos

def load_enviados() -> List[RegistroEnvio]:
    """Carrega registros de envio (chaves) do CSV local."""
    if not os.path.exists(ENVIADOS_FILEPATH): return []
    registros = []
    try:
        with open(ENVIADOS_FILEPATH, mode='r', encoding=ENCODING) as f:
            reader = csv.reader(f, delimiter=DELIMITER)
            next(reader, None) # Pula cabeçalho
            for row in reader:
                if len(row) < 8: continue
                registros.append(RegistroEnvio(
                    timestamp=row[0],
                    email=row[1],
                    user_id=row[2],
                    pub_key=row[3],
                    generation=int(row[4]),
                    is_active=(row[5].lower() == 'true'),
                    is_delivered=(row[6].lower() == 'true'),
                    is_production=(row[7].lower() == 'true')
                ))
    except Exception as e:
        print(f"[ERRO] Falha ao ler enviados: {e}")
        return []
    return registros

def log_event(level: str, email: str, user_id: str, message: str, is_production: bool) -> None:
    """Registra evento no log."""
    
    timestamp_str = datetime.now().strftime(DATE_FORMAT) 
    
    entry = [
        timestamp_str, # Formato: DD/MM/AAAA HH:MM:SS
        str(is_production),
        level,
        email,
        user_id,
        message.replace(DELIMITER, ' | ') # Evita quebra de coluna
    ]
    file_exists = os.path.exists(LOG_FILEPATH)
    try:
        with open(LOG_FILEPATH, mode='a', newline='', encoding=ENCODING) as f:
            writer = csv.writer(f, delimiter=DELIMITER)
            if not file_exists:
                writer.writerow(LogEntry.__annotations__.keys())
            writer.writerow(entry)
    except Exception as e:
        print(f"[ERRO FATAL] Falha INESPERADA ao escrever no log: {e}")
        sys.exit(1)

def save_enviados_atomically(registros: List[RegistroEnvio]) -> None:
    """
    Salva a lista completa de registros de forma atômica.
    
    Observação: O bloco try/except foi removido. Qualquer falha 
    (ex: Acesso Negado) é lançada diretamente para o caller, 
    onde o Fail-Fast obrigatório está implementado.
    """
    temp_filepath = ENVIADOS_FILEPATH + '.tmp'
    
    # 1. Escreve no arquivo temporário. Se falhar, lança a exceção.
    with open(temp_filepath, mode='w', newline='', encoding=ENCODING) as f:
        writer = csv.writer(f, delimiter=DELIMITER)
        writer.writerow(RegistroEnvio.__annotations__.keys()) # Escreve cabeçalho
        for reg in registros:
            # Usando asdict(reg) é uma suposição, mantenha o que for correto para você
            writer.writerow(list(asdict(reg).values())) 
    
    # 2. Substituição atômica. Se falhar, lança a exceção (ex: WinError 5).
    os.replace(temp_filepath, ENVIADOS_FILEPATH)
    
    # Se a função chegar aqui, a operação foi bem-sucedida.


# --- 6. GERAÇÃO DE CHAVES E ENCRIPTAÇÃO ---

def generate_key_pair() -> KeyPair:
    """Gera um user_id e um par de chaves (priv_key, pub_key)."""
    
    # 1. Geração do ID numérico 6 dígitos (100000-999999)
    user_id = str(secrets.randbelow(900000) + 100000)

    # 2. Carregamento da Master Key
    master_key = ENV.get('MASTER_KEY')
    if not master_key: 
        raise RuntimeError("MASTER_KEY ausente na raiz do env.toml")

    # 3. Chave Privada: 12 letras maiúsculas
    priv_key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(12)) 
    
    # 4. Chave Pública: HMAC-SHA256
    pub_key = hmac.new(master_key.encode(), priv_key.encode(), 'sha256').hexdigest()
    
    return KeyPair(user_id=user_id, priv_key=priv_key, pub_key=pub_key)


# --- 7. COMUNICAÇÃO (SMTP) ---

def load_template_html() -> str:
    """Carrega o conteúdo do template HTML para e-mail."""
    # Usando a constante ENCODING do script ('utf-8-sig')
    if os.path.exists(TEMPLATE_FILEPATH):
        with open(TEMPLATE_FILEPATH, 'r', encoding=ENCODING) as f: 
            return f.read()
    
    # Template de fallback seguro (para o caso de o arquivo não existir)
    return (
        "<html><body>"
        "<p>Olá {nome},</p>"
        "<p>ID de Validação: {user_id}</p>"
        "<p>Chave Privada: {chave_privada}</p>"
        "</body></html>"
    )

def send_email(eleitor: Eleitor, keys: KeyPair, is_production: bool) -> bool:
    """
    Constrói, envia (ou simula) o e-mail e registra o log, 
    mantendo a formatação detalhada de simulação no terminal.
    """
    # 1. Preparação
    ano = datetime.now().year
    html_tmpl = load_template_html() # Usa a função auxiliar
    
    template_data = {
        'nome': eleitor.nome,
        'user_id': keys.user_id,
        'priv_key': keys.priv_key,      
        'pub_key': keys.pub_key, 
        'link_votacao': BASE_FORM_URL, 
        'ano': ano, 
        'from_name': FROM_NAME,
        'data_inicio_votacao': DATA_INICIO_VOTACAO,
        'data_fim_votacao': DATA_FIM_VOTACAO
    }

    # Preenche o template com TODAS as variáveis necessárias
    try:
        html_content = html_tmpl.format(**template_data)
    except KeyError as e:
        print(f"[ERRO FATAL] Variável faltando no template HTML: {e}")
        log_event(
            level='ERRO FATAL', 
            email=eleitor.email, 
            user_id=keys.user_id, 
            message=f"KeyError no template: {e}", 
            is_production=is_production
        )
        return False
    except Exception as e:
         print(f"[ERRO FATAL] Erro desconhecido na formatação do template: {e}")
         log_event(
            level='ERRO FATAL',
            email=eleitor.email,
            user_id=keys.user_id,
            message=f"Erro na formatação do template: {e}",
            is_production=is_production
        )
         return False
    
    # Conteúdo de texto simples (Formato detalhado desejado pelo usuário)
    text_content = (
        f"Olá {eleitor.nome},\n\n"
        f"Seguem seus dados para a Eleição AGESP {ano}:\n\n"
        f"Período        : {DATA_INICIO_VOTACAO} a {DATA_FIM_VOTACAO}\n"
        f"ID de Validação: {keys.user_id}\n"
        f"Chave Privada  : {keys.priv_key}\n"
        f"Chave Pública  : {keys.pub_key}\n"
        f"Link de Votação: {BASE_FORM_URL}\n\n"
        f"Atenciosamente,\n{FROM_NAME}"
    )

    # 2. Construção da Mensagem EmailMessage
    msg = EmailMessage()
    msg["Subject"] = SUBJECT 
    msg["From"] = formataddr((FROM_NAME, SMTP_USER))
    msg["To"] = eleitor.email
    msg.set_content(text_content) # Conteúdo de texto simples
    msg.add_alternative(html_content, subtype="html") # Conteúdo HTML
    
    # 3. Envio / Simulação
    success = False
    log_msg = ""
    log_level = 'INFO'

    if not is_production:
        # MODO DE TESTE: Formato de simulação detalhado
        print("\n" + "="*60)
        print(f"🧪 [TESTE] E-MAIL SIMULADO PARA: {eleitor.email}")
        print("-" * 60)
        print(f"ASSUNTO: {SUBJECT}")
        print("\nCONTEÚDO (Visualização):")
        # Imprime o conteúdo de texto formatado
        print("    " + "\n    ".join(text_content.split('\n'))) 
        print("="*60 + "\n")
        
        success = True
        log_msg = "Simulação de envio bem-sucedida."
        log_level = 'INFO'

    else:
        # MODO DE PRODUÇÃO: Lógica de envio robusta com tratamento de exceções        
        smtp_password = ENV.get('SMTP_PASSWORD')
        if not smtp_password:
            log_msg = "SMTP_PASSWORD ausente na raiz do env.toml. Cancelando envio."
            log_level = 'ERRO FATAL'
        else:
            try:
                print(f"[INFO] Tentando enviar e-mail para: {eleitor.email}...")
                ctx = ssl.create_default_context()
                
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
                    server.login(SMTP_USER, smtp_password)
                    server.send_message(msg)
                    
                    success = True
                    log_msg = "E-mail enviado com sucesso (SMTP)."

                    # ----------------------------------------------------
                    # >>> PONTO DE INTERRUPÇÃO PARA TESTE (PRODUÇÃO) <<<
                    # ATENÇÃO: COMENTE ou REMOVA esta linha após o teste!
                    # print("[TESTE DE FALHA] PRODUÇÃO: Interrompendo após o envio SMTP.")
                    # sys.exit(1)
                    # ----------------------------------------------------
            
            # Tratamento de Erros Detalhado (Mantido robusto)
            except smtplib.SMTPAuthenticationError:
                log_msg = "Falha de autenticação SMTP. Senha ou usuário incorretos."
                log_level = 'ERRO FATAL'
            except smtplib.SMTPConnectError as e:
                log_msg = f"Falha de conexão SMTP. Servidor ou porta incorretos: {e}"
                log_level = 'ERRO CRÍTICO'
            except smtplib.SMTPException as e:
                log_msg = f"Falha geral no envio SMTP: {e}"
                log_level = 'ERRO CRÍTICO'
            except Exception as e:
                log_msg = f"Erro desconhecido durante o envio: {e}"
                log_level = 'ERRO CRÍTICO'

    # Registro de Log e feedback no terminal
    log_event(
        level=log_level,
        email=eleitor.email,
        user_id=keys.user_id,
        message=log_msg,
        is_production=is_production
    )
    if success and log_level == 'INFO': 
        print(f"[SUCESSO] {log_msg}")
    elif not success and log_level != 'INFO':
        print(f"[{log_level}] {log_msg}") # Imprime logs de erro no terminal
        
    return success


# --- 8. FLUXO PRINCIPAL ---

import sys 
import time
from datetime import datetime

# Presumindo que estas classes/funções/constantes globais existam e estejam importadas no topo do seu arquivo:
# Eleitor, KeyPair, RegistroEnvio, GoogleSheetsService, load_enviados, generate_key_pair, 
# save_enviados_atomically, send_email, log_event, DATE_FORMAT, SHEET_NAME_PUB_KEY, 
# SYSTEM_LOG_USER, SYSTEM_LOG_EMAIL, ...

def process_eleitor(eleitor: Eleitor, sheet_service: GoogleSheetsService, force_resend: bool, production: bool) -> None:
    """
    Processa um único eleitor com persistência segura (Write-Ahead Logging).
    
    1. Gera chaves e salva em disco como PENDENTE (is_delivered=False). 
       -> FAIL-FAST OBRIGATÓRIO AQUI.
    2. Envia o e-mail (Ação de Risco).
    3. Se sucesso, atualiza o Google Sheets.
    4. Atualiza disco para ENTREGUE (is_delivered=True) e ATIVO (is_active=True).
    """
    
    # 0. Preparação de Dados
    registros_antigos = load_enviados()
    registro_atual = next((r for r in registros_antigos if r.email == eleitor.email), None)
    
    # 1. Checagem de Reenvio
    if registro_atual and registro_atual.is_delivered and not force_resend:
        print(f"[PULAR] Eleitor {eleitor.nome} ({eleitor.email}) já processado com sucesso (Geração {registro_atual.generation}).")
        return

    # 2. Geração de Chaves
    keys = generate_key_pair()
    new_generation = (registro_atual.generation + 1) if registro_atual else 1
    timestamp_now = datetime.now().strftime(DATE_FORMAT)

    # 3. PERSISTÊNCIA ETAPA 1: REGISTRO "PENDENTE" (FAIL-FAST)
    # Criamos o registro marcando como NÃO ENTREGUE e NÃO ATIVO.
    novo_registro = RegistroEnvio(
        timestamp=timestamp_now,
        email=eleitor.email,
        user_id=keys.user_id,
        pub_key=keys.pub_key,
        generation=new_generation,
        is_active=False,      # Ainda não ativada no Sheets
        is_delivered=False,   # Ainda não enviado
        is_production=production
    )

    # Remove registro antigo da memória e adiciona o novo (Pendente)
    lista_atualizada = [r for r in registros_antigos if r.email != eleitor.email]
    lista_atualizada.append(novo_registro)
    
    # === BLOCO FAIL-FAST ===
    try:
        # Tenta salvar o estado PENDENTE no disco
        save_enviados_atomically(lista_atualizada) 
        
    except Exception as e:
        # ERRO FATAL: Falha na persistência. Devemos interromper imediatamente.
        error_msg = f'ERRO FATAL: Falha ao persistir registro PENDENTE em disco (Etapa 1). O script não pode prosseguir sem registro de auditoria. Erro: {e}'
        
        print(f"\n[ERRO CRÍTICO DE PERSISTÊNCIA] {error_msg}")
        log_event(
            level='ERRO FATAL', 
            email=eleitor.email, 
            user_id=keys.user_id, 
            message=error_msg, 
            is_production=production
        )
        
        # Interrupção GARANTIDA
        print("\n[INTERRUPÇÃO FORÇADA] Script encerrado devido a falha de persistência de registro PENDENTE.")
        sys.exit(1) 
    # =======================

    # Log da tentativa (Só executa se o salvamento PENDENTE foi bem-sucedido)
    log_event(
        level='INFO', 
        email=eleitor.email, 
        user_id=keys.user_id, 
        message=f'Geradas chaves (Gen {new_generation}). Registro PENDENTE salvo. Tentando envio...', 
        is_production=production
    )

    # 4. AÇÃO DE RISCO: Envio de E-mail
    is_delivered = send_email(eleitor, keys, production)

    # 5. TRATAMENTO DO RESULTADO (Se falhou o envio, apenas registra o estado e sai)
    if not is_delivered:
        print(f"[AVISO] Falha no envio para {eleitor.email}. Registro PENDENTE mantido para reprocessamento.")
        # O registro PENDENTE já está no CSV (is_delivered=False). Nada mais precisa ser feito aqui.
        return

    # SE CHEGAMOS AQUI, O E-MAIL FOI ENVIADO (ou simulado) COM SUCESSO.

    # 6. ATUALIZAÇÃO GOOGLE SHEETS (Se falhar aqui, o estado é de alto risco)
    try:
        # a. Invalida anteriores no Sheets
        if registro_atual:
             if sheet_service.invalidate_old_key(registro_atual.user_id):
                time.sleep(3.0) 

        # b. Insere nova chave no Sheets
        sheet_service.append_row(SHEET_NAME_PUB_KEY, [
            keys.user_id,
            keys.pub_key,
            True,       # ATIVA
            production,
            timestamp_now,
            '' 
        ])
        time.sleep(2.0)

        log_event(
            level='INFO', 
            email=eleitor.email, 
            user_id=keys.user_id, 
            message='Google Sheets atualizado com nova chave ativa.', 
            is_production=production
        )
        
        # Estado de sucesso total
        novo_registro.is_active = True 
        
    except Exception as e:
        # Se falhar no Sheets, o usuário recebeu o email (is_delivered=True) mas a chave não foi ativada.
        # Isto é um ERRO CRÍTICO que exige atenção manual.
        log_event(
            level='ERRO CRÍTICO',
            email=eleitor.email,
            user_id=keys.user_id,
            message=f'E-mail enviado, mas falha ao salvar no Sheets (chave pode estar INATIVA). Erro: {e}',
            is_production=production
        )
        print(f"[ERRO CRÍTICO] E-mail enviado para {eleitor.email}, mas falha ao salvar no Sheets: {e}")
        
        # Atualizamos o CSV para refletir que o e-mail foi enviado (mas a chave NÃO está ativa)
        novo_registro.is_active = False 

    # 7. PERSISTÊNCIA ETAPA 2: SUCESSO TOTAL (COMMIT)
    # Atualiza o objeto em memória para refletir que o e-mail foi entregue (independentemente do Sheets)
    novo_registro.is_delivered = True
    
    # Salvamos novamente no disco para confirmar o estado final (Entregue e/ou Ativo)
    try:
        save_enviados_atomically(lista_atualizada)
        print(f"[SUCESSO] Processamento de {eleitor.nome} concluído. Geração: {new_generation}")
    except Exception as e:
        # Falhar no COMMIT final é menos grave, pois o e-mail já foi enviado.
        # O estado final ainda será PENDENTE, mas com log de envio.
        # O script deve pelo menos logar o erro, mas a interrupção não é obrigatória.
        error_msg = f'ERRO: Falha ao persistir registro FINAL (COMMIT). Estado pode ser inconsistente no CSV. Erro: {e}'
        print(f"[ERRO] {error_msg}")
        log_event(
            level='ERROR',
            email=eleitor.email,
            user_id=keys.user_id,
            message=error_msg,
            is_production=production
        )

# NOTA IMPORTANTE SOBRE save_enviados_atomically:
# Garanta que a sua função `save_enviados_atomically` **NÃO** tenha um `try...except` que capture e ignore a exceção
# `[WinError 5] Acesso negado`, mas sim **re-lance** essa exceção (usando `raise e`) para que o `process_eleitor`
# possa capturá-la no bloco de Fail-Fast da Etapa 3.

def main():
    # 0. Configuração de Argumentos (Deve ser a primeira coisa a rodar)
    parser = argparse.ArgumentParser(description="Script de gerenciamento de eleitores e envio de credenciais para votação eletrônica.")
    parser.add_argument('destinatario', nargs='?', default='TODOS', help="eleitor@email.com.br (ou 'TODOS') para processamento.")
    parser.add_argument('--production', action='store_true', help="Ativa o modo de produção (envios REAIS de e-mail).")
    parser.add_argument('--resend', action='store_true', help="Força o reenvio de credenciais (gera nova chave) para TODOS. USE COM CAUTELA!")
    parser.add_argument('--skip-audit', action='store_true', help="Pula a auditoria de hashes com o GitHub para testes locais. NÃO USE EM PRODUÇÃO!")
    args = parser.parse_args()

    # --- INÍCIO DO REDIRECIONAMENTO DE SAÍDA ---
    tee_output = None
    try:
        # 1. Configura o Tee logo após o parsing
        tee_output = Tee(TERMINAL_LOG_FILEPATH)
        sys.stdout = tee_output 

        # 2. Registro do Tempo de Início (com separador robusto)
        start_time = datetime.now()
        
        # Prints que vão para o terminal E para o log
        print("\n" + "#"*58)
        print(f"[{start_time.strftime(DATE_FORMAT)}] >>> INÍCIO da execução do script <<<")
        print("#"*58)
        
        # Log event inicial
        log_event(
            level="INFO", 
            email="", 
            user_id="SYSTEM", 
            message=f"INÍCIO da execução do script. Modo Produção: {args.production}", 
            is_production=args.production
        )

        # 3. Executa Auditoria de Arquivos
        if args.skip_audit:
            print("\n[AVISO] Auditoria de Hashes (Local vs. GitHub) ignorada (--skip-audit).")
        else:
            # A função generate_audit_hashes agora lida com a interrupção/confirmação
            generate_audit_hashes(args.production)

        # 4. Alertas de Segurança e Confirmação
        if args.production:
            print("\n🚨 MODO DE PRODUÇÃO ATIVADO 🚨")
            print("Envios REAIS de e-mail. Cancelar? (Aperte Ctrl+C em 5 segundos)")
            time.sleep(5)
        else:
            print("\n🧪 MODO DE TESTE (Simulação de E-mail) 🧪")
            print("Planilha será atualizada, e-mails NÃO serão enviados (apenas simulados).")

        if args.resend:
            print("\n⚠️ ALERTA: MODO REENVIO FORÇADO (--resend) ATIVADO! ⚠️")
            print("Todas as chaves serão REGERADAS. As credenciais antigas serão INVALIDADAS.")
            
            # Confirmação explícita no terminal (Segurança máxima)
            confirmation = input("Tem certeza que deseja continuar? (digite 'SIM' para prosseguir): ")
            if confirmation.upper() != 'SIM':
                print("\n[CANCELADO] Execução interrompida pelo usuário. Nenhuma chave foi alterada.")
                return
            
        print("\n" + "="*50 + "\n")
        
        # O bloco try/except/finally original do usuário (Lógica Principal)
        try:
            sheet_service = GoogleSheetsService(SPREADSHEET_ID)
            eleitores = load_eleitores()
            
            if not eleitores:
                print("[AVISO] Nenhum eleitor encontrado.")
                return

            targets = []
            if args.destinatario.upper() == 'TODOS':
                targets = eleitores
            else:
                found = next((e for e in eleitores if e.email == args.destinatario), None)
                if found:
                    targets = [found]
                    args.resend = True  
                else:
                    print(f"[ERRO] Eleitor {args.destinatario} não encontrado na lista (ou o e-mail é inválido).")
                    return

            # 4. Lógica de embaralhamento criptograficamente seguro (não-reprodutível)
            if len(targets) > 1:
                secrets.SystemRandom().shuffle(targets)
                
                print(f"[INFO] Ordem de processamento embaralhada de forma CRIPTOGRAFICAMENTE SEGURA para {len(targets)} eleitor(es).")
                print("[INFO] A ordem é irreprodutível e garante a máxima proteção contra inferência de ID/Chave.")

            print(f"[INFO] Iniciando processamento de {len(targets)} eleitor(es)...")
            
            for eleitor in targets:
                process_eleitor(eleitor, sheet_service, args.resend, args.production)

            # 5. Atualização da flag de apuração (run once)
            if len(targets) > 0:
                timestamp = datetime.now().strftime(DATE_FORMAT)
                range_a1_notation = f"{APPS_SCRIPT_FLAG_CELL}"
                sheet_service.update_cell(range_a1_notation, timestamp)
                
                log_event(
                    level="INFO", 
                    email="", 
                    user_id="SYSTEM", 
                    message=f"Gatilho Sheets API acionado para {range_a1_notation} via triggerApuracao. (Disparo ÚNICO)", 
                    is_production=args.production
                )
                print(f"[API SCRIPT] Gatilho Sheets API acionado para {range_a1_notation} via triggerApuracao. (Disparo ÚNICO)")

        except KeyboardInterrupt:
            print("\n[INTERRUPÇÃO] Processamento cancelado pelo usuário.")
            log_event(
                level="WARNING", 
                email="", 
                user_id="SYSTEM", 
                message="Processamento interrompido pelo usuário (Ctrl+C).", 
                is_production=args.production
            )
        
        except Exception as e:
            print(f"\n[ERRO FATAL] Ocorreu um erro não tratado: {e}")
            log_event(
                level="ERROR", 
                email="", 
                user_id="SYSTEM", 
                message=f"ERRO FATAL: {e}", 
                is_production=args.production
            )
        
        finally:
            # 6. Registro do Tempo de Fim e Duração (Calculado após a lógica principal)
            end_time = datetime.now()
            duration = end_time - start_time
            
            total_seconds = duration.total_seconds()
            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            seconds = total_seconds % 60
            
            duration_str = f"{hours:02d}:{minutes:02d}:{seconds:05.2f}"
            
            print("\n" + "="*50)
            print(f"[{end_time.strftime(DATE_FORMAT)}] 🏁 FIM da execução do script.")
            print(f"⏳ DURAÇÃO TOTAL: {duration_str}")
            print("="*50)

            # Log event final (já no log de auditoria)
            log_event(
                level="INFO", 
                email="", 
                user_id="SYSTEM", 
                message=f"FIM da execução do script. Duração: {duration_str}. Log completo em {os.path.basename(TERMINAL_LOG_FILEPATH)}",
                is_production=args.production
            )

    # --- FIM DO REDIRECIONAMENTO DE SAÍDA (Garante Cleanup) ---
    finally:
        if tee_output:
            # Escreve um separador claro no arquivo ANTES de restaurar o stdout
            tee_output.write(f"\n[{datetime.now().strftime(DATE_FORMAT)}] <<< FIM DA EXECUÇÃO >>>\n\n")

            # 1. Restaura o sys.stdout original
            sys.stdout = tee_output.stdout 
            
            # 2. Fecha o arquivo de log do terminal
            tee_output.close()

if __name__ == "__main__":
    main()