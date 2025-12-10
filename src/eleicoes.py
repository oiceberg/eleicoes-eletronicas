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
EMAIL_SEND_INTERVAL_SECONDS = 5.0
EMAIL_COL_NAME        = 'Endereço de e-mail'

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

import hashlib # Garanta que hashlib está importado

def generate_hash_of_file(filepath: str) -> Optional[str]:
    """
    Calcula o hash SHA-256 de um arquivo em disco, forçando a normalização
    das quebras de linha para LF (Unix) para garantir compatibilidade com o GitHub.
    """
    try:
        # 1. Abre em modo texto ('r') com newline=None para ler universalmente.
        #    Isso garante que \r\n (CRLF) e \r ou \n sejam tratados como quebras de linha.
        with open(filepath, "r", encoding="utf-8", newline=None) as f:
            # 2. Lê o conteúdo. O Python normaliza as linhas para o padrão \n (LF).
            content = f.read()
            
            # 3. Codifica de volta para bytes (UTF-8) para o cálculo do hash
            content_bytes = content.encode("utf-8")
            
            # 4. Calcula o hash dos bytes normalizados
            return hashlib.sha256(content_bytes).hexdigest()
            
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[ERRO HASH] Falha ao calcular hash de {filepath}: {e}")
        return None

def generate_audit_hashes(is_production: bool) -> None:
    """
    Gera hashes SHA-256 dos arquivos críticos, imprime na tela e salva em CSV para auditoria.
    Inclui uma comparação explícita com os hashes do GitHub.
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

    # LOGGING: 1. Registra todos os hashes locais calculados
    local_log_message = "AUDITORIA: HASHES LOCAIS CALCULADOS PARA EXECUÇÃO:\n" + "\n".join(
        [f"  [L] {entry['arquivo'].ljust(35)}: {entry['hash_sha256']}" for entry in audit_data]
    )
    log_event(
        level='INFO', 
        email="", 
        user_id="", 
        message=local_log_message, 
        is_production=is_production
    )

    # Busca Hashes do GitHub para Comparação
    github_hashes_map = fetch_github_hashes(GITHUB_FILES_TO_COMPARE)

    # LOGGING: 2. Registra a comparação Local vs. GitHub
    comparison_log_message = "AUDITORIA: RESULTADO DA COMPARAÇÃO LOCAL vs. GITHUB\n"
    all_match_for_log = True
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
    
    # Adiciona o status geral ao log
    status_geral = 'MATCH' if all_match_for_log else 'DIVERGÊNCIA (Execução Interrompida)'
    comparison_log_message += f"\n  STATUS GERAL: {status_geral}"
    
    log_level = 'ERRO FATAL' if not all_match_for_log else 'INFO'
    log_event(
        level=log_level, 
        email="", 
        user_id="", 
        message=comparison_log_message, 
        is_production=is_production
    )

    # Salva Hashes Locais em CSV
    try:
        with open(DYNAMIC_AUDIT_FILEPATH, mode='w', newline='', encoding=ENCODING) as f: 
            writer = csv.writer(f, delimiter=DELIMITER)
            writer.writerow(['timestamp', 'arquivo', 'hash_sha256'])
            for entry in audit_data:
                writer.writerow([entry['timestamp'], entry['arquivo'], entry['hash_sha256']])
                
    except Exception as e:
        print(f"[ERRO] Não foi possível salvar arquivo de auditoria '{DYNAMIC_AUDIT_FILEPATH}': {e}")
        sys.exit(1)

    # Calcula o Meta Hash do Arquivo de Auditoria
    meta_hash = generate_hash_of_file(DYNAMIC_AUDIT_FILEPATH)
    meta_entry = None
    if meta_hash:
        meta_file_name = DYNAMIC_AUDIT_FILEPATH.replace(os.sep, '/')
        meta_entry = {
            "timestamp": datetime.now().strftime(DATE_FORMAT),
            "arquivo": meta_file_name,
            "hash_sha256": meta_hash
        }

    # LOGGING: 3. Registra o Meta Hash
    meta_log_message = f"AUDITORIA: META HASH GERADO: {meta_file_name} -> {meta_hash}"
    log_event(
        level='INFO', 
        email="", 
        user_id="", 
        message=meta_log_message,
        is_production=is_production
    )

    # Imprime o Relatório Final

    # Definições de Largura (Otimizadas)
    COL_FILE = 23
    COL_COMP = 13
    COL_FONTE = 6
    COL_HASH = 64
    
    # Cálculo da Largura Total
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
    
    all_match = True
    
    for display_name in GITHUB_FILES_TO_COMPARE:
        local_hash = local_hashes_map.get(display_name, "N/A - Local")
        github_hash = github_hashes_map.get(display_name, "N/A - GitHub")
        
        match = (local_hash == github_hash) and (local_hash != "N/A - Local")

        # Normalização do status
        if match:
            status = "✅ MATCH   " 
        else:
            status = "❌ DIVERGÊNCIA"
        
        # LINHA 1: Local Hash (Completa)
        line1 = f"{display_name.ljust(COL_FILE)} | {status.ljust(COL_COMP)} | {'Local'.ljust(COL_FONTE)} | {local_hash}"
        
        # LINHA 2: GitHub Hash
        empty_col1 = " " * COL_FILE + " | "
        empty_col2_with_separator = " " * COL_COMP + "  | "
        line2 = f"{empty_col1}{empty_col2_with_separator}{'GitHub'.ljust(COL_FONTE)} | {github_hash}"
        
        print(line1)
        print(line2)
        print("-" * TOTAL_WIDTH)

        if not match:
            all_match = False
            
    # Rodapé da Seção A
    status_msg = '✅ Todos os arquivos de código-fonte públicos correspondem.' if all_match else '❌ ALERTA: HÁ DIVERGÊNCIAS NOS CÓDIGOS-FONTE. EXECUÇÃO INTERROMPIDA.'
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
        # Ajuste a impressão aqui para usar COL_FILE e o separador
        print(f"{entry['arquivo'].ljust(COL_FILE)} | {entry['hash_sha256']}") 
    print("-" * LOCAL_ONLY_WIDTH, "\n")

    # C. Meta Hash
    print(f">>> 🔑 C. META HASH - Arquivo com os hashes para auditoria dos arquivos executados <<<")

    if meta_entry:
        print("-" * 104)
        print(f"{meta_entry['arquivo'].ljust(23)} | {meta_entry['hash_sha256']}")
        
    print("=" * 104)

    # Interrompe por Segurança (Fail-Fast) se houver divergências entre os códigos-fonte
    if not all_match:
        sys.exit(1)

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
    IMPORTANTE: Não captura exceções. Se falhar (ex: arquivo aberto), 
    o erro subirá para parar o script imediatamente.
    """
    temp_filepath = ENVIADOS_FILEPATH + '.tmp'
    
    # 1. Tenta escrever no arquivo temporário
    with open(temp_filepath, mode='w', newline='', encoding=ENCODING) as f:
        writer = csv.writer(f, delimiter=DELIMITER)
        writer.writerow(RegistroEnvio.__annotations__.keys()) # Cabeçalho
        for reg in registros:
            writer.writerow(list(asdict(reg).values()))
    
    # 2. Substituição atômica
    # Se o arquivo 'enviados.csv' estiver aberto no Excel, esta linha
    # lançará um PermissionError. Como removemos o try/except, isso parará o script.
    os.replace(temp_filepath, ENVIADOS_FILEPATH)

def update_eleitor_email(old_email: str, new_email: str) -> bool:
    """
    Localiza o eleitor pelo e-mail antigo e atualiza para o e-mail novo no CSV.
    Retorna True se a atualização for bem-sucedida, False caso contrário.
    """
    try:
        # 1. Lê o arquivo (Correção: Usa ENCODING e DELIMITER globais)
        with open(ELEITORES_FILEPATH, 'r', newline='', encoding=ENCODING) as f:
            # IMPORTANTE: delimiter=DELIMITER é essencial para arquivos separados por ';'
            reader = csv.DictReader(f, delimiter=DELIMITER)
            
            # Converte para lista para poder modificar e regravar
            data = list(reader)
        
        updated = False
        
        # 2. Localiza e corrige o e-mail
        for row in data:
            # Garante que a coluna de e-mail existe na leitura
            if EMAIL_COL_NAME in row and row[EMAIL_COL_NAME] == old_email:
                row[EMAIL_COL_NAME] = new_email
                updated = True
                break
        
        if not updated:
            # Não encontrou o e-mail antigo
            return False

        # 3. Salva os dados atualizados (Correção: Usa ENCODING e DELIMITER globais)
        with open(ELEITORES_FILEPATH, 'w', newline='', encoding=ENCODING) as f:
            writer = csv.DictWriter(f, fieldnames=reader.fieldnames, delimiter=DELIMITER)
            writer.writeheader()
            writer.writerows(data)
            
        return True

    except FileNotFoundError:
        print(f"[ERRO] Arquivo CSV não encontrado: {ELEITORES_FILEPATH}")
        return False
    except Exception as e:
        print(f"[ERRO] Erro ao atualizar o CSV: {e}")
        return False

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

def process_eleitor(eleitor: Eleitor, sheet_service: GoogleSheetsService, force_resend: bool, production: bool) -> None:
    """
    Processa um único eleitor: verifica status, gera chaves e envia e-mail.
    """
    registros_antigos = load_enviados()
    registro_atual = next((r for r in registros_antigos if r.email == eleitor.email), None)
    
    # 1. Verifica se já foi enviado e se não é reenvio forçado
    if registro_atual and not force_resend:
        print(f"[PULAR] Eleitor {eleitor.nome} ({eleitor.email}) já processado (Geração {registro_atual.generation}). Use --resend para reenviar.")
        return

    # 2. Geração da Nova Chave
    keys = generate_key_pair()
    
    # 3. Tentativa de Envio de E-mail
    is_delivered = send_email(eleitor, keys, production)

    if not is_delivered and production:
        # Se falhou em produção, não registra a chave no Sheets e aborta o registro local.
        print(f"[AVISO] Chave não registrada no Sheets devido à falha de envio para {eleitor.email}.")
        return

    # 4. Atualização Google Sheets (Sempre Real - Chaves são registradas mesmo em modo TESTE)
    try:
        # a. Invalida anteriores (com delay se necessário)
        for r in registros_antigos:
            if r.email == eleitor.email and sheet_service.invalidate_old_key(r.user_id):
                time.sleep(3.0) # Delay para cota de escrita

        # b. Insere nova chave
        now_str = datetime.now().strftime(DATE_FORMAT)
        sheet_service.append_row(SHEET_NAME_PUB_KEY, [
            keys.user_id,
            keys.pub_key,
            True,
            production,
            now_str,
            '' # Coluna de t_desativacao (vazio na inserção)
        ])
        time.sleep(2.0) # Delay pós-escrita

        log_event(
            level='INFO', 
            email=eleitor.email, 
            user_id=keys.user_id, 
            message='Google Sheets atualizado.', 
            is_production=production
        )

    except Exception as e:
        log_event(
            level='ERRO',
            email=eleitor.email,
            user_id=keys.user_id,
            message=f'Falha crítica no Sheets API: {e}',
            is_production=production
        )
        print(f"[ERRO CRÍTICO] Falha ao atualizar Google Sheets para {eleitor.email}: {e}")
        return # Aborta registro local se Sheets falhou

    # 5. Atualiza Registro Local (COM HISTÓRICO)
    
    # a. Filtra todo o histórico deste usuário para calcular a geração correta
    historico_usuario = [r for r in registros_antigos if r.email == eleitor.email]
    
    if historico_usuario:
        # Pega a maior geração existente e soma 1
        new_generation = max(r.generation for r in historico_usuario) + 1
    else:
        new_generation = 1
    
    # b. Atualiza o status dos registros antigos para Inativo (is_active = False)
    # Como estamos manipulando objetos dentro da lista 'registros_antigos', 
    # a alteração reflete na lista principal.
    for r in historico_usuario:
        r.is_active = False

    # c. Adiciona o novo registro diretamente à lista COMPLETA (sem limpar os antigos)
    registros_antigos.append(RegistroEnvio(
        timestamp=datetime.now().strftime(DATE_FORMAT),
        email=eleitor.email,
        user_id=keys.user_id,
        pub_key=keys.pub_key,
        generation=new_generation,
        is_active=True,         # Apenas o novo é ativo
        is_delivered=is_delivered,
        is_production=production
    ))
    
    # d. Salva a lista completa (com histórico atualizado e o novo registro)
    save_enviados_atomically(registros_antigos)

    print(f"[SUCESSO] Processamento de {eleitor.nome} concluído. Geração: {new_generation}")

    if production:
        print(f"[PAUSA SMTP] Aguardando {EMAIL_SEND_INTERVAL_SECONDS} segundos antes do próximo eleitor...")
        time.sleep(EMAIL_SEND_INTERVAL_SECONDS)

def main():
    # 0. Configuração de Argumentos (REMOÇÃO DA FLAG --resend)
    parser = argparse.ArgumentParser(description="Script de gerenciamento de eleitores e envio de credenciais para votação eletrônica.")
    parser.add_argument('destinatario', nargs='?', default='TODOS', help="eleitor@email.com.br (ou 'TODOS') para processamento.")
    parser.add_argument('--replace', nargs=2, metavar=('OLD', 'NEW'), help="Inativa credencial do OLD_EMAIL e envia novas chaves para NEW_EMAIL.")
    parser.add_argument('--production', action='store_true', help="Ativa o modo de produção (envios REAIS de e-mail).")
    # A flag --resend foi removida para eliminar a funcionalidade de reenvio em massa.
    args = parser.parse_args()

    # Define args.resend com o valor padrão False para uso posterior
    args.resend = False
    
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
        # generate_audit_hashes(args.production)

        # 4. Inicializa o serviço Sheets logo no início para ser acessível pelo --replace.
        sheet_service = GoogleSheetsService(SPREADSHEET_ID)

        # 5. Lógica de Substituição de Credencial (--replace)
        is_replace_operation = False
        if args.replace:
            is_replace_operation = True
            old_email, new_email = args.replace
            print(f"\n🔄 OPERAÇÃO DE SUBSTITUIÇÃO: {old_email} -> {new_email}")
            
            # 1. Carrega histórico local
            registros = load_enviados()
            registro_antigo = next((r for r in registros if r.email == old_email and r.is_active), None)
            
            if not registro_antigo:
                print(f"[ERRO] Credencial ativa para {old_email} não encontrada no histórico local.")
                return

            # 2. Invalida no Google Sheets e Localmente
            print(f"[INFO] Invalidando credencial antiga ({registro_antigo.user_id})...")
            # Este comando pode falhar por problemas de rede/API.
            sheet_service.invalidate_old_key(registro_antigo.user_id)

            for r in registros:
                if r.email == old_email:
                    r.is_active = False
            save_enviados_atomically(registros)

            # --- CORREÇÃO ADICIONADA: ATUALIZAÇÃO DO CSV ---
            # 3. Correção do E-mail no Eleitores.csv
            # ELEITORES_FILEPATH deve estar definido no escopo global/módulo.
            print(f"[INFO] Corrigindo e-mail no arquivo ELEITORES_FILEPATH...")
            
            # Chama a função que carrega, atualiza e salva o eleitores.csv
            if update_eleitor_email(old_email, new_email):
                # LOG DE SUCESSO (usando print, que é redirecionado)
                print(f"✅ E-mail corrigido com sucesso: '{old_email}' alterado para '{new_email}' no CSV.")
            else:
                # Se falhar a correção do CSV, interrompemos, pois a próxima etapa falhará.
                print(f"[ERRO] Não foi possível encontrar/corrigir o e-mail '{old_email}' no CSV. Operação abortada.")
                return 
            # --- FIM DA CORREÇÃO ADICIONADA ---

            # 4. Configura o alvo para ser o NOVO e-mail
            args.destinatario = new_email
            # Programaticamente, forçamos o resend para que o fluxo principal processe o novo e-mail.
            args.resend = True 

        # 6. Alertas de Segurança e Confirmação
        if args.production:
            print("\n🚨 MODO DE PRODUÇÃO ATIVADO 🚨")
            print("Envios REAIS de e-mail. Cancelar? (Aperte Ctrl+C em 5 segundos)")
            print(f"[PAUSA SMTP] Aguardando {EMAIL_SEND_INTERVAL_SECONDS} entre envios de e-mails.")

            time.sleep(5)
        else:
            print("\n🧪 MODO DE TESTE (Simulação de E-mail) 🧪")
            print("Planilha será atualizada, e-mails NÃO serão enviados (apenas simulados).")

        # ** IMPLEMENTAÇÃO DA NOVA MEDIDA DE SEGURANÇA MÁXIMA **
        is_target_all = args.destinatario.upper() == 'TODOS'
        
        if is_target_all:
            # Caso de uso: python eleicoes.py TODOS
            print("\n[ERRO DE SEGURANÇA MÁXIMA] Tentativa de processar 'TODOS'.")
            print("O reenvio/processamento em massa está bloqueado para prevenir a geração acidental de novas chaves.")
            print("Para operações de 'replace' ou reenvio, use o e-mail específico: python eleicoes.py eleitor@email.com")
            return
            
        elif is_replace_operation:
             # Caso de uso: python eleicoes.py --replace old@email new@email
             print(f"\n[INFO] Modo Substituição de Credencial (unitário) ativado para {args.destinatario}.")
        else:
            # Caso de uso: python eleicoes.py jose@email.com
            # Neste ponto, args.destinatario é um e-mail único.
            print(f"\n[INFO] Modo Reenvio (unitário) ativado para {args.destinatario}.")
            
        print("\n" + "="*50 + "\n")
        
        # O bloco try/except/finally original do usuário (Lógica Principal)
        try:
            eleitores = load_eleitores()
            
            if not eleitores:
                print("[AVISO] Nenhum eleitor encontrado.")
                return

            targets = []
            # A checagem de is_target_all já garante que o fluxo abaixo só rodará para e-mails únicos.
            
            # ATENÇÃO: args.destinatario AGORA é o NEW_EMAIL corrigido no caso de --replace
            found = next((e for e in eleitores if e.email == args.destinatario), None)
            
            if found:
                targets = [found]
                # Se for envio unitário (e-mail específico), forçamos o resend para que o envio ocorra.
                args.resend = True 
            else:
                # Este erro agora só ocorre se: 
                # 1. O e-mail nunca existiu (caso normal de reenvio unitário), OU
                # 2. A função update_eleitor_email FALHOU (o que já foi tratado acima, mas é um bom fallback)
                print(f"[ERRO] Eleitor {args.destinatario} não encontrado na lista (ou o e-mail é inválido).")
                return

            # 4. Lógica de embaralhamento criptograficamente seguro (não-reprodutível)
            # Esta seção não será executada, pois targets terá no máximo 1 elemento,
            # mas é mantida por segurança/modularidade caso targets seja modificado.
            if len(targets) > 1:
                secrets.SystemRandom().shuffle(targets)
                
                print(f"[INFO] Ordem de processamento embaralhada de forma CRIPTOGRAFICAMENTE SEGURA para {len(targets)} eleitor(es).")
                print("[INFO] A ordem é irreprodutível e garante a máxima proteção contra inferência de ID/Chave.")

            print(f"[INFO] Iniciando processamento de {len(targets)} eleitor(es)...")
            
            for eleitor in targets:
                # 'sheet_service' está definido no escopo externo e acessível aqui.
                # args.resend está TRUE, garantindo o reenvio/geração da nova chave.
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