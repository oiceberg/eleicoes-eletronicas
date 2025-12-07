"""
Script Name: eleicoes.py
Version: 1.0 (Com Auditoria e Validação)
Date: 2025-12-06
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
SUBJECT: Final[str]   = "TESTE – Eleições AGESP 2025 – Suas credenciais para votação"

# Google Forms
BASE_FORM_URL: Final[str] = "https://forms.gle/KxS5SK5xcv7RPhew5"

# Datas da Eleição
DATA_INICIO_VOTACAO: Final[str] = "09/12/2025" 
DATA_FIM_VOTACAO: Final[str] = "10/12/2025"

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

def generate_hash_of_file(filepath: str) -> Optional[str]:
    """Calcula o hash SHA-256 de um arquivo em disco."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[ERRO HASH] Falha ao calcular hash de {filepath}: {e}")
        return None

def generate_audit_hashes() -> None:
    """
    Gera hashes SHA-256 dos arquivos críticos, imprime na tela e salva em CSV para auditoria.
    Calcula e imprime o 'meta hash' do arquivo de auditoria DEPOIS de salvá-lo.
    """

    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    DYNAMIC_AUDIT_FILEPATH = os.path.join('data', f"audit_hashes_{now_str}.csv")

    # 1. Lista em ordem lógica/cronológica de importância no processo de auditoria
    files_to_hash = [
        os.path.abspath(__file__), # 1. O script principal
        ENV_TOML_FILEPATH,         # 2. Configuração de segredos
        CREDENTIALS_PATH,          # 3. JSON de credenciais
        ELEITORES_FILEPATH,        # 4. Dados de entrada (eleitores)
        GS_FORMULARIO_FILEPATH,    # 5. Script do Google Form
        GS_PLANILHA_FILEPATH,      # 6. Script do Google Sheets
        TEMPLATE_FILEPATH,         # 7. Template do e-mail
    ]
    
    audit_data = []
    
    # 2. Calcula hashes de todos os arquivos de entrada
    for filepath in files_to_hash:
        file_hash = generate_hash_of_file(filepath)
        
        if file_hash:
            # Lógica para definir o nome de exibição (caminho relativo com '/')
            if filepath == os.path.abspath(__file__):
                display_name = 'src/eleicoes.py' 
            elif filepath == CREDENTIALS_PATH:
                display_name = 'config/' + os.path.basename(CREDENTIALS_PATH)
            else:
                display_name = filepath.replace(os.sep, '/')
                
            audit_data.append({
                "timestamp": datetime.now().strftime(DATE_FORMAT),
                "arquivo": display_name,
                "hash_sha256": file_hash
            })
        else:
            print(f"[AVISO] Arquivo não encontrado para auditoria: {filepath.replace(os.sep, '/')} -> Hash não gerado.")

    # 3. Salva em CSV (audit_hashes_timestamp.csv)
    try:
        with open(DYNAMIC_AUDIT_FILEPATH, mode='w', newline='', encoding=ENCODING) as f:
            writer = csv.writer(f, delimiter=DELIMITER)
            
            # Escreve cabeçalho
            writer.writerow(['timestamp', 'arquivo', 'hash_sha256'])
            
            for entry in audit_data:
                writer.writerow([entry['timestamp'], entry['arquivo'], entry['hash_sha256']])
                
    except Exception as e:
        print(f"[ERRO] Não foi possível salvar arquivo de auditoria '{DYNAMIC_AUDIT_FILEPATH}': {e}")
        # Aborta a execução para não prosseguir com uma auditoria incompleta
        sys.exit(1)

    # 4. Calcula e adiciona o Meta Hash (agora que o arquivo está SALVO)
    meta_hash = generate_hash_of_file(DYNAMIC_AUDIT_FILEPATH)
    
    if meta_hash:
        meta_file_name = DYNAMIC_AUDIT_FILEPATH.replace(os.sep, '/')
        # Adiciona a entrada do Meta Hash no final para ser impresso
        audit_data.append({
            "timestamp": datetime.now().strftime(DATE_FORMAT),
            "arquivo": meta_file_name,
            "hash_sha256": meta_hash
        })
    
    # 5. Imprime o Relatório Final
    print("\n" + "="*104)
    print("🔐 Relatório de Integridade Criptográfica (SHA-256) 🔐".center(104))
    print("-" * 104)
    
    # Imprime todos os hashes, exceto o último (Meta Hash)
    if audit_data:
        # Imprime todos os itens, exceto o último (o Meta Hash)
        for entry in audit_data[:-1]:
            print(f"[{entry['arquivo'].ljust(37)}] {entry['hash_sha256']}")
        
        # Imprime a linha de separação
        print("-" * 104)

        # Imprime a mensagem de salvamento
        print(f"📝 Hashes de auditoria salvos em '{DYNAMIC_AUDIT_FILEPATH.replace(os.sep, '/')}'")

        # Imprime o Meta Hash (último item da lista)
        meta_entry = audit_data[-1]
        print(f"[{meta_entry['arquivo'].ljust(37)}] {meta_entry['hash_sha256']}")
    else:
        print("Nenhum arquivo auditado com sucesso.".center(104))
        
    print("=" * 104)

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
        print(f"[ERRO CRÍTICO] Falha no log: {e}")

def save_enviados_atomically(registros: List[RegistroEnvio]) -> None:
    """Salva a lista completa de registros de forma atômica."""
    temp_filepath = ENVIADOS_FILEPATH + '.tmp'
    try:
        with open(temp_filepath, mode='w', newline='', encoding=ENCODING) as f:
            writer = csv.writer(f, delimiter=DELIMITER)
            writer.writerow(RegistroEnvio.__annotations__.keys()) # Escreve cabeçalho
            for reg in registros:
                writer.writerow(list(asdict(reg).values()))
        
        os.replace(temp_filepath, ENVIADOS_FILEPATH)
    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha ao salvar registros de envio: {e}")


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

    # 5. Atualiza Registro Local
    new_generation = (registro_atual.generation + 1) if registro_atual else 1
    
    # Remove registros antigos do mesmo eleitor
    registros_limpos = [r for r in registros_antigos if r.email != eleitor.email]
    
    # Adiciona o novo registro (limpando o antigo)
    registros_limpos.append(RegistroEnvio(
        timestamp=datetime.now().strftime(DATE_FORMAT),
        email=eleitor.email,
        user_id=keys.user_id,
        pub_key=keys.pub_key,
        generation=new_generation,
        is_active=True,
        is_delivered=is_delivered,
        is_production=production
    ))
    save_enviados_atomically(registros_limpos)
    print(f"[SUCESSO] Processamento de {eleitor.nome} concluído. Geração: {new_generation}")

def main():
    # 0. Configuração de Argumentos
    parser = argparse.ArgumentParser(description="Script de gerenciamento de eleitores e envio de credenciais para votação eletrônica.")
    parser.add_argument('destinatario', nargs='?', default='TODOS', help="E-mail do eleitor (ou 'TODOS') para processamento.")
    parser.add_argument('--resend', action='store_true', help="Força o reenvio de credenciais (gera nova chave) para TODOS. USE COM CAUTELA.")
    parser.add_argument('--production', action='store_true', help="Ativa o modo de produção (envios REAIS de e-mail).")
    args = parser.parse_args()

    # 1. Registro do Tempo de Início
    start_time = datetime.now()
    print("="*50)
    print(f"[{start_time.strftime(DATE_FORMAT)}] ⏱️ INÍCIO da execução do script.")
    print("="*50)

    log_event(
        level="INFO", 
        email="", 
        user_id="SYSTEM", 
        message=f"INÍCIO da execução do script. Modo Produção: {args.production}", 
        is_production=args.production
    )

    # 2. Executa Auditoria de Arquivos (Para o vídeo/registro)
    generate_audit_hashes()

    # 3. Alertas de Segurança e Confirmação
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
        # Usa SystemRandom do módulo secrets para garantir que o embaralhamento seja baseado na entropia do SO.
        if len(targets) > 1:
            secrets.SystemRandom().shuffle(targets)
            
            print(f"[INFO] Ordem de processamento embaralhada de forma CRIPTOGRAFICAMENTE SEGURA para {len(targets)} eleitor(es).")
            print("[INFO] A ordem é irreprodutível e garante a máxima proteção contra inferência de ID/Chave.")

        print(f"[INFO] Iniciando processamento de {len(targets)} eleitor(es)...")
        
        for eleitor in targets:
            process_eleitor(eleitor, sheet_service, args.resend, args.production)

        # 5. Atualização da flag de apuração (run once)
        # O "Cutucão" para o Apps Script é feito APENAS UMA ÚNICA VEZ
        if len(targets) > 0:
            timestamp = datetime.now().strftime(DATE_FORMAT)
            
            # Combina o nome da aba e a célula no formato A1
            range_a1_notation = f"{APPS_SCRIPT_FLAG_CELL}"

            # Chama a função de atualização via API uma única vez
            sheet_service.update_cell(range_a1_notation, timestamp)
            
            # Log corrigido, referenciando a função triggerApuracao
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
        # 4. Registro do Tempo de Fim e Duração
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

        log_event(
            level="INFO", 
            email="", 
            user_id="SYSTEM", 
            message=f"FIM da execução do script. Duração: {duration_str}", 
            is_production=args.production
        )

if __name__ == "__main__":
    main()
