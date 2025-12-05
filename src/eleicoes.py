import argparse
import csv
import hmac
import os
import secrets
import string
import time
import tomllib
import smtplib
import ssl
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

# Google Sheets
SPREADSHEET_ID: Final[str] = '1TwS__JwRBG94R4d0WuVMXcYKKnafBuKIJWiJ6frKufw'
APPS_SCRIPT_FLAG_CELL: Final[str] = 'config_automatica!A1'
SHEET_NAME_PUB_KEY = 'chaves_publicas'
RANGE_PUB_KEY = f'{SHEET_NAME_PUB_KEY}!A:F'

# Caminho programático da credencial para o Google Sheets API
CREDENTIALS_FILE_NAME: Final[str] = 'eleicoes-eletronicas-agesp-94459f9b1b7c.json'
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
        print(f"[DEBUG] Usando credencial: {os.environ['GOOGLE_APPLICATION_CREDENTIALS']}")
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
        """Insere uma nova linha na planilha. Operação SEMPRE executada."""
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
        # Mantendo para compatibilidade, embora seja melhor usar o invalidate_old_key
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
        IMPORTANTE: Itera sobre TODAS as linhas para desativar CHAVES DUPLICADAS ATIVAS.
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
                    # Não retorna False, pois pode haver outras linhas para tentar invalidar
                    continue
        
        return writes_performed


# --- 4. PERSISTÊNCIA LOCAL (CSV) ---

def load_eleitores() -> List[Eleitor]:
    """
    Carrega a lista de eleitores do CSV.
    """
    if not os.path.exists(ELEITORES_FILEPATH): return []
    try:
        with open(ELEITORES_FILEPATH, mode='r', encoding=ENCODING) as f:
            reader = csv.reader(f, delimiter=DELIMITER)
            next(reader, None) # Pula o cabeçalho
            return [
                Eleitor(
                    nome=r[0].strip(),
                    email=r[1].strip()
                )
                for r in reader if len(r) >= 2
            ]
    except Exception as e:
        print(f"[ERRO] Falha ao ler eleitores: {e}")
        return []

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
    return registros

def log_event(level: str, email: str, user_id: str, message: str, is_production: bool) -> None:
    """Registra evento no log."""
    entry = [
        datetime.now().isoformat(timespec='seconds'), 
        str(is_production),
        level,
        email,
        user_id,
        message.replace(DELIMITER, ' | ')
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
    """Salva o CSV de forma atômica para evitar corrupção."""
    tmp_path = f"{ENVIADOS_FILEPATH}.tmp"
    try:
        with open(tmp_path, mode='w', newline='', encoding=ENCODING) as f:
            writer = csv.writer(f, delimiter=DELIMITER)
            writer.writerow(RegistroEnvio.__annotations__.keys())
            for reg in registros:
                writer.writerow(list(asdict(reg).values()))
        os.replace(tmp_path, ENVIADOS_FILEPATH)
    except Exception as e:
        if os.path.exists(tmp_path): os.remove(tmp_path)
        raise Exception(f"Falha ao salvar CSV: {e}")


# --- 5. LÓGICA DE DOMÍNIO ---

def generate_key_pair() -> KeyPair:
    """Gera um novo user_id e um par de chaves (priv_key, pub_key)."""
    
    # 1. Geração do ID numérico 6 dígitos (100000-999999)
    user_id = str(secrets.randbelow(900000) + 100000)

    master_key = ENV.get('secrets', {}).get('master_key')
    if not master_key: raise RuntimeError("master_key ausente no env.toml")

    # 2. Chave Privada: 12 letras maiúsculas
    priv_key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(12))
    # 3. Chave Pública: HMAC-SHA256
    pub_key = hmac.new(master_key.encode(), priv_key.encode(), 'sha256').hexdigest()
    
    return KeyPair(user_id, priv_key, pub_key)

def load_template_html() -> str:
    if os.path.exists(TEMPLATE_FILEPATH):
        with open(TEMPLATE_FILEPATH, 'r', encoding='utf-8') as f: return f.read()
    return "<html><body><p>Olá {nome},</p><p>ID: {user_id}</p><p>Senha: {priv_key}</p></body></html>"

def send_email_consolidated(eleitor: Eleitor, keys: KeyPair, production: bool) -> bool:
    """Constrói, envia (ou simula) o e-mail e registra o log."""
    
    # 1. Preparação
    ano = datetime.now().year
    html_tmpl = load_template_html()
    
    # Preenche o template com TODAS as variáveis necessárias
    try:
        html_content = html_tmpl.format(
            nome=eleitor.nome.split()[0], # Apenas o primeiro nome para o template
            user_id=keys.user_id, 
            
            # Mapeia 'priv_key' para 'chave_privada' e 'priv_key' para o template
            priv_key=keys.priv_key,       
            chave_privada=keys.priv_key,  
            
            pub_key=keys.pub_key, 
            link_votacao=BASE_FORM_URL, 
            ano=ano, 
            from_name=FROM_NAME,
            
            # ➡️ MUDANÇA MÍNIMA AQUI: INSERINDO AS DATAS
            data_inicio_votacao=DATA_INICIO_VOTACAO,
            data_fim_votacao=DATA_FIM_VOTACAO
        )
    except KeyError as e:
        print(f"[ERRO TEMPLATE] Variável faltando no template HTML: {e}")
        return False
    
    # Conteúdo de texto simples
    text_content = (
        f"Olá {eleitor.nome},\n\n"
        f"Seguem seus dados para a Eleição AGESP {ano}:\n\n"
        f"Período: {DATA_INICIO_VOTACAO} a {DATA_FIM_VOTACAO}\n"
        f"ID de Validação: {keys.user_id}\n"
        f"Chave Privada  : {keys.priv_key}\n"
        f"Chave Pública  : {keys.pub_key}\n"
        f"Link de Votação: {BASE_FORM_URL}\n\n"
        f"Atenciosamente,\n{FROM_NAME}"
    )

    msg = EmailMessage()
    msg["Subject"] = SUBJECT
    msg["From"] = formataddr((FROM_NAME, SMTP_USER))
    msg["To"] = eleitor.email
    msg.set_content(text_content)
    msg.add_alternative(html_content, subtype="html")

    # 2. Envio / Simulação
    success = False
    log_msg = ""
    log_level = 'INFO'

    if not production:
        print("\n" + "="*60)
        print(f"🧪 [TESTE] E-MAIL SIMULADO PARA: {eleitor.email}")
        print("-" * 60)
        print(f"Assunto: {SUBJECT}")
        print("\nCONTEÚDO (Visualização):")
        print("    " + "\n    ".join(text_content.split('\n')))
        print("="*60 + "\n")
        success = True
        log_msg = "Simulação de envio bem-sucedida."
    else:
        smtp_pass = ENV.get('secrets', {}).get('smtp_pass')
        if not smtp_pass:
            log_msg = "Senha SMTP não configurada."
            log_level = 'ERROR'
        else:
            try:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
                    server.login(SMTP_USER, smtp_pass)
                    server.send_message(msg)
                success = True
                log_msg = "E-mail enviado com sucesso (SMTP)."
            except Exception as e:
                log_msg = f"Falha no envio SMTP: {e}"
                log_level = 'ERROR'

    log_event(log_level, eleitor.email, keys.user_id, log_msg, production)
    if success: print(f"[SUCESSO] {log_msg}")
    else: print(f"[FALHA] {log_msg}")
    
    return success

def process_eleitor(eleitor: Eleitor, sheet_service: GoogleSheetsService, resend: bool, production: bool):
    """Fluxo completo de processamento de um eleitor."""
    enviados_list = load_enviados()
    registros_antigos = [r for r in enviados_list if r.email == eleitor.email]
    
    # Validação de Processamento
    if registros_antigos and not resend:
        print(f'[INFO] {eleitor.email} já processado. Use --resend para forçar.')
        return

    # A partir daqui, estamos sempre emitindo novas chaves/IDs.
    
    if registros_antigos:
        for r in registros_antigos: r.is_active = False # Invalida localmente
        log_event('INFO', eleitor.email, 'N/A', f'Reenvio: {len(registros_antigos)} registros invalidados', production)

    # 1. Gera Novas Chaves e ID (SEMPRE NOVOS)
    ids_usados = {r.user_id for r in enviados_list}
    keys = generate_key_pair()
    # Garante unicidade do NOVO user_id
    while keys.user_id in ids_usados:
        keys = generate_key_pair()

    # 2. Persistência Local (Antes de Enviar)
    next_gen = max([r.generation for r in registros_antigos], default=0) + 1
    novo_reg = RegistroEnvio(
        timestamp=datetime.now().isoformat(timespec='seconds'),
        email=eleitor.email,
        user_id=keys.user_id,
        pub_key=keys.pub_key,
        generation=next_gen,
        is_active=True,
        is_delivered=False,
        is_production=production
    )
    enviados_list.append(novo_reg)
    
    try:
        save_enviados_atomically(enviados_list)
    except Exception as e:
        print(f"[ERRO] Falha ao salvar CSV local: {e}")
        return

    # 3. Atualização Google Sheets (Sempre Real)
    try:
        # a. Invalida anteriores (com delay se necessário)
        for r in registros_antigos:
            if sheet_service.invalidate_old_key(r.user_id):
                time.sleep(3.0) # Delay para cota de escrita
        
        # b. Insere nova chave
        now_str = datetime.now().strftime(DATE_FORMAT)
        sheet_service.append_row(SHEET_NAME_PUB_KEY, [
            keys.user_id, keys.pub_key, True, production, now_str, ''
        ])
        time.sleep(2.0) # Delay pós-escrita
        
        log_event('INFO', eleitor.email, keys.user_id, 'Google Sheets atualizado.', production)

        # 💡 PASSO CRÍTICO: CHAMA O APPS SCRIPT PARA RECALCULAR TUDO
        # sheet_service.execute_apps_script_function('generateApuracaoAutomatica')
        # time.sleep(5.0) # Delay para processamento do Apps Script

        sheet_service.write_flag_to_cell(
            APPS_SCRIPT_FLAG_CELL, 
            datetime.now().strftime(DATE_FORMAT) # Usa o timestamp como flag
        )
        print("[API SCRIPT] Função generateApuracaoAutomatica acionada via Sheets API (Flag).")
        time.sleep(5.0) # Delay para dar tempo do gatilho rodar

    except Exception as e:
        msg = f"Falha CRÍTICA no Google Sheets: {e}"
        print(f"[ERRO] {msg}")
        log_event('ERROR', eleitor.email, keys.user_id, msg, production)
        return

    # 4. Envio de E-mail
    sent = False
    attempts = 3 if production else 1
    
    for i in range(attempts):
        if send_email_consolidated(eleitor, keys, production):
            sent = True
            break
        time.sleep(2)

    # 5. Atualiza Status Entrega
    if sent:
        novo_reg.is_delivered = True
        try:
            save_enviados_atomically(enviados_list)
            print(f"[CSV] Status atualizado: Entregue para {eleitor.email}")
        except Exception as e:
            print(f"[WARN] Falha ao atualizar status de entrega: {e}")


# --- 6. MAIN ---

def main():
    parser = argparse.ArgumentParser(description='Sistema de Eleições AGESP')
    parser.add_argument('destinatario', help='Email do destinatário ou "TODOS"')
    parser.add_argument('--resend', action='store_true', help='Força reenvio e rotação de chaves')
    parser.add_argument('--production', action='store_true', help='ATIVA ENVIO REAL (E-mail e Sheets)')
    args = parser.parse_args()

    print("\n" + "="*50)
    if args.production:
        print("🚨 MODO DE PRODUÇÃO ATIVADO 🚨")
        print("Envios REAIS de e-mail. Cancelar? (Ctrl+C - 5 segundos)")
        time.sleep(5)
    else:
        print("🧪 MODO DE TESTE (Simulação de E-mail)")
        print("Planilha será atualizada, e-mails apenas exibidos.")
    print("="*50 + "\n")

    try:
        # sheet_service = GoogleSheetsService(SPREADSHEET_ID, APPS_SCRIPT_ID)
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
                args.resend = True # Alvo único implica intenção de envio/reenvio
            else:
                print(f"[ERRO] Eleitor {args.destinatario} não encontrado.")
                return

        print(f"[INFO] Iniciando processamento de {len(targets)} eleitor(es)...")
        
        for eleitor in targets:
            process_eleitor(eleitor, sheet_service, args.resend, args.production)

    except KeyboardInterrupt:
        print("\n[INTERROMPIDO] Operação cancelada pelo usuário.")
    except Exception as e:
        print(f"\n[ERRO FATAL] {e}")

if __name__ == '__main__':
    main()
