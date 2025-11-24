#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
PROJETO: SISTEMA DE ELEIÇÕES ELETRÔNICAS DA AGESP
ARQUIVO: mailer.py
VERSÃO:  1.0.0 (Lançamento Inicial no GitHub)
AUTOR:   Leandro Salvador <leandrosalvador@gmail.com>
DATA:    2025-11-23

DESCRIÇÃO:
    Módulo principal responsável pelo disparo em massa de e-mails transacionais.
    Envia as chaves criptográficas (pública e privada) e o link de votação
    para cada eleitor. Possui mecanismos de resiliência (retentativas, envio
    por lotes, e log de status) essenciais para operações em escala.

ENTRADAS:
    -> data/envio_confidencial.csv (Lista de eleitores com chaves geradas).

SAÍDAS:
    <- data/envios_log.csv (Registro de sucesso/falha para controle e retomada).

DEPENDÊNCIAS:
    Python 3 nativo.
=============================================================================
"""

import os
import csv
import ssl
import smtplib
import time
import random
import html
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from urllib.parse import urlencode, quote_plus
from typing import Dict, Any

# =============================================================================
# 1. CARREGAMENTO DE CONFIGURAÇÕES
# =============================================================================

def carregar_env(arquivo=".env"):
    """Carrega variáveis do arquivo .env, tratando comentários e espaços."""
    if not os.path.exists(arquivo): return
    with open(arquivo, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha: continue
            
            k_raw, v_raw = linha.split("=", 1)
            
            if "#" in v_raw:
                v = v_raw[:v_raw.find("#")].strip()
            else:
                v = v_raw.strip()

            os.environ[k_raw.strip()] = v

def obter_config() -> Dict[str, Any]:
    """Lê todas as configurações do ambiente e do .env."""
    carregar_env()
    ano = os.getenv("ANO_ELEICAO", str(datetime.now().year))
    
    DATA_FOLDER = "data/"
    csv_input_path = DATA_FOLDER + os.getenv("CSV_INPUT", "envio_confidencial.csv")
    csv_log_path = DATA_FOLDER + os.getenv("CSV_LOG", "envios_log.csv")
    
    simulacao_raw = os.getenv("SIMULACAO", "false")
    is_simulation = simulacao_raw.lower() in {"1", "true", "yes"}
    ignore_sent_final = not is_simulation

    # Lendo o template do assunto e formatando
    subject_template = os.getenv("ASSUNTO", f"Eleições AGESP {ano} – Suas chaves para votação")
    try:
        # FIX: Garante que {ano} seja substituído
        subject_final = subject_template.format(ano=ano)
    except:
        subject_final = subject_template.replace("{ano}", ano) # Fallback seguro
    
    return {
        "smtp_host": os.getenv("SMTP_HOST", ""),
        "smtp_port": int(os.getenv("SMTP_PORT", "465")),
        "smtp_user": os.getenv("SMTP_USER", ""),
        "smtp_pass": os.getenv("SMTP_PASS", ""),
        "use_ssl":   os.getenv("USE_SSL", "true").lower() in {"1", "true", "yes"},
        "from_name":  os.getenv("FROM_NAME", f"Comissão Eleitoral AGESP {ano}"),
        "from_email": os.getenv("FROM_EMAIL", os.getenv("SMTP_USER", "")),
        "subject":    subject_final, 
        "ano":        ano,
        "csv_input": csv_input_path, 
        "csv_log":   csv_log_path,   
        "batch_size":  int(os.getenv("EMAILS_POR_LOTE", "30")),
        "batch_pause": int(os.getenv("PAUSA_ENTRE_LOTES_SEC", "180")),
        "delay_min":   float(os.getenv("DELAY_MIN_SEC", "6")),
        "delay_max":   float(os.getenv("DELAY_MAX_SEC", "12")),
        "max_retries": int(os.getenv("MAX_TENTATIVAS", "3")),
        "is_simulation": is_simulation,
        "ignore_sent":   ignore_sent_final, 
        "base_form_url":     os.getenv("BASE_FORM_URL", ""),
        "entry_public_key":  os.getenv("ENTRY_PUBLIC_KEY", ""),
        "entry_private_key": os.getenv("ENTRY_PRIVATE_KEY", ""),
        "entry_email":       os.getenv("ENTRY_EMAIL", "")
    }

# =============================================================================
# 2. MANIPULAÇÃO DE ARQUIVOS
# =============================================================================

def ler_eleitores(caminho_csv):
    """Lê o CSV de eleitores/chaves."""
    if not os.path.exists(caminho_csv):
        print(f"[ERRO] Arquivo não encontrado: {caminho_csv}")
        return []
    
    encodings = ["utf-8-sig", "utf-8", "cp1252"]
    for enc in encodings:
        try:
            with open(caminho_csv, "r", encoding=enc, newline="") as f:
                sample = f.read(1024)
                f.seek(0)
                delimiter = ";" if sample.count(";") >= sample.count(",") else ","
                reader = csv.DictReader(f, delimiter=delimiter)
                return list(reader)
        except Exception: continue
    return []

def carregar_log(caminho_log):
    """Carrega os e-mails já enviados do log."""
    enviados = set()
    if os.path.exists(caminho_log):
        try:
            with open(caminho_log, "r", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f, delimiter=";"):
                    if row.get("status") == "enviado":
                        enviados.add(row.get("email", "").strip().lower())
        except: pass
    return enviados

def registrar_log(caminho_log, dados):
    """Registra o resultado do envio no log."""
    existe = os.path.exists(caminho_log)
    campos = ["timestamp", "nome", "email", "status", "tentativa", "erro"]
    with open(caminho_log, "a", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=campos, delimiter=";")
        if not existe: writer.writeheader()
        writer.writerow(dados)

# =============================================================================
# 3. COMPOSIÇÃO DE E-MAIL
# =============================================================================

def gerar_link(config, pub, priv, email):
    """Gera o link pré-preenchido para o Google Forms."""
    if not config["base_form_url"] or not config["entry_public_key"]: return ""
    params = {
        config["entry_public_key"]: pub,
        config["entry_private_key"]: priv
    }
    if config["entry_email"]: params[config["entry_email"]] = email
    sep = "&" if "?" in config["base_form_url"] else "?"
    return f"{config['base_form_url']}{sep}{urlencode(params, quote_via=quote_plus)}"

def criar_mensagem(config, dados):
    """Cria o objeto EmailMessage com texto simples e HTML."""
    msg = EmailMessage()
    msg["Subject"] = config["subject"]
    msg["From"] = formataddr((config["from_name"], config["from_email"]))
    msg["To"] = dados.get("Email", "")
    msg["Message-ID"] = make_msgid(domain=config["from_email"].split("@")[-1])
    
    pub  = dados.get("Chave Pública", "ERRO_KEY")
    priv = dados.get("Chave Privada", "ERRO_KEY")
    nome = dados.get("Nome", "")
    
    link = gerar_link(config, pub, priv, msg["To"])
    
    # --- Criação do Link e da Mensagem de Segurança ---
    
    link_txt = f"\nLink para votação: {link}\n" if link else ""
    
    if link:
        # Link clicável com texto amigável
        link_html = (
            f'<p style="margin-top: 15px;">'
            f'<strong>Link para votação:</strong> <a href="{link}" style="color: #0056b3; text-decoration: underline;">Clique aqui para votar</a>'
            f'</p>'
        )
    else:
        link_html = ''
    
    nome_safe = html.escape(nome)
    
    # Frases de Segurança Padronizadas
    msg_seguranca_txt = "IMPORTANTE: Para garantir seu voto secreto, não compartilhe estas chaves e o link acima com ninguém. Guarde-os em local seguro."
    
    # FIX: Usa tags HTML <strong> e caixa de destaque
    msg_seguranca_html = (
        f'<div style="border: 1px solid #CC0000; padding: 10px; margin: 15px 0; background-color: #ffeaea; border-radius: 5px;">'
        f'<p style="margin:0; font-weight:bold; color:#CC0000;">ATENÇÃO (SEGURANÇA):</p>'
        f'<p style="margin: 5px 0 0 0;">Para garantir seu voto secreto, <strong>NÃO COMPARTILHE</strong> estas chaves e o link com ninguém.<br>Guarde-os em local seguro.</p>'
        f'</div>'
    )
    
    # --- Corpo do E-mail (Texto Simples) ---

    texto = (
        f"Olá {nome},\n\n"
        f"Seguem suas chaves para votação:\n\n" 
        f"CHAVE PÚBLICA: {pub}\n"
        f"CHAVE PRIVADA: {priv}\n\n"
        f"{link_txt}\n"
        f"{msg_seguranca_txt}\n\n"
        f"Atenciosamente,\n{config['from_name']}\n"
    )
    
    # --- Corpo do E-mail (HTML) ---
    
    html_body = (
        f"<!doctype html><html><body style='font-family: Arial, sans-serif; color:#333;'>"
        f"<div style='max-width:600px; margin:0 auto; border:1px solid #ddd; padding:20px; border-radius: 5px;'>"
        f"<h2 style='color:#0056b3;'>Eleições AGESP {config['ano']}</h2>"
        f"<p>Olá <strong>{nome_safe}</strong>,</p>"
        f"<p>Seguem suas chaves para votação:</p>"
        
        # FIX: BOX DE CHAVES (Removendo margin-top do primeiro <p> para alinhar)
        f"<div style='background:#f4f4f4; padding:15px; margin:15px 0; border-radius: 5px;'>"
        f"<p style='margin-top: 0; margin-bottom: 5px;'><strong>Chave Pública:</strong> {pub}</p>" 
        f"<p style='margin-top: 5px; margin-bottom: 0;'><strong>Chave Privada:</strong> {priv}</p>"
        f"</div>"
        
        f"{link_html}" # Link Clicável
        
        f"{msg_seguranca_html}" # Aviso de segurança destacado
        
        f"<hr style='border: 0; border-top: 1px solid #eee; margin: 20px 0;'>"
        
        # FIX: ASSINATURA AJUSTADA
        f"<p style='font-size:0.9em; color:#666;'>"
        f"Atenciosamente,<br>"
        f"<strong>{config['from_name']}</strong><br>"
        f"<span style='font-size: 0.8em; color: #999; margin-top: 10px; display: block;'>Mensagem automática.</span>"
        f"</p>"
        f"</div></body></html>"
    )
    
    msg.set_content(texto)
    msg.add_alternative(html_body, subtype="html")
    return msg

def enviar_retry(server, msg, config, dest):
    """Tenta enviar o e-mail (ou simula) com retentativas."""
    if config["is_simulation"]:
        # MODO SIMULAÇÃO: MOSTRA O PACOTE COMPLETO (Auditoria)
        try:
            plain_text_part = msg.get_body(preferencelist=('plain',))
            corpo_completo = plain_text_part.get_content().strip() 
        except AttributeError:
             corpo_completo = "Não foi possível extrair o corpo para debug."
        
        print("\n" + "~"*60)
        print("[SIMULACAO] E-MAIL PRONTO PARA ENVIO (AUDITORIA COMPLETA):")
        print(f"  DE: {msg['From']}")
        print(f"  PARA: {dest}")
        print(f"  ASSUNTO: {msg['Subject']}")
        print("\n  ========================================")
        print("  CORPO DO E-MAIL (TEXTO PURO):")
        print("  ========================================")
        for line in corpo_completo.splitlines():
            print(f"  {line}") 
        print("  ========================================\n")
        print("~"*60 + "\n")
        return "simulacao", ""
    
    # MODO REAL
    for i in range(1, config["max_retries"] + 1):
        try:
            server.send_message(msg) 
            print(f"[OK] Enviado: {dest}")
            return "enviado", ""
        except Exception as e:
            # Captura a mensagem de erro para o log, incluindo códigos SMTP
            error_msg = str(e)
            print(f"[ERRO {i}] {dest}: {error_msg}")
            
            # Se for um erro temporário (como 451), espera e tenta de novo
            if any(code in error_msg for code in ["421", "451", "452"]):
                 time.sleep(2 ** i)
            else:
                 # Se for erro fatal (como 5xx), não tenta de novo imediatamente
                 time.sleep(2)
                 break
                 
    # Se o loop de tentativas terminar sem sucesso
    return "erro", error_msg

# =============================================================================
# 4. EXECUÇÃO PRINCIPAL
# =============================================================================

def main():
    print("== MAILER AGESP (v4.1) ==")
    cfg = obter_config()
    
    # 1. Carregar Eleitores
    lista = ler_eleitores(cfg["csv_input"])
    if not lista: return print("[ERRO] Lista de eleitores vazia ou não encontrada.")
    print(f"[INFO] {len(lista)} registros carregados de {cfg['csv_input']}.")
    
    # 2. Verificar Já Enviados
    enviados = set()
    if cfg["ignore_sent"]: enviados = carregar_log(cfg["csv_log"])
    
    # 3. Conectar SMTP
    server = None
    if not cfg["is_simulation"]:
        try:
            print("[CONECTANDO] SMTP...")
            ctx = ssl.create_default_context()
            if cfg["use_ssl"]: server = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=ctx)
            else:
                server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"])
                server.starttls(context=ctx)
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            print("[CONECTADO] Pronto para envio.")
        except Exception as e: return print(f"[FALHA SMTP] {e}")
    else:
        print("[INFO] MODO SIMULAÇÃO ATIVO. Nenhum e-mail real será enviado.")


    # 4. Loop de Envio
    cnt = 0
    try:
        for i, row in enumerate(lista):
            email = row.get("Email", "").strip().lower()
            if not email or "@" not in email: continue
            
            if cfg["ignore_sent"] and email in enviados: 
                print(f"[PULADO] Já enviado (log): {email}")
                continue
            
            msg = criar_mensagem(cfg, row)
            st, err = enviar_retry(server, msg, cfg, email)
            
            registrar_log(cfg["csv_log"], {
                "timestamp": datetime.now().isoformat(),
                "nome": row.get("Nome"), "email": email,
                "status": st, "tentativa": 1, "erro": err
            })
            
            if not cfg["is_simulation"]:
                # Pausa randômica entre e-mails (apenas em modo real)
                time.sleep(random.uniform(cfg["delay_min"], cfg["delay_max"]))
                cnt += 1
                
                # Pausa por lote
                if cfg["batch_size"] > 0 and cnt >= cfg["batch_size"]:
                    print(f"[PAUSA] Lote de {cfg['batch_size']} atingido. Aguardando {cfg['batch_pause']}s...")
                    time.sleep(cfg['batch_pause'])
                    cnt = 0
                    try: server.noop() # Verifica se a conexão ainda está ativa
                    except: pass
                    
    except KeyboardInterrupt:
        print("\n[INTERROMPIDO] Processo parado pelo usuário.")
    except Exception as e:
        print(f"\n[ERRO FATAL] {e}")
    finally:
        if server: 
            try: server.quit()
            except: pass
            
        arquivo_sensivel = cfg.get("csv_input", "envio_confidencial.csv")
        print("\n" + "="*60)
        print("  SEGURANÇA DA INFORMAÇÃO: AÇÃO NECESSÁRIA")
        print("="*60)
        print(f"  O processo de envio foi finalizado.")
        print(f"  Para garantir o sigilo das eleições, por favor:")
        print(f"  REMOVA DEFINITIVAMENTE O ARQUIVO:")
        print(f"  -> {arquivo_sensivel}")
        print("="*60 + "\n")

if __name__ == "__main__":
    main()
