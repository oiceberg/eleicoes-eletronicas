#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
PROJETO: SISTEMA DE ELEIÇÕES ELETRÔNICAS DA AGESP
ARQUIVO: keys_generator.py
VERSÃO:  1.0.0 (Lançamento Inicial no GitHub)
AUTOR:   Leandro Salvador <leandrosalvador@gmail.com>
DATA:    2025-11-23

DESCRIÇÃO:
    Módulo essencial para a segurança eleitoral. Gera pares de chaves criptográficas
    determinísticas (Pública e Privada) a partir da lista base de eleitores,
    garantindo o **desacoplamento** da identidade do eleitor e seu voto.

    O script cria os arquivos necessários para a distribuição sigilosa e para a
    auditoria pública do processo de votação, utilizando o princípio do HASH
    para validação do voto sem expor a chave privada.

ENTRADAS:
    -> data/eleitores_base.csv (Lista inicial de eleitores: Nome Completo;Endereço de e-mail)

SAÍDAS GERADAS (Quatro Arquivos Principais):
    1. data/envio_confidencial.csv (SIGILOSO): Nome, Email, Chave Pública, Chave Privada. (ENTRADA DO MAILER)
    2. data/keys_hash.csv (SISTEMA/AUDITORIA): Chave Pública e Hash da Chave Privada. (IMPORTAR PARA PLANILHA)
    3. data/lista_eleitores_aptos.csv (PÚBLICO): Lista de Nomes (Auditoria).
    4. data/lista_chaves_validas.csv (PÚBLICO): Lista de Chaves Públicas (Auditoria).

DEPENDÊNCIAS:
    pip install pandas
=============================================================================
"""

import os
import sys
import csv
import hmac
import hashlib
import base64
from io import StringIO
import pandas as pd

# =============================================================================
# 1. CARREGAMENTO DE AMBIENTE
# =============================================================================
def load_env(env_path=".env"):
    if not os.path.exists(env_path):
        print(f"[AVISO] {env_path} não encontrado. Usando variáveis do sistema.")
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()

load_env()

# =============================================================================
# 2. CONFIGURAÇÕES
# =============================================================================
print("== GERADOR DE CHAVES ==")

# Variáveis de Configuração Essenciais
MASTER_SECRET = os.getenv("MASTER_SECRET", "")
ELECTION_SALT = os.getenv("ELECTION_SALT", "ELEICAO_PADRAO")
PRIVATE_LEN   = int(os.getenv("PRIVATE_LEN", "12"))
DATA_FOLDER   = "data/"
INPUT_CSV_BASENAME = os.getenv("INPUT_CSV", "eleitores_base.csv")

# --- 1. Determinação do Caminho de Entrada ---
# Define os caminhos possíveis
FILE_INPUT_REAL    = DATA_FOLDER + INPUT_CSV_BASENAME
FILE_INPUT_EXAMPLE = FILE_INPUT_REAL + ".example"
input_path = "" # Variável que será usada para ler o CSV

# Lógica de fallback: Prioriza o arquivo real, senão usa o exemplo
if not os.path.exists(FILE_INPUT_REAL):
    if os.path.exists(FILE_INPUT_EXAMPLE):
        print(f"[AVISO] Arquivo '{INPUT_CSV_BASENAME}' não encontrado.")
        print(f"[AVISO] Usando o arquivo de exemplo: '{FILE_INPUT_EXAMPLE}'")
        input_path = FILE_INPUT_EXAMPLE
    else:
        # Se nem o real nem o exemplo existirem, encerra o script
        sys.exit(f"[ERRO CRÍTICO] Arquivo de entrada '{FILE_INPUT_REAL}' (e seu exemplo) não encontrado. Crie um dos dois.")
else:
    # Se o arquivo real existir, usa ele.
    input_path = FILE_INPUT_REAL

print(f"[INFO] Lendo dados de {input_path}...")

# --- 2. Nomes de Arquivos de Saída (sem alteração) ---
FILE_MAILER      = DATA_FOLDER + "envio_confidencial.csv"
FILE_PUBLIC_LIST = DATA_FOLDER + "lista_eleitores_aptos.csv"
FILE_PUBLIC_KEYS = DATA_FOLDER + "lista_chaves_validas.csv"
FILE_SHEET_HASH  = DATA_FOLDER + "keys_hash.csv"

# --- 3. Validação de Segurança (Mantida) ---
if not MASTER_SECRET:
    sys.exit("[ERRO CRÍTICO] MASTER_SECRET não definido no arquivo .env!")

# =============================================================================
# 3. LÓGICA CRIPTOGRÁFICA
# =============================================================================
def norm_email(s): return (s or "").strip().lower()

def hmac_sha256(secret: str, msg: str) -> bytes:
    key_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()

def material_derivacao(email: str) -> bytes:
    return hmac_sha256(MASTER_SECRET, f"{ELECTION_SALT}:{norm_email(email)}")

def gerar_chave_publica(email: str) -> str:
    """Gera ID numérico de 6 dígitos."""
    dig = material_derivacao(email)
    num = int.from_bytes(dig[:8], "big")
    val = (num % 900_000) + 100_000
    return f"{val:06d}"

def gerar_chave_privada(email: str, length=12) -> str:
    """Gera senha alfanumérica."""
    dig = material_derivacao(email)
    b32 = base64.b32encode(dig).decode("ascii")
    letters = [ch for ch in b32 if "A" <= ch <= "Z"]
    i = 0
    while len(letters) < length:
        extra_msg = f"{norm_email(email)}|{ELECTION_SALT}|{i}"
        extra_dig = hmac_sha256(MASTER_SECRET, extra_msg)
        b32x = base64.b32encode(extra_dig).decode("ascii")
        letters.extend([ch for ch in b32x if "A" <= ch <= "Z"])
        i += 1
    return "".join(letters[:length])

def hash_sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()

# =============================================================================
# 4. UTILITÁRIOS E PANDAS
# =============================================================================
def ler_csv_robusto(path):
    if not os.path.exists(path): sys.exit(f"[ERRO] Entrada não encontrada: {path}")
    raw_bytes = b""
    with open(path, "rb") as f: raw_bytes = f.read()
    encodings = ["utf-8-sig", "cp1252", "latin-1", "utf-8"]
    for enc in encodings:
        try: return raw_bytes.decode(enc)
        except UnicodeDecodeError: continue
    return raw_bytes.decode("utf-8", errors="replace")

def detectar_delimitador(texto):
    line = texto.split('\n')[0]
    return ';' if line.count(';') >= line.count(',') else ','

def salvar_dataframe_excel_friendly(df: pd.DataFrame, path: str, rename_cols: dict = None):
    df_to_save = df.copy()
    if rename_cols: df_to_save.rename(columns=rename_cols, inplace=True)
    df_to_save.to_csv(path, sep=';', encoding='utf-8-sig', decimal=',', index=False)
    print(f"[SUCESSO] Gerado: {path}")

# =============================================================================
# 5. EXECUÇÃO
# =============================================================================
def main():
    conteudo = ler_csv_robusto(input_path)
    delim = detectar_delimitador(conteudo)
    reader = csv.DictReader(StringIO(conteudo), delimiter=delim)
    
    registros = []
    
    def get_val(row, *keys):
        for k in keys:
            if k in row and row[k]: return row[k].strip()
        return ""

    for row in reader:
        nome  = get_val(row, "Nome Completo", "nome_completo", "nome")
        email = get_val(row, "Endereço de e-mail", "endereco_email", "email")
        if not nome or not email: continue
            
        pub = gerar_chave_publica(email)
        priv = gerar_chave_privada(email, PRIVATE_LEN)
        
        registros.append({
            "nome_completo": nome,
            "endereco_email": email,
            "chave_publica": pub,
            "chave_privada": priv,
            "hash_privada": hash_sha256_hex(priv)
        })

    if not registros: sys.exit("[ERRO] Nenhum registro processado.")
    print(f"[INFO] {len(registros)} eleitores processados.")

    # DataFrames base
    df_base = pd.DataFrame(registros)
    
    # 1. ENVIO (Para o Mailer) - Contém TUDO
    df_mailer = df_base[["nome_completo", "endereco_email", "chave_publica", "chave_privada"]].sort_values("chave_publica")
    
    # 2. LISTA PÚBLICA (Nomes e E-mail para Auditoria)
    df_public_voters = df_base[["nome_completo", "endereco_email"]].sort_values("nome_completo")
    
    # 3. CHAVES VÁLIDAS (Para Auditoria da Urna)
    df_public_keys = df_base[["chave_publica"]].sort_values("chave_publica")
    
    # 4. VALIDAÇÃO (Para o Sheets)
    df_sheet = df_base[["chave_publica", "hash_privada"]].sort_values("chave_publica")

    print("-" * 40)
    
    # AQUI ESTÁ A PADRONIZAÇÃO DOS CABEÇALHOS:
    
    salvar_dataframe_excel_friendly(df_mailer, FILE_MAILER, rename_cols={
        "nome_completo": "Nome",
        "endereco_email": "Email",
        "chave_publica": "Chave Pública",  # Termo Oficial
        "chave_privada": "Chave Privada"   # Termo Oficial
    })
    
    salvar_dataframe_excel_friendly(df_public_voters, FILE_PUBLIC_LIST, rename_cols={
        "nome_completo": "Nome Completo",
        "endereco_email": "Email"
    })
    
    salvar_dataframe_excel_friendly(df_public_keys, FILE_PUBLIC_KEYS, rename_cols={
        "chave_publica": "Chave Pública"   # Termo Oficial
    })

    salvar_dataframe_excel_friendly(df_sheet, FILE_SHEET_HASH, rename_cols={
        "chave_publica": "Chave Pública",
        "hash_privada": "Hash Privada"
    })

    print("-" * 40)
    print("Processo concluído com sucesso.")

if __name__ == "__main__":
    main()
