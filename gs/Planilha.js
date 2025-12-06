/**
 * ==============================================================================
 * SCRIPT CORE: Planilha.js
 * ==============================================================================
 * * Script Name: Planilha.js
 * Version: 1.0 (Com Validação e Apuração)
 * Date: 2025-12-06
 * * Authors:
 * - Leandro Pires Salvador (leandrosalvador@protonmail.com, leandrosalvador@gmail.com)
 * - Tiago Barreiros de Freitas (tiago4680@gmail.com)
 * * GitHub Project: https://github.com/oiceberg/eleicoes-eletronicas/
 * * Description:
 * Motor de Validação Criptográfica e Apuração do Sistema de Eleições Eletrônicas da AGESP.
 * O script atua como o Core do sistema no ambiente da nuvem, garantindo:
 * 1. Autenticidade do voto recalculando o **HMAC-SHA256**.
 * 2. Limpeza Criptográfica (substituição imediata da Chave Privada pela Chave Pública).
 * 3. Unicidade do voto (regra: o primeiro voto válido é o único contabilizado).
 * 4. Apuração em tempo real (Cálculo do Método de Borda e estatísticas).
 * * ==============================================================================
 * Gatilhos (Triggers) Configurados:
 * ==============================================================================
 * * * 1. onFormSubmit: Processa cada voto logo após a submissão, atualizando a
 * aba 'validacao_automatica' e gerando a 'Apuração'.
 * * 2. triggerApuracao: Acionado pelo gatilho 'Ao editar' na célula de flag
 * (config_automatica!A1). Este é o mecanismo de comunicação entre o Backend (Python)
 * e o Core (GAS), acionando o recálculo imediato da apuração.
 * * ==============================================================================
 * Variáveis de Configuração (Script Properties):
 * ==============================================================================
 * * * - MK: String (A Chave Mestra usada para recalcular o HMAC e validar as
 * credenciais. Deve ser idêntica à MASTER_KEY do env.toml do Python).
 * * - QTD_CANDIDATOS_EXEC: Number (Usado para definir o N_BORDA, o número máximo
 * de posições que recebem pontuação no Método de Borda, equivale ao número de
 * candidatos ao Conselho Executivo).
 * * ==============================================================================
 * TODO:
 * * - [Acompanhamento] Monitorar performance da validação com grande volume de votos.
 * * ==============================================================================
 */

// ======================================================================================
// 1. CONFIGURAÇÃO E CONSTANTES
// ======================================================================================

const SHEET_NAMES = {
  KEYS: 'Credenciais',
  RESPONSES: 'Respostas',
  VALIDATION: 'validacao_automatica',
  TALLY: 'Apuração'
};

const COL_NAMES = {
  ID: 'ID',
  PRIV_KEY: ['Chave Privada', 'Chave privada', 'chave privada', 'ChavePrivada'],
  PUB_KEY: 'Chave Pública',
  CREDENTIALS: 'Credenciais',
  VALIDITY: 'Validade',
  FISCAL_VOTE: 'Votação para o Conselho Fiscal e de Ética'
};

/**
 * Retorna a chave mestra (MK) armazenada nas Propriedades do Script.
 */
function getMasterKey() {
  const MK = PropertiesService.getScriptProperties().getProperty('MK');
  if (!MK) throw new Error('MK (Master Key) não configurada em ScriptProperties. Abortando.');
  return MK;
}


// ======================================================================================
// 2. FUNÇÕES DE SERVIÇO (UTILITY)
// ======================================================================================

/**
 * Busca valor em namedValues com suporte a múltiplos rótulos.
 */
function getFromNamedValues(namedValues, keys) {
  const safeKeys = Array.isArray(keys) ? keys : [];
  for (const k of safeKeys) {
    if (namedValues.hasOwnProperty(k)) {
      const arr = namedValues[k];
      return Array.isArray(arr) ? String(arr[0] || '').trim() : '';
    }
  }
  return '';
}

function normalizeId(id) {
  return String(id || '').trim().replace(/^'/, '');
}

function getIndexByColNameCI(headers, colName) {
  const target = String(colName).trim().toLowerCase();
  for (let i = 0; i < headers.length; i++) {
    if (String(headers[i]).trim().toLowerCase() === target) return i + 1;
  }
  return 0;
}

function writeCellByNameOrFallback(sheet, row, headers, colName, fallbackIndex1Based, value) {
  const idx = getIndexByColNameCI(headers, colName);
  const col = idx > 0 ? idx : fallbackIndex1Based;
  sheet.getRange(row, col).setValue(value);
}

function calculatePubKey(privKey, masterKey) {
  if (!privKey || !masterKey) return '';
  const bytes = Utilities.computeHmacSha256Signature(privKey, masterKey);
  return bytes.map(byte => ('0' + (byte & 0xff).toString(16)).slice(-2)).join('');
}

function parseVotos(voteString) {
  if (!voteString) return [];
  return String(voteString).split(/,\n|,/g).map(n => n.trim()).filter(n => n.length > 0);
}

function padRows(rows, width) {
  return rows.map(row => {
    const padded = [...row];
    while (padded.length < width) padded.push('');
    return padded;
  });
}


// ======================================================================================
// 3. FUNÇÕES DE SERVIÇO DE CHAVES (KEY_SERVICE)
// ======================================================================================

/**
 * Retorna mapa { ID -> {pub_key, is_active} } para TODAS as chaves ou apenas ATIVAS.
 * @param {boolean} onlyActive Se true, retorna apenas chaves ativas.
 */
function getKeysMap(onlyActive = false) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_NAMES.KEYS);
  if (!sheet) return {};

  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return {};

  const rows = sheet.getRange(2, 1, lastRow - 1, 3).getValues();
  const keyMap = {};

  for (const row of rows) {
    const idKey = normalizeId(row[0]);
    if (!idKey) continue;

    const isActive = row[2] === true || String(row[2]).toLowerCase().trim() === 'true';
    
    if (!onlyActive || isActive) {
      keyMap[idKey] = {
        pub_key: String(row[1] || '').trim(),
        is_active: isActive
      };
    }
  }
  return keyMap;
}


// ======================================================================================
// 4. PROCESSAMENTO E VALIDAÇÃO (VOTE_PROCESSING)
// ======================================================================================

/**
 * Revalida TODOS os votos na aba 'Respostas' contra as chaves ativas.
 */
function revalidateAllVotes() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const resSheet = ss.getSheetByName(SHEET_NAMES.RESPONSES);
  if (!resSheet) return;

  const allKeysData = getKeysMap(false); // Mapa completo
  const lastRow = resSheet.getLastRow();
  if (lastRow <= 1) return;

  const headers = resSheet.getRange(1, 1, 1, resSheet.getLastColumn()).getValues()[0];
  
  const ID_IDX = getIndexByColNameCI(headers, COL_NAMES.ID);
  const PUB_IDX = getIndexByColNameCI(headers, COL_NAMES.PRIV_KEY[0]);
  
  let VAL_IDX = getIndexByColNameCI(headers, COL_NAMES.CREDENTIALS);
  if (VAL_IDX <= 0) VAL_IDX = 4; // Fallback para D (Credenciais)

  if (ID_IDX <= 0 || PUB_IDX <= 0) {
    Logger.log("ERRO: Colunas 'ID' ou 'Chave Privada' (onde fica a PubKey) não encontradas. Verifique os cabeçalhos.");
    return;
  }

  const dataRange = resSheet.getRange(2, 1, lastRow - 1, headers.length);
  const responses = dataRange.getValues();
  const updates = [];

  for (const row of responses) {
    const subId = normalizeId(row[ID_IDX - 1]);
    const subPub = String(row[PUB_IDX - 1] || '').trim();
    const keyData = allKeysData[subId];
    
    let status = 'Inválidas - ID Inválido';
    if (keyData) {
      if (subPub === keyData.pub_key) {
        status = keyData.is_active ? 'Válidas' : 'Inválidas - Chave Privada Desativada';
      } else {
        status = 'Inválidas - Chave Privada Inválida';
      }
    }
    updates.push([status]);
  }

  if (updates.length > 0) {
    resSheet.getRange(2, VAL_IDX, updates.length, 1).setValues(updates);
  }
}

function processResponse_({ sheet, row, namedValues }) {
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  try {
    const MK = getMasterKey();
    const userId = normalizeId(getFromNamedValues(namedValues, [COL_NAMES.ID]));
    const privKey = getFromNamedValues(namedValues, COL_NAMES.PRIV_KEY);
    
    const calcPub = calculatePubKey(privKey, MK);
    writeCellByNameOrFallback(sheet, row, headers, COL_NAMES.PRIV_KEY[0], 3, calcPub); // Escreve PubKey na col C

    const allKeysData = getKeysMap(false);
    const keyData = allKeysData[userId];
    let status = 'Inválidas - ID Inválido';

    if (keyData) {
      if (keyData.pub_key === calcPub) {
        status = keyData.is_active ? 'Válidas' : 'Inválidas - Chave Privada Desativada';
      } else {
        status = 'Inválidas - Chave Privada Inválida';
      }
    }
    writeCellByNameOrFallback(sheet, row, headers, COL_NAMES.CREDENTIALS, 4, status);
  } catch (e) {
    writeCellByNameOrFallback(sheet, row, headers, COL_NAMES.CREDENTIALS, 4, `Inválidas - Erro Interno (${e.message})`);
  }
}


// ======================================================================================
// 5. AUDITORIA E APURAÇÃO (AUDIT_AND_TALLY)
// ======================================================================================

/**
 * Gera a aba 'validacao_automatica' com o processamento completo das regras eleitorais.
 */
function generateValidationSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const resSheet = ss.getSheetByName(SHEET_NAMES.RESPONSES);
  if (!resSheet) throw new Error(`Aba "${SHEET_NAMES.RESPONSES}" não encontrada.`);

  // 1. PREPARAÇÃO DA ABA DE VALIDAÇÃO (Limpa primeiro, sempre)
  let valSheet = ss.getSheetByName(SHEET_NAMES.VALIDATION);
  if (!valSheet) valSheet = ss.insertSheet(SHEET_NAMES.VALIDATION, 0);
  else valSheet.clear(); // AGORA LIMPA A ABA MESMO QUE NÃO HAJA RESPOSTAS
  
  const lastRow = resSheet.getLastRow();

  // 2. DEFINE E ESCREVE O CABEÇALHO (Mesmo que esteja vazio)
  const valHeaders = [
    'Carimbo de data/hora', 'ID', 'Chave Pública', 'Credenciais', 'Voto', 
    'Contador', 'Validação', 'Conselho Executivo (Ordenado)', 'Conselho Fiscal e de Ética'
  ];
  valSheet.getRange(1, 1, 1, valHeaders.length).setValues([valHeaders]).setFontWeight('bold');
  valSheet.setFrozenRows(1);
  valSheet.autoResizeColumns(1, valHeaders.length);

  // 3. SAÍDA ANTECIPADA: Sai se não há dados, mas garante que a aba foi limpa.
  if (lastRow <= 1) {
    Logger.log(`Aba '${SHEET_NAMES.VALIDATION}' limpa (sem respostas).`);
    return; 
  }

  // --- O PROCESSAMENTO DE DADOS COMEÇA AQUI ---
  const headers = resSheet.getRange(1, 1, 1, resSheet.getLastColumn()).getValues()[0];
  const allData = resSheet.getRange(2, 1, lastRow - 1, headers.length).getValues();

  // Índices (0-based)
  const IDX_ID = 1; 
  const IDX_CRED = 3;
  const IDX_PUB_KEY = 2; 
  const IDX_FISCAL = getIndexByColNameCI(headers, COL_NAMES.FISCAL_VOTE) - 1;
  
  // Range Executivo (Início após Credenciais, Fim antes de Fiscal)
  const IDX_EXEC_START = IDX_CRED + 1;
  const IDX_EXEC_END = IDX_FISCAL - 1;

  if (IDX_FISCAL < 0 || IDX_EXEC_END < IDX_EXEC_START) throw new Error('Configuração de colunas inválida.');

  const results = [];
  const validContentCounter = {}; 

  for (const row of allData) {
    const userId = normalizeId(String(row[IDX_ID] || '').trim());
    if (!userId) continue;

    const credStatus = String(row[IDX_CRED] || '').trim();
    const fiscalRaw = String(row[IDX_FISCAL] || '').trim();
    
    const execVotos = [];
    for (let j = IDX_EXEC_START; j <= IDX_EXEC_END; j++) {
      const v = String(row[j] || '').trim();
      if (v) execVotos.push(v);
    }

    const hasContent = (execVotos.length > 0 || fiscalRaw);
    const finalPreenchimento = hasContent ? 'Válido' : 'Branco';
    
    let contador = 0;
    const isCredValid = credStatus === 'Válidas';
    const isCountable = isCredValid && finalPreenchimento === 'Válido';
    
    if (isCountable) {
        validContentCounter[userId] = (validContentCounter[userId] || 0) + 1;
        contador = validContentCounter[userId];
    }
    
    let finalStatus = 'INVÁLIDO';

    if (!isCredValid) {
      finalStatus = `INVÁLIDO - Credenciais ${credStatus}`;
    } else {
      if (finalPreenchimento === 'Branco') {
        finalStatus = 'INVÁLIDO - Credenciais Válidas - Voto Branco';
      } else {
        if (contador === 1) {
          finalStatus = 'VÁLIDO - Credenciais Válidas - Voto Válido';
        } else {
          finalStatus = 'INVÁLIDO - Credenciais Válidas - Voto Repetido';
        }
      }
    }

    const execUnicos = Array.from(new Set(execVotos));
    const APURACAO_STATUS = 'VÁLIDO - Credenciais Válidas - Voto Válido';
    
    const execStr = (finalStatus === APURACAO_STATUS) ? execUnicos.join(',\n') : '';
    const fiscalStr = (finalStatus === APURACAO_STATUS) ? fiscalRaw.replace(/, /g, ',\n') : '';

    results.push([
      row[0], 
      userId, 
      String(row[IDX_PUB_KEY] || '').trim(), 
      credStatus,
      finalPreenchimento, 
      contador, 
      finalStatus, 
      execStr, 
      fiscalStr
    ]);
  }

  // 4. ESCREVE OS RESULTADOS
  if (results.length > 0) {
    valSheet.getRange(2, 1, results.length, valHeaders.length).setValues(results);
  }
  
  valSheet.getRange(1, 8, valSheet.getMaxRows(), 2).setWrap(true);
  Logger.log(`Aba '${SHEET_NAMES.VALIDATION}' gerada.`);
}

/**
 * Gera a aba 'Apuração' com os resultados de ambos os conselhos, incluindo estatísticas.
 */
function generateApuracaoAutomatica() {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const validationSheet = ss.getSheetByName(SHEET_NAMES.VALIDATION);
    const keysSheet = ss.getSheetByName(SHEET_NAMES.KEYS); 
    
    // Define o status completo de um voto que contém conteúdo válido para pontuação
    const APURACAO_STATUS = 'VÁLIDO - Credenciais Válidas - Voto Válido';

    // --- 1. Determinação da Pontuação Máxima (N_BORDA) ---
    const scriptProperties = PropertiesService.getScriptProperties();
    const maxCandidatosStr = scriptProperties.getProperty('QTD_CANDIDATOS_EXEC'); 

    let N_BORDA = 0; 

    if (maxCandidatosStr) {
        const configuredMax = parseInt(maxCandidatosStr.trim(), 10);
        if (!isNaN(configuredMax) && configuredMax > 0) {
             N_BORDA = configuredMax; 
        }
    }
    
    // --- CÁLCULO DAS ESTATÍSTICAS ---
    let credenciaisAtivas = 0;
    let votacoesValidas = 0;
    let nCandidatosExec = N_BORDA; 

    if (keysSheet) {
        const COL_IS_ACTIVE = 3; 
        const lastRowKeys = keysSheet.getLastRow();
        if (lastRowKeys > 1) {
            const activeFlags = keysSheet.getRange(2, COL_IS_ACTIVE, lastRowKeys - 1, 1).getValues();
            credenciaisAtivas = activeFlags.flat().filter(flag => String(flag).toUpperCase() === 'TRUE').length;
        }
    }
    
    if (validationSheet && validationSheet.getLastRow() > 1) {
        const COL_STATUS_VALIDATION_FULL = 7; 
        const lastRowValidation = validationSheet.getLastRow();
        const statusRange = validationSheet.getRange(2, COL_STATUS_VALIDATION_FULL, lastRowValidation - 1, 1);
        const statuses = statusRange.getValues().flat();
        votacoesValidas = statuses.filter(status => status === APURACAO_STATUS).length;
    }

    const MTPCE = credenciaisAtivas * nCandidatosExec;
    const notaDeCorte = MTPCE * 0.1;

    const statsRowsData = [
        ['Credenciais Ativas:', credenciaisAtivas],
        ['Votações Válidas Realizadas:', votacoesValidas],
        ['Candidatos ao Conselho Executivo:', nCandidatosExec],
        ['MTPCE:', MTPCE], 
        ['Nota de Corte:', notaDeCorte] 
    ];
    
    // Estas variáveis serão atualizadas com base nos dados reais
    let N_VOTOS_VOTADOS = 0; 
    let N_POSICOES_MOSTRADAS_FINAL = N_BORDA > 0 ? N_BORDA : 3;
    let N_POSICOES_MOSTRADAS = N_POSICOES_MOSTRADAS_FINAL;
    let maxColsFinal = N_POSICOES_MOSTRADAS + 2; 

    // Funções auxiliares (writeEmpty permanece inalterada)
    const writeEmpty = () => {
        let apSheet = ss.getSheetByName(SHEET_NAMES.TALLY);
        if (!apSheet) apSheet = ss.insertSheet(SHEET_NAMES.TALLY, 0);
        else apSheet.clear();
        
        const emptyData = padRows([
            ['Conselho Executivo (Pontos)'], 
            ['Candidatos', 'Pontos', ...Array.from({length:N_POSICOES_MOSTRADAS}, (_,i)=>`#${i+1}`)], 
            [''],
            ['Conselho Fiscal e de Ética (Votos)'], 
            ['Candidatos', 'Votos']
        ], maxColsFinal);
        
        apSheet.getRange(1, 1, emptyData.length, maxColsFinal).setValues(emptyData);
        // Garante alinhamento esquerdo nos títulos vazios (para transbordamento)
        apSheet.getRange('A1').setFontWeight('bold').setFontSize(14).setHorizontalAlignment('left'); 
        apSheet.getRange('A4').setFontWeight('bold').setFontSize(14).setHorizontalAlignment('left'); 
        apSheet.autoResizeColumns(1, maxColsFinal);
    };

    if (!validationSheet || validationSheet.getLastRow() <= 1) {
        writeEmpty(); return;
    }

    // Colunas G, H e I
    const COL_STATUS = 6;  
    const lastRow = validationSheet.getLastRow();
    
    // 2. Carregar dados de apuração
    const dataRangeValidation = validationSheet.getRange(2, COL_STATUS + 1, lastRow - 1, 3); 
    const validationData = dataRangeValidation.getValues();
    
    // 3. Determinação Dinâmica dos Candidatos
    const execCandidateSet = new Set();
    const fiscalCandidateSet = new Set();

    for (const row of validationData) {
        const execVotosRaw = String(row[1] || ''); 
        const fiscalVotosRaw = String(row[2] || ''); 

        if (execVotosRaw) {
            parseVotos(execVotosRaw).forEach(name => execCandidateSet.add(name));
        }
        if (fiscalVotosRaw) {
            parseVotos(fiscalVotosRaw).forEach(name => fiscalCandidateSet.add(name));
        }
    }

    const officialExecCandidates = Array.from(execCandidateSet).sort((a,b) => a.localeCompare(b, 'pt-BR'));
    const officialFiscalCandidates = Array.from(fiscalCandidateSet).sort((a,b) => a.localeCompare(b, 'pt-BR'));
    
    // ATUALIZAÇÃO E DIMENSIONAMENTO
    N_VOTOS_VOTADOS = officialExecCandidates.length; 

    if (N_BORDA === 0) {
        N_BORDA = N_VOTOS_VOTADOS;
    }
    
    N_POSICOES_MOSTRADAS_FINAL = N_BORDA;
    N_POSICOES_MOSTRADAS = N_POSICOES_MOSTRADAS_FINAL; 
    maxColsFinal = N_POSICOES_MOSTRADAS + 2; 

    if (N_VOTOS_VOTADOS === 0 && officialFiscalCandidates.length === 0) {
        writeEmpty(); 
        return;
    }

    // 4. Inicializar e Processar Estatísticas
    const execStats = new Map(); 
    const fiscalStats = new Map(); 

    for (const nome of officialExecCandidates) {
        execStats.set(nome, { pontos: 0, posCounts: Array(N_POSICOES_MOSTRADAS_FINAL).fill(0) });
    }
    for (const nome of officialFiscalCandidates) {
        fiscalStats.set(nome, 0);
    }
    
    for (const row of validationData) {
        const status = String(row[0] || '').trim();
        if (status !== APURACAO_STATUS) { 
            continue; 
        }
        
        const execVotosRaw = String(row[1] || ''); 
        const fiscalVotosRaw = String(row[2] || ''); 

        // Apuração Executivo
        const execVotosDedupe = parseVotos(execVotosRaw);
        for (let i = 0; i < execVotosDedupe.length; i++) {
            const cand = execVotosDedupe[i];
            if (!execStats.has(cand)) continue; 
            const s = execStats.get(cand);
            const pontosGanhos = N_BORDA - i; 
            s.pontos += pontosGanhos;
            if (i < N_POSICOES_MOSTRADAS_FINAL) {
                s.posCounts[i] += 1;
            }
        }
        
        // Apuração Fiscal
        const fiscalVotosDedupe = parseVotos(fiscalVotosRaw);
        for (const cand of fiscalVotosDedupe) {
            if (!fiscalStats.has(cand)) continue; 
            fiscalStats.set(cand, fiscalStats.get(cand) + 1);
        }
    }
    
    // 5. Formatar e Ordenar Resultados
    
    // Tabela Executivo
    const execHeader = ['Candidatos', 'Pontos', ...Array.from({length:N_POSICOES_MOSTRADAS_FINAL}, (_,i)=>`#${i+1}`)];
    const execRows = Array.from(execStats.entries()).map(([nome, s]) => [nome, s.pontos, ...s.posCounts]);

    execRows.sort((a, b) => {
        if (b[1] !== a[1]) return b[1] - a[1]; 
        for (let i = 2; i < 2 + N_POSICOES_MOSTRADAS_FINAL; i++) {
            if (b[i] !== a[i]) return b[i] - a[i];
        }
        return a[0].localeCompare(b[0], 'pt-BR');
    });
    
    const execTableRows = [
        ['Conselho Executivo (Pontos)'], 
        execHeader, 
        ...execRows
    ];

    // Tabela Fiscal
    const fiscalHeader = ['Candidatos', 'Votos'];
    const fiscalRows = Array.from(fiscalStats.entries())
        .map(([nome, votos]) => [nome, votos])
        .sort((a,b) => (b[1] - a[1]) || a[0].localeCompare(b[0], 'pt-BR')); 

    const fiscalTableRows = [
        ['Conselho Fiscal e de Ética (Votos)'], 
        fiscalHeader, 
        ...fiscalRows
    ];
    
    // 6. Combinar e Escrever
    const paddedExecTable = padRows(execTableRows, maxColsFinal);
    const paddedFiscalTable = padRows(fiscalTableRows, maxColsFinal);

    // BLOCO ESTATÍSTICAS
    const statsTitleRowData = ['Estatísticas da Eleição']; 
    const paddedStatsTable = padRows([
        statsTitleRowData,
        ...statsRowsData
    ], maxColsFinal);
    
    const allResults = [
        ...paddedExecTable,
        Array(maxColsFinal).fill(''), 
        ...paddedFiscalTable,
        Array(maxColsFinal).fill(''), 
        ...paddedStatsTable 
    ];

    let apuracaoSheet = ss.getSheetByName(SHEET_NAMES.TALLY);
    if (!apuracaoSheet) {
        apuracaoSheet = ss.insertSheet(SHEET_NAMES.TALLY, 0);
    } else {
        apuracaoSheet.clear();
    }

    if (allResults.length > 0) {
        const range = apuracaoSheet.getRange(1, 1, allResults.length, maxColsFinal);
        range.setValues(allResults); 
    }
    
    // 7. Formatação Final
    
    // === ALINHAMENTO GLOBAL ===
    // Coluna A (1): Esquerda
    // Colunas B em diante (2+): Centralizado
    const maxRows = apuracaoSheet.getMaxRows();
    apuracaoSheet.getRange(1, 1, maxRows, 1).setHorizontalAlignment('left');
    if (maxColsFinal > 1) {
        apuracaoSheet.getRange(1, 2, maxRows, maxColsFinal - 1).setHorizontalAlignment('center');
    }

    // Índices de Linha
    const execTitleRowIdx = 1;
    const execHeaderRowIdx = 2;
    const fiscalTitleRowIdx = paddedExecTable.length + 2;
    const fiscalHeaderRowIdx = fiscalTitleRowIdx + 1;
    const statsTitleRowIdx = paddedExecTable.length + 1 + paddedFiscalTable.length + 2; 
    
    // Formatação dos Títulos de Seção (Fonte Grande, Negrito)
    apuracaoSheet.getRange(execTitleRowIdx, 1).setFontWeight('bold').setFontSize(14);
    apuracaoSheet.getRange(fiscalTitleRowIdx, 1).setFontWeight('bold').setFontSize('14');
    apuracaoSheet.getRange(statsTitleRowIdx, 1).setFontWeight('bold').setFontSize(14);

    // Formatação dos Cabeçalhos de Tabela (Fundo Colorido)
    apuracaoSheet.getRange(execHeaderRowIdx, 1, 1, execHeader.length).setFontWeight('bold').setBackground('#d9ead3'); 
    apuracaoSheet.getRange(fiscalHeaderRowIdx, 1, 1, fiscalHeader.length).setFontWeight('bold').setBackground('#cfe2f3'); 
    
    // 🚨 CORREÇÃO DE FORMATO: Força a exibição de inteiros para as contagens e pontos.
    
    // === CONSELHO EXECUTIVO: Colunas B em diante (Pontos e Contagens de Posição) ===
    const execBodyStartRow = execHeaderRowIdx + 1;
    const execRowCount = execRows.length;
    if (execRowCount > 0 && maxColsFinal > 1) {
        // Aplica o formato de inteiro '0' para todos os resultados numéricos do Executivo
        apuracaoSheet.getRange(execBodyStartRow, 2, execRowCount, maxColsFinal - 1).setNumberFormat('0');
    }

    // === CONSELHO FISCAL: Coluna B (Votos) ===
    const fiscalBodyStartRow = fiscalHeaderRowIdx + 1;
    const fiscalRowCount = fiscalRows.length;
    if (fiscalRowCount > 0) {
        // Aplica o formato de inteiro '0' para os Votos
        apuracaoSheet.getRange(fiscalBodyStartRow, 2, fiscalRowCount, 1).setNumberFormat('0');
    }

    // === ESTATÍSTICAS: Coluna B (Valores) ===
    const statsBodyStartRow = statsTitleRowIdx + 1;
    const statsCount = statsRowsData.length;
    
    // Coluna 2 (Valores) das estatísticas: Fundo Cinza e Formato de INTEIRO
    const statsValuesRange = apuracaoSheet.getRange(statsBodyStartRow, 2, statsCount, 1);
    statsValuesRange.setBackground('#f3f3f3');
    // Formato de Inteiro '0' para Credenciais, Votações, MTPCE
    statsValuesRange.setNumberFormat('0'); 

    // Destaque Vermelho para a Nota de Corte (SOBRESCREVE o formato anterior com '0.0' para a última linha)
    const notaDeCorteRow = statsBodyStartRow + statsCount - 1;
    apuracaoSheet.getRange(notaDeCorteRow, 2).setBackground('#ffdddd').setNumberFormat('0.0'); 
    
    apuracaoSheet.autoResizeColumns(1, apuracaoSheet.getMaxColumns());

    Logger.log(`Aba '${SHEET_NAMES.TALLY}' gerada (Layout Final: Extrapolação de Título).`);
}


// ======================================================================================
// 6. FUNÇÕES DE GATILHO (ENTRY POINTS)
// ======================================================================================

function onFormSubmit(e) {
  if (!e || !e.namedValues) {
    Logger.log('Use processLastResponse() para teste manual.');
    return;
  }
  processResponse_({ sheet: e.range.getSheet(), row: e.range.getRow(), namedValues: e.namedValues });
  Utilities.sleep(1000);
  revalidateAllVotes();
  generateValidationSheet();
  generateApuracaoAutomatica();
}

function onSpreadsheetEdit(e) {
  if (e && e.range && e.range.getSheet().getName() === SHEET_NAMES.KEYS) {
    revalidateAllVotes();
    generateValidationSheet();
    generateApuracaoAutomatica();
  }
}

function processLastResponse() {
  Logger.log('Iniciando processamento manual...');
  revalidateAllVotes();
  generateValidationSheet();
  generateApuracaoAutomatica();
  Logger.log('Concluído.');
}

/**
 * A célula que o Python irá editar para acionar o gatilho.
 */
const FLAG_CELL_RANGE = "config_automatica!A1"; 

/**
 * Função principal a ser chamada pelo gatilho instalável (On Edit).
 * Verifica se a célula de flag foi editada e executa a apuração.
 * * @param {GoogleAppsScript.Events.Sheets.OnEdit} e O evento de edição.
 */
function triggerApuracao(e) {
  // Se o evento for nulo ou não for uma edição de célula, ignora.
  if (!e || !e.range) {
    return;
  }

  const range = e.range;
  const sheet = range.getSheet();
  
  // Verifica se o range editado é a célula A1 da aba config_automatica
  if (sheet.getName() === "config_automatica" && range.getA1Notation() === "A1") {
    // A célula flag foi editada!
    Logger.log("Flag detectada! Iniciando generateApuracaoAutomatica...");
    
    try {
      // Chama a função que era executada pelo Python
      generateApuracaoAutomatica(); 
      Logger.log("Apuração automática concluída com sucesso.");
    } catch (error) {
      Logger.log("ERRO CRÍTICO na Apuração: " + error.toString());
    }
  }
}