
/**
 * ================================
 *  AGESP | Apps Script (revisado e reativo)
 * ================================
 * Módulos:
 * 1) Validação de chaves (hash SHA-256) contra aba 'keys_hash'
 * 2) Conselho Executivo: método de Borda modificado
 * 3) Conselho Fiscal e de Ética: contagem de votos (ordem irrelevante)
 *
 * Convenções:
 * - Cabeçalhos na linha 1; leitura por NOME de coluna (mais robusta)
 * - Normalização de nomes: remove acentos, colapsa espaços, UPPERCASE
 * - Cédulas: aceitamos vírgula, ponto-e-vírgula ou quebra de linha entre nomes
 * - Duplicatas dentro da cédula: contam uma única vez (Executivo e Fiscal)
 *
 * Reatividade:
 * - As funções SCORECARD/POINTS/VOTES aceitam um 4º argumento opcional `faixaVotos`.
 *   Se fornecido, a função passa a depender de um Range, e o Sheets recalcula ao mudar a faixa.
 */

/* ========= 1) Validação de chaves ========= */

const KEYS_SHEET_NAME = 'keys_hash';  // aba com chave_publica (A) e hash_privada (B) em HEX maiúsculo
let __KEY_MAP_MEMO__ = null;
const KEY_CACHE_NS = 'AGESP_KEYS_HASH';
const KEY_CACHE_TTL_SEC = 60;

/** Normaliza texto da chave privada: Uppercase; remove espaços; mantém apenas A–Z */
function normalizePrivate_(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .toUpperCase()
    .replace(/\s+/g, '')
    .replace(/[^A-Z]/g, '');
}

/** SHA-256 do texto em HEX maiúsculo (aplica normalização para privada) */
function sha256Hex(text) {
  const cleaned = normalizePrivate_(text);
  if (!cleaned) return '';
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, cleaned);
  return bytes.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('').toUpperCase();
}

/** Carrega mapa chave_publica -> hash_privada com cache */
function loadKeysHashMap() {
  if (__KEY_MAP_MEMO__) return __KEY_MAP_MEMO__;
  const cache = CacheService.getScriptCache();
  const cached = cache.get(KEY_CACHE_NS);
  if (cached) {
    try { __KEY_MAP_MEMO__ = JSON.parse(cached); return __KEY_MAP_MEMO__; } catch (_) {}
  }

  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(KEYS_SHEET_NAME);
  if (!sh) throw new Error(`Aba '${KEYS_SHEET_NAME}' não encontrada.`);
  const lastRow = sh.getLastRow();
  if (lastRow < 2) { __KEY_MAP_MEMO__ = {}; return __KEY_MAP_MEMO__; }

  const values = sh.getRange(2, 1, lastRow - 1, 2).getValues(); // A:B
  const map = {};
  for (let i = 0; i < values.length; i++) {
    const pub  = String(values[i][0] || '').trim();
    const hash = String(values[i][1] || '').trim().toUpperCase();
    if (pub) map[pub] = hash;
  }
  __KEY_MAP_MEMO__ = map;
  try { cache.put(KEY_CACHE_NS, JSON.stringify(map), KEY_CACHE_TTL_SEC); } catch (_) {}
  return map;
}

/** Funções custom para usar em célula */
function VALIDAR_CHAVES(pub, priv) {
  const p = String(pub || '').trim();
  const s = String(priv || '').trim();
  if (!p || !s) return 'INVÁLIDO';
  const computed = sha256Hex(s);
  const expected = loadKeysHashMap()[p] || '';
  return (computed && expected && computed === expected) ? 'VÁLIDO' : 'INVÁLIDO';
}
function EXPECTED_HASH(pub) {
  const p = String(pub || '').trim();
  return loadKeysHashMap()[p] || '';
}
function HASH_SHA256(input) {
  return sha256Hex(input);
}
function VALIDAR_CHAVES_DEBUG(pub, priv) {
  const computed = sha256Hex(priv);
  const expected = EXPECTED_HASH(pub);
  return computed + ' | ' + expected;
}

/* ========= Helpers comuns para votação ========= */

function norm(x) {
  return String(x || '')
    .normalize('NFKC')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .trim()
    .replace(/\s+/g, ' ')
    .toUpperCase();
}

/** Aceita vírgula, ponto-e-vírgula ou quebra de linha */
function parseList(cell) {
  if (!cell) return [];
  const parts = String(cell).split(/[;,]\s*|\n+/);
  return parts.map(s => norm(s)).filter(s => s);
}

/** Remove duplicatas preservando a primeira ocorrência e a ordem (por cédula) */
function dedupePreserve(arr) {
  const seen = new Set();
  const out = [];
  for (const a of arr) {
    if (!seen.has(a)) { seen.add(a); out.push(a); }
  }
  return out;
}

/** Leitura por cabeçalho (linha 1) */
function readColumnByHeader(sheetName, headerName) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sh = ss.getSheetByName(String(sheetName));
  if (!sh) throw new Error(`Aba '${sheetName}' não encontrada.`);
  const headerRow = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0];
  const target = norm(headerName);
  let colIdx = -1;
  for (let c = 0; c < headerRow.length; c++) {
    if (norm(headerRow[c]) === target) { colIdx = c + 1; break; }
  }
  if (colIdx === -1) throw new Error(`Cabeçalho '${headerName}' não encontrado na linha 1 da aba '${sheetName}'.`);
  const lastRow = sh.getLastRow();
  const valores = lastRow > 1 ? sh.getRange(2, colIdx, lastRow - 1, 1).getValues().map(r => r[0]) : [];
  return { sheet: sh, colIdx, valores };
}

/** Leitura por letra (compatibilidade) */
function letterToIndex(letter) {
  letter = String(letter).trim().toUpperCase();
  let idx = 0;
  for (let i = 0; i < letter.length; i++) idx = idx * 26 + (letter.charCodeAt(i) - 64);
  return idx;
}
function readColumnByLetter(sheetName, letterCol) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sh = ss.getSheetByName(String(sheetName));
  if (!sh) throw new Error(`Aba '${sheetName}' não encontrada.`);
  const colIdx = letterToIndex(letterCol);
  const lastRow = sh.getLastRow();
  const valores = lastRow > 1 ? sh.getRange(2, colIdx, lastRow - 1, 1).getValues().map(r => r[0]) : [];
  return { sheet: sh, colIdx, valores };
}

/** Conjunto de candidatos oficiais (normalizados) a partir do intervalo passado */
function buildOfficialSet(intervaloCandidatos) {
  const set = new Set();
  if (intervaloCandidatos == null) return set;
  const m = Array.isArray(intervaloCandidatos) ? intervaloCandidatos : [[intervaloCandidatos]];
  for (let i = 0; i < m.length; i++) {
    for (let j = 0; j < m[i].length; j++) {
      const nome = norm(m[i][j]);
      if (nome) set.add(nome);
    }
  }
  return set;
}

/** Universo: oficial (se fornecido) ou inferido pelas cédulas */
function resolveUniverse(intervaloCandidatos, celulas) {
  const oficialSet = buildOfficialSet(intervaloCandidatos);
  if (oficialSet.size > 0) return { oficialSet, n: oficialSet.size, source: 'oficial' };
  for (const cel of celulas) for (const nome of parseList(cel)) oficialSet.add(nome);
  return { oficialSet, n: oficialSet.size, source: 'inferido' };
}
function resolveUniverseFiscal(intervaloCandidatos, celulas) {
  const oficialSet = buildOfficialSet(intervaloCandidatos);
  if (oficialSet.size > 0) return { oficialSet, source: 'oficial' };
  for (const cel of celulas) for (const nome of parseList(cel)) oficialSet.add(nome);
  return { oficialSet, source: 'inferido' };
}

/* ========= 2) Conselho Executivo — Método de Borda ========= */
/**
 * BORDA_POINTS_BY_COLNAME(candidato, nomeDaAba, nomeColuna, [faixaVotos], [intervaloCandidatos])
 * Soma a pontuação do candidato pelo método de Borda modificado.
 * n = # de candidatos (oficial, se fornecido; senão inferido das cédulas).
 *
 * Assinatura reativa:
 *   - Se `faixaVotos` for fornecido (Range/array), ele é usado como fonte.
 *   - `intervaloCandidatos` continua opcional (define universo oficial).
 *
 * Uso (Sheets pt-BR; ';'):
 *   =BORDA_POINTS_BY_COLNAME(A2; "Validação Chaves"; "Conselho Executivo"; 'Validação Chaves'!I2:I; 'Conselho Executivo'!A2:A)
 *   ou (sem faixaVotos):
 *   =BORDA_POINTS_BY_COLNAME(A2; "Validação Chaves"; "Conselho Executivo"; ; 'Conselho Executivo'!A2:A)
 */
function BORDA_POINTS_BY_COLNAME(candidato, nomeDaAba, nomeColuna, faixaVotos, intervaloCandidatos) {
  const alvo = norm(candidato);
  const valores = readVotesOrHeader(nomeDaAba, nomeColuna, faixaVotos);
  const { oficialSet, n, source } = resolveUniverse(intervaloCandidatos, valores);
  if (!n) return 0;

  let total = 0;
  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    for (let i = 0; i < lista.length; i++) {
      if (lista[i] === alvo) { total += (n - i); break; }
    }
  }
  return total;
}

/**
 * BORDA_SCORECARD_BY_COLNAME(nomeDaAba, nomeColuna, [faixaVotos], [intervaloCandidatos])
 * Placar: [Candidato | Pontos | 1ªs | 2ªs | ...], ordenado por pontos desc,
 * depois # de 1ªs, 2ªs, ..., e por fim nome asc.
 *
 * Uso:
 *   =BORDA_SCORECARD_BY_COLNAME("Validação Chaves"; "Conselho Executivo"; 'Validação Chaves'!I2:I; 'Conselho Executivo'!A2:A)
 *   ou (sem faixaVotos):
 *   =BORDA_SCORECARD_BY_COLNAME("Validação Chaves"; "Conselho Executivo"; ; 'Conselho Executivo'!A2:A)
 */
function BORDA_SCORECARD_BY_COLNAME(nomeDaAba, nomeColuna, faixaVotos, intervaloCandidatos) {
  const valores = readVotesOrHeader(nomeDaAba, nomeColuna, faixaVotos);
  const { oficialSet, n, source } = resolveUniverse(intervaloCandidatos, valores);
  if (!n) return [['Candidato','Pontos']];

  const stats = new Map(); // nome -> { pontos, posCounts[] }
  for (const nome of oficialSet) stats.set(nome, { pontos: 0, posCounts: Array(n).fill(0) });

  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);

    for (let i = 0; i < lista.length; i++) {
      const cand = lista[i];
      if (!stats.has(cand)) stats.set(cand, { pontos: 0, posCounts: Array(n).fill(0) });
      const s = stats.get(cand);
      s.pontos += (n - i);
      if (i < n) s.posCounts[i] += 1;
    }
  }

  const header = ['Candidato','Pontos', ...Array.from({length:n}, (_,i)=>`#${i+1}`)];
  const rows = Array.from(stats.entries()).map(([nome, s]) => [nome, s.pontos, ...s.posCounts]);

  rows.sort((a,b) => {
    if (b[1] !== a[1]) return b[1]-a[1];
    for (let i=2; i<2+n; i++) if (b[i] !== a[i]) return b[i]-a[i];
    return a[0].localeCompare(b[0], 'pt-BR');
  });

  return [header, ...rows];
}

/* Compatibilidade: por LETRA (aceitam 4º argumento reativo `faixaVotos`) */
function BORDA_POINTS(candidato, nomeDaAba, letraColuna, faixaVotos, intervaloCandidatos) {
  const alvo = norm(candidato);
  const valores = readVotesOrLetter(nomeDaAba, letraColuna, faixaVotos);
  const { oficialSet, n, source } = resolveUniverse(intervaloCandidatos, valores);
  if (!n) return 0;

  let total = 0;
  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    for (let i = 0; i < lista.length; i++) {
      if (lista[i] === alvo) { total += (n - i); break; }
    }
  }
  return total;
}
function BORDA_SCORECARD(nomeDaAba, letraColuna, faixaVotos, intervaloCandidatos) {
  const valores = readVotesOrLetter(nomeDaAba, letraColuna, faixaVotos);
  const { oficialSet, n, source } = resolveUniverse(intervaloCandidatos, valores);
  if (!n) return [['Candidato','Pontos']];

  const stats = new Map();
  for (const nome of oficialSet) stats.set(nome, { pontos: 0, posCounts: Array(n).fill(0) });

  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    for (let i = 0; i < lista.length; i++) {
      const cand = lista[i];
      if (!stats.has(cand)) stats.set(cand, { pontos: 0, posCounts: Array(n).fill(0) });
      const s = stats.get(cand);
      s.pontos += (n - i);
      if (i < n) s.posCounts[i] += 1;
    }
  }

  const header = ['Candidato','Pontos', ...Array.from({length:n}, (_,i)=>`${i+1}ªs`)];
  const rows = Array.from(stats.entries()).map(([nome, s]) => [nome, s.pontos, ...s.posCounts]);

  rows.sort((a,b) => {
    if (b[1] !== a[1]) return b[1]-a[1];
    for (let i=2; i<2+n; i++) if (b[i] !== a[i]) return b[i]-a[i];
    return a[0].localeCompare(b[0], 'pt-BR');
  });
  return [header, ...rows];
}

/* ========= 3) Conselho Fiscal e de Ética — Votos ========= */
/**
 * FISCAL_VOTES_BY_COLNAME(candidato, nomeDaAba, nomeColuna, [faixaVotos], [intervaloCandidatos])
 * Total de votos do candidato (máx. 1 por cédula; ordem irrelevante).
 *
 * Uso:
 *   =FISCAL_VOTES_BY_COLNAME(A2; "Validação Chaves"; "Conselho Fiscal e de Ética"; 'Validação Chaves'!K2:K; 'Conselho Fiscal'!A2:A)
 *   ou:
 *   =FISCAL_VOTES_BY_COLNAME(A2; "Validação Chaves"; "Conselho Fiscal e de Ética"; ; 'Conselho Fiscal'!A2:A)
 */
function FISCAL_VOTES_BY_COLNAME(candidato, nomeDaAba, nomeColuna, faixaVotos, intervaloCandidatos) {
  const alvo = norm(candidato);
  const valores = readVotesOrHeader(nomeDaAba, nomeColuna, faixaVotos);
  const { oficialSet, source } = resolveUniverseFiscal(intervaloCandidatos, valores);

  let total = 0;
  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    if (lista.includes(alvo)) total += 1;
  }
  return total;
}

/**
 * FISCAL_SCORECARD_BY_COLNAME(nomeDaAba, nomeColuna, [faixaVotos], [intervaloCandidatos])
 * Placar: [Candidato | Votos], ordenado por votos desc e nome asc.
 *
 * Uso:
 *   =FISCAL_SCORECARD_BY_COLNAME("Validação Chaves"; "Conselho Fiscal e de Ética"; 'Validação Chaves'!K2:K; 'Conselho Fiscal'!A2:A)
 *   ou:
 *   =FISCAL_SCORECARD_BY_COLNAME("Validação Chaves"; "Conselho Fiscal e de Ética"; ; 'Conselho Fiscal'!A2:A)
 */
function FISCAL_SCORECARD_BY_COLNAME(nomeDaAba, nomeColuna, faixaVotos, intervaloCandidatos) {
  const valores = readVotesOrHeader(nomeDaAba, nomeColuna, faixaVotos);
  const { oficialSet, source } = resolveUniverseFiscal(intervaloCandidatos, valores);

  if (oficialSet.size === 0 && valores.length === 0) return [['Candidato','Votos']];

  const stats = new Map(); // nome -> votos
  for (const nome of oficialSet) stats.set(nome, 0);

  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    for (const cand of lista) {
      if (!stats.has(cand)) stats.set(cand, 0);
      stats.set(cand, stats.get(cand) + 1);
    }
  }

  const rows = Array.from(stats.entries())
    .map(([nome, votos]) => [nome, votos])
    .sort((a,b) => (b[1]-a[1]) || a[0].localeCompare(b[0], 'pt-BR'));

  return [['Candidato','Votos'], ...rows];
}

/* Compatibilidade: por LETRA (aceitam 4º argumento reativo `faixaVotos`) */
function FISCAL_VOTES(candidato, nomeDaAba, letraColuna, faixaVotos, intervaloCandidatos) {
  const alvo = norm(candidato);
  const valores = readVotesOrLetter(nomeDaAba, letraColuna, faixaVotos);
  const { oficialSet, source } = resolveUniverseFiscal(intervaloCandidatos, valores);
  let total = 0;
  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    if (lista.includes(alvo)) total += 1;
  }
  return total;
}
function FISCAL_SCORECARD(nomeDaAba, letraColuna, faixaVotos, intervaloCandidatos) {
  const valores = readVotesOrLetter(nomeDaAba, letraColuna, faixaVotos);
  const { oficialSet, source } = resolveUniverseFiscal(intervaloCandidatos, valores);

  if (oficialSet.size === 0 && valores.length === 0) return [['Candidato','Votos']];

  const stats = new Map();
  for (const nome of oficialSet) stats.set(nome, 0);

  for (const cel of valores) {
    const listaRaw = parseList(cel);
    const base = source === 'oficial' ? listaRaw.filter(nm => oficialSet.has(nm)) : listaRaw;
    const lista = dedupePreserve(base);
    for (const cand of lista) {
      if (!stats.has(cand)) stats.set(cand, 0);
      stats.set(cand, stats.get(cand) + 1);
    }
  }

  const rows = Array.from(stats.entries())
    .map(([nome, votos]) => [nome, votos])
    .sort((a,b) => (b[1]-a[1]) || a[0].localeCompare(b[0], 'pt-BR'));

  return [['Candidato','Votos'], ...rows];
}

/* ========= 4) Helpers de leitura reativa ========= */

/**
 * Se `faixaVotos` for fornecido (Range/matriz), usa-o; senão, lê pelo cabeçalho.
 * Permite que funções personalizadas dependam de Range para recalcular automaticamente.
 */
function readVotesOrHeader(nomeDaAba, nomeColuna, faixaVotos) {
  if (faixaVotos != null) {
    // Espera-se uma coluna: [[cel],[cel],...]
    const arr = Array.isArray(faixaVotos) ? faixaVotos : [[faixaVotos]];
    return arr.map(r => r[0]);
  }
  return readColumnByHeader(nomeDaAba, nomeColuna).valores;
}

function readVotesOrLetter(nomeDaAba, letraColuna, faixaVotos) {
  if (faixaVotos != null) {
    const arr = Array.isArray(faixaVotos) ? faixaVotos : [[faixaVotos]];
    return arr.map(r => r[0]);
  }
  return readColumnByLetter(nomeDaAba, letraColuna).valores;
}
