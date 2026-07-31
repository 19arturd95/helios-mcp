/**
 * Helios Drive Adapter — Google Apps Script Web App.
 *
 * Jedyny komponent, który dotyka Google Drive. Wywoływany wyłącznie przez
 * Helios MCP podpisanymi żądaniami HMAC. Wszystkie operacje działają w obrębie
 * ROOT_FOLDER_ID i za każdym razem potwierdzają, że plik jest jego potomkiem.
 *
 * Script Properties (Ustawienia projektu → Właściwości skryptu):
 *   ROOT_FOLDER_ID   — ID folderu głównego "helios" na Drive.
 *   SHARED_SECRET    — wspólny sekret HMAC (identyczny z APPS_SCRIPT_SECRET w MCP).
 *
 * Zasady bezpieczeństwa:
 *   - odrzuca żądania starsze niż 5 minut (okno ±300 s),
 *   - odrzuca ponownie użyte nonce (CacheService, check-and-set atomowy przez LockService),
 *   - odrzuca nieprawidłowy podpis HMAC (porównanie w czasie stałym),
 *   - blokuje ścieżki absolutne, "..", traversal, "%", "\", znaki sterujące,
 *   - obsługuje wyłącznie operacje odczytu notatek oraz `consumeAuthCode`,
 *   - limity listTree/search (liczba węzłów, liczba odczytów treści, liczba wyników),
 *   - nie loguje treści notatek, nie zwraca sekretów w błędach,
 *   - brak trwałego usuwania, brak zmian uprawnień, brak udostępniania.
 *
 * `consumeAuthCode` — jednorazowe zużycie kodu autoryzacyjnego OAuth (MCP):
 * atomowy check-and-set przez LockService + PropertiesService (przechowuje
 * WYŁĄCZNIE jti + czas wygaśnięcia, nigdy sam kod/token). To stan bezpieczeństwa
 * OAuth, niezależny od odczytu notatek. CacheService/PropertiesService
 * wystarczają dla modelu ryzyka Fazy 1
 * (pojedynczy użytkownik, niski wolumen); Faza 2 (zapis) będzie wymagać
 * trwalszego mechanizmu idempotencji operacji zapisu (patrz docs/PLAN.md).
 */

var MAX_SKEW_SECONDS = 300;
var ALLOWED_EXTENSIONS = ['.md'];

// Limity kosztu listTree/search — chronią przed DoS przez wyliczanie całego Drive.
var MAX_TREE_NODES = 500;       // maksymalna liczba węzłów (folderów+plików) w drzewie
var MAX_SEARCH_SCAN = 800;      // maksymalna liczba plików przejrzanych (nazwa) w search
var MAX_SEARCH_CONTENT_READS = 200; // maksymalna liczba odczytów TREŚCI pliku w search
var MAX_RESPONSE_BYTES = 200 * 1024;
var MAX_NOTE_BYTES = MAX_RESPONSE_BYTES; // pojedynczy odczyt nie może zwrócić dowolnie dużego pliku
var MAX_SEARCH_CONTENT_BYTES = 2 * 1024 * 1024; // łączny budżet treści jednego wyszukiwania

var READ_OPS = { status: true, listTree: true, search: true, read: true };
// Operacje "meta" (bezpieczeństwo OAuth) — nie modyfikują vaulta Helios.
var META_OPS = { consumeAuthCode: true };
var AUTH_CODE_PROP_PREFIX = 'authcode:';

// ---------------------------------------------------------------------------
// Wejście HTTP
// ---------------------------------------------------------------------------

function doGet() {
  return jsonOut_({ ok: true, service: 'Helios Drive Adapter' });
}

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonOut_({ ok: false, error: 'Brak treści żądania.', code: 'no_body' });
    }
    var envelope;
    try {
      envelope = JSON.parse(e.postData.contents);
    } catch (parseErr) {
      return jsonOut_({ ok: false, error: 'Treść nie jest prawidłowym JSON-em.', code: 'bad_json' });
    }

    var props = PropertiesService.getScriptProperties();
    var secret = props.getProperty('SHARED_SECRET');
    if (!secret) {
      return jsonOut_({ ok: false, error: 'Adapter nie jest skonfigurowany.', code: 'config' });
    }

    var deps = {
      secret: secret,
      now: function () { return Math.floor(Date.now() / 1000); },
      hmacBase64: hmacBase64_,
      cacheGet: cacheGet_,
      cachePut: cachePut_,
      maxSkewSeconds: MAX_SKEW_SECONDS
    };

    var verified = verifyEnvelope_(envelope, deps);
    if (!verified.ok) {
      return jsonOut_({ ok: false, error: verified.error, code: verified.code });
    }

    var request = JSON.parse(verified.payload);
    var result = dispatch_(request, props);
    return jsonOut_({ ok: true, result: result });
  } catch (err) {
    // Bez stack trace i bez treści notatek w odpowiedzi.
    return jsonOut_({ ok: false, error: safeMessage_(err), code: 'error' });
  }
}

function jsonOut_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}

function safeMessage_(err) {
  var msg = err && err.message ? String(err.message) : 'Błąd wewnętrzny.';
  // Nigdy nie zwracamy sekretu.
  return msg.length > 300 ? msg.substring(0, 300) : msg;
}

// ---------------------------------------------------------------------------
// Weryfikacja koperty (podpis + czas + nonce)
// ---------------------------------------------------------------------------

function canonicalString_(timestamp, nonce, payload) {
  return String(timestamp) + '\n' + String(nonce) + '\n' + String(payload);
}

function constantTimeEqual_(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Weryfikuje kopertę. `deps` wstrzykuje zależności (crypto/cache/czas),
 * dzięki czemu funkcję można testować w Node bez środowiska Google.
 * Zwraca { ok:true, payload } albo { ok:false, error, code }.
 */
function verifyEnvelope_(envelope, deps) {
  if (!envelope || typeof envelope !== 'object') {
    return { ok: false, error: 'Nieprawidłowa koperta.', code: 'invalid_envelope' };
  }
  var ts = envelope.timestamp;
  var nonce = envelope.nonce;
  var payload = envelope.payload;
  var signature = envelope.signature;

  if (typeof ts !== 'number' || typeof nonce !== 'string' ||
      typeof payload !== 'string' || typeof signature !== 'string') {
    return { ok: false, error: 'Nieprawidłowe pola koperty.', code: 'invalid_envelope' };
  }

  var now = deps.now();
  var skew = deps.maxSkewSeconds || MAX_SKEW_SECONDS;
  if (Math.abs(now - ts) > skew) {
    return { ok: false, error: 'Żądanie poza dozwolonym oknem czasu.', code: 'stale' };
  }

  var expected = deps.hmacBase64(deps.secret, canonicalString_(ts, nonce, payload));
  if (!constantTimeEqual_(expected, signature)) {
    return { ok: false, error: 'Nieprawidłowy podpis.', code: 'bad_signature' };
  }

  // Ochrona przed powtórzeniem — dopiero po weryfikacji podpisu.
  // Check-and-set musi być atomowy: LockService serializuje równoległe
  // żądania, żeby dwa wywołania z tym samym nonce nie mogły obie przejść
  // weryfikacji przed zapisaniem go w cache (TOCTOU).
  var nonceKey = 'nonce:' + nonce;
  var lock = LockService.getScriptLock();
  lock.waitLock(5000);
  try {
    if (deps.cacheGet(nonceKey)) {
      return { ok: false, error: 'Nonce został już użyty.', code: 'replay' };
    }
    deps.cachePut(nonceKey, '1', skew * 2);
  } finally {
    lock.releaseLock();
  }

  return { ok: true, payload: payload };
}

function hmacBase64_(secret, message) {
  var raw = Utilities.computeHmacSha256Signature(message, secret, Utilities.Charset.UTF_8);
  return Utilities.base64Encode(raw);
}

function cacheGet_(key) {
  return CacheService.getScriptCache().get(key);
}

function cachePut_(key, value, ttlSeconds) {
  CacheService.getScriptCache().put(key, value, ttlSeconds);
}

// ---------------------------------------------------------------------------
// Walidacja ścieżek (lustro lib/security/paths.ts)
// ---------------------------------------------------------------------------

function pathSafe_(raw, opts) {
  opts = opts || {};
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new Error('Ścieżka jest pusta lub nie jest tekstem.');
  }
  if (raw.length > 1024) throw new Error('Ścieżka jest zbyt długa.');
  if (/[\u0000-\u001F\u007F]/.test(raw)) throw new Error('Ścieżka zawiera znaki sterujące.');
  if (raw.indexOf('\\') !== -1) throw new Error('Ukośnik wsteczny jest niedozwolony.');
  if (raw.indexOf('%') !== -1) throw new Error('Znak "%" jest niedozwolony.');

  var normalized = raw.normalize ? raw.normalize('NFC') : raw;
  if (normalized.charAt(0) === '/') throw new Error('Ścieżki absolutne są niedozwolone.');
  if (/^[a-zA-Z]:[\\/]/.test(normalized)) throw new Error('Ścieżki absolutne są niedozwolone.');

  var segments = normalized.split('/');
  var clean = [];
  for (var i = 0; i < segments.length; i++) {
    var seg = segments[i];
    if (seg === '' || seg === '.') continue;
    if (seg === '..') throw new Error('Path traversal jest niedozwolony.');
    if (seg !== seg.trim() || seg.trim().length === 0) {
      throw new Error('Nieprawidłowy segment ścieżki.');
    }
    clean.push(seg);
  }
  if (clean.length === 0) throw new Error('Ścieżka nie zawiera prawidłowych segmentów.');

  var finalPath = clean.join('/');
  if (opts.requireExtension !== false) {
    var lower = finalPath.toLowerCase();
    var ok = false;
    for (var j = 0; j < ALLOWED_EXTENSIONS.length; j++) {
      var ext = ALLOWED_EXTENSIONS[j];
      if (lower.length > ext.length && lower.substring(lower.length - ext.length) === ext) ok = true;
    }
    if (!ok) throw new Error('Niedozwolone rozszerzenie pliku (dozwolone: ' + ALLOWED_EXTENSIONS.join(', ') + ').');
  }
  return finalPath;
}

// ---------------------------------------------------------------------------
// Dostęp do Drive
// ---------------------------------------------------------------------------

function getRoot_(props) {
  var id = props.getProperty('ROOT_FOLDER_ID');
  if (!id) throw new Error('Brak ROOT_FOLDER_ID.');
  return DriveApp.getFolderById(id);
}

function assertDescendant_(file, rootId) {
  var seen = {};
  var toVisit = [];
  var parents = file.getParents();
  while (parents.hasNext()) toVisit.push(parents.next());
  while (toVisit.length) {
    var f = toVisit.shift();
    var id = f.getId();
    if (id === rootId) return true;
    if (seen[id]) continue;
    seen[id] = true;
    var ps = f.getParents();
    while (ps.hasNext()) toVisit.push(ps.next());
  }
  throw new Error('Plik znajduje się poza ROOT_FOLDER_ID.');
}

function childFolder_(folder, name) {
  var it = folder.getFoldersByName(name);
  return it.hasNext() ? it.next() : null;
}

function childFile_(folder, name) {
  var it = folder.getFilesByName(name);
  return it.hasNext() ? it.next() : null;
}

function resolveByPath_(root, safePath) {
  var parts = safePath.split('/');
  var fileName = parts.pop();
  var folder = root;
  for (var i = 0; i < parts.length; i++) {
    var next = childFolder_(folder, parts[i]);
    if (!next) {
      return { folder: null, file: null, fileName: fileName };
    }
    folder = next;
  }
  return { folder: folder, file: childFile_(folder, fileName), fileName: fileName };
}

function folderByPath_(root, safeFolderPath) {
  var parts = safeFolderPath.split('/');
  var folder = root;
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    var next = childFolder_(folder, parts[i]);
    if (!next) {
      return null;
    }
    folder = next;
  }
  return folder;
}

// ---------------------------------------------------------------------------
// Jednorazowe zużycie kodu autoryzacyjnego OAuth (bezpieczeństwo MCP)
// ---------------------------------------------------------------------------

/**
 * Usuwa wygasłe wpisy `authcode:*` z PropertiesService, żeby magazyn nie rósł
 * bez końca. Tanie przy niskim wolumenie (Faza 1, pojedynczy użytkownik) —
 * skanuje wszystkie właściwości skryptu przy każdym wywołaniu `consumeAuthCode`.
 */
function cleanupExpiredAuthCodes_(props, now) {
  var all = props.getProperties();
  for (var key in all) {
    if (Object.prototype.hasOwnProperty.call(all, key) && key.indexOf(AUTH_CODE_PROP_PREFIX) === 0) {
      var exp = parseInt(all[key], 10);
      if (!exp || exp < now) {
        props.deleteProperty(key);
      }
    }
  }
}

/**
 * Atomowo (LockService) sprawdza i oznacza `jti` jako zużyty. Przechowuje
 * WYŁĄCZNIE jti (losowy, nieodwracalny identyfikator) i czas wygaśnięcia —
 * nigdy sam kod ani token. Zwraca `{ consumed: true }` przy pierwszym użyciu,
 * `{ consumed: false }` przy każdym kolejnym (replay).
 */
function consumeAuthCode_(props, jti, expSeconds) {
  if (!jti || typeof jti !== 'string') {
    throw new Error('Nieprawidłowy jti.');
  }
  var lock = LockService.getScriptLock();
  lock.waitLock(5000);
  try {
    var now = Math.floor(Date.now() / 1000);
    cleanupExpiredAuthCodes_(props, now);
    var key = AUTH_CODE_PROP_PREFIX + jti;
    if (props.getProperty(key)) {
      return { consumed: false };
    }
    var exp = parseInt(expSeconds, 10) || (now + 60);
    props.setProperty(key, String(exp));
    return { consumed: true };
  } finally {
    lock.releaseLock();
  }
}

// ---------------------------------------------------------------------------
// Dyspozytor operacji
// ---------------------------------------------------------------------------

function dispatch_(request, props) {
  var op = request && request.op;
  if (!op || (!READ_OPS[op] && !META_OPS[op])) {
    throw new Error('Nieznana operacja.');
  }
  if (META_OPS[op]) {
    switch (op) {
      case 'consumeAuthCode': return consumeAuthCode_(props, request.jti, request.exp);
      default: throw new Error('Nieobsługiwana operacja.');
    }
  }
  var root = getRoot_(props);
  var rootId = root.getId();

  switch (op) {
    case 'status': return opStatus_(root);
    case 'listTree': return opListTree_(root, request);
    case 'search': return opSearch_(root, request);
    case 'read': return opRead_(root, rootId, request);
    default: throw new Error('Nieobsługiwana operacja.');
  }
}

function opStatus_(root) {
  return {
    ok: true,
    rootId: root.getId(),
    rootName: root.getName(),
    serverTime: new Date().toISOString(),
    readOnly: true
  };
}

/**
 * `counter` jest współdzielonym obiektem { count, truncated } przekazywanym
 * przez całą rekurencję — pozwala twardo ograniczyć CAŁKOWITĄ liczbę węzłów
 * (nie tylko głębokość) i uciąć budowanie drzewa, gdy limit zostanie osiągnięty.
 * Bez tego pojedyncze żądanie mogłoby wyliczyć całe Drive.
 */
function buildTree_(folder, basePath, depth, maxDepth, counter) {
  counter.count++;
  var node = {
    path: basePath,
    name: folder.getName(),
    type: 'folder',
    id: folder.getId(),
    children: []
  };
  if (counter.count >= MAX_TREE_NODES) {
    counter.truncated = true;
    return node;
  }
  if (depth >= maxDepth) return node;
  var folders = folder.getFolders();
  while (folders.hasNext()) {
    if (counter.count >= MAX_TREE_NODES) {
      counter.truncated = true;
      break;
    }
    var sub = folders.next();
    node.children.push(buildTree_(sub, basePath ? basePath + '/' + sub.getName() : sub.getName(), depth + 1, maxDepth, counter));
  }
  var files = folder.getFiles();
  while (files.hasNext()) {
    if (counter.count >= MAX_TREE_NODES) {
      counter.truncated = true;
      break;
    }
    var f = files.next();
    counter.count++;
    node.children.push({
      path: basePath ? basePath + '/' + f.getName() : f.getName(),
      name: f.getName(),
      type: 'file',
      id: f.getId(),
      modifiedTime: f.getLastUpdated().toISOString()
    });
  }
  return node;
}

function opListTree_(root, request) {
  var maxDepth = Math.min(Math.max(parseInt(request.maxDepth, 10) || 4, 1), 8);
  var startFolder = root;
  var basePath = '';
  if (request.path) {
    var safe = pathSafe_(request.path, { requireExtension: false });
    startFolder = folderByPath_(root, safe);
    if (!startFolder) throw new Error('Folder nie istnieje.');
    basePath = safe;
  }
  var counter = { count: 0, truncated: false };
  var tree = buildTree_(startFolder, basePath, 0, maxDepth, counter);
  return { root: tree, truncated: counter.truncated === true };
}

function opSearch_(root, request) {
  var query = String(request.query || '').toLowerCase();
  var limit = Math.min(Math.max(parseInt(request.limit, 10) || 10, 1), 50);
  if (!query) return { query: request.query || '', hits: [], truncated: false };

  var hits = [];
  var scanned = 0;
  var contentReads = 0;
  var contentBytes = 0;
  var truncated = false;

  function budgetExhausted() {
    return hits.length >= limit || scanned >= MAX_SEARCH_SCAN ||
      contentReads >= MAX_SEARCH_CONTENT_READS || contentBytes >= MAX_SEARCH_CONTENT_BYTES;
  }

  function walk(folder, basePath) {
    if (budgetExhausted()) {
      if (scanned >= MAX_SEARCH_SCAN || contentReads >= MAX_SEARCH_CONTENT_READS) truncated = true;
      return;
    }
    var files = folder.getFiles();
    while (files.hasNext() && !budgetExhausted()) {
      var f = files.next();
      scanned++;
      var name = f.getName();
      var path = basePath ? basePath + '/' + name : name;
      var matched = name.toLowerCase().indexOf(query) !== -1;
      var snippet = undefined;
      if (!matched && /\.md$/i.test(name) && contentReads < MAX_SEARCH_CONTENT_READS) {
        var fileSize = Math.max(Number(f.getSize()) || 0, 0);
        if (fileSize > MAX_NOTE_BYTES) {
          // Zbyt duży plik pomijamy zamiast ładować go w całości do pamięci.
          truncated = true;
        } else if (contentBytes + fileSize > MAX_SEARCH_CONTENT_BYTES) {
          // Ustawienie licznika na limit kończy dalszy skan treści.
          contentBytes = MAX_SEARCH_CONTENT_BYTES;
          truncated = true;
        } else {
          contentReads++;
          contentBytes += fileSize;
          var content = f.getBlob().getDataAsString();
          var idx = content.toLowerCase().indexOf(query);
          if (idx !== -1) {
            matched = true;
            var start = Math.max(0, idx - 40);
            snippet = content.substring(start, Math.min(content.length, idx + 80));
          }
        }
      }
      if (matched) {
        hits.push({ path: path, id: f.getId(), name: name, modifiedTime: f.getLastUpdated().toISOString(), snippet: snippet });
      }
    }
    if (scanned >= MAX_SEARCH_SCAN || contentReads >= MAX_SEARCH_CONTENT_READS ||
        contentBytes >= MAX_SEARCH_CONTENT_BYTES) truncated = true;
    var folders = folder.getFolders();
    while (folders.hasNext() && !budgetExhausted()) {
      var sub = folders.next();
      walk(sub, basePath ? basePath + '/' + sub.getName() : sub.getName());
    }
  }

  walk(root, '');
  return { query: request.query || '', hits: hits, truncated: truncated };
}

function opRead_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var resolved = resolveByPath_(root, safe);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);
  if (resolved.file.getSize() > MAX_NOTE_BYTES) {
    throw new Error('Notatka przekracza limit rozmiaru odczytu.');
  }
  return {
    path: safe,
    id: resolved.file.getId(),
    name: resolved.file.getName(),
    modifiedTime: resolved.file.getLastUpdated().toISOString(),
    content: resolved.file.getBlob().getDataAsString()
  };
}

// ---------------------------------------------------------------------------
// Eksport dla testów w Node (ignorowany przez Apps Script).
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    verifyEnvelope_: verifyEnvelope_,
    canonicalString_: canonicalString_,
    constantTimeEqual_: constantTimeEqual_,
    pathSafe_: pathSafe_,
    dispatch_: dispatch_,
    doPost: doPost,
    doGet: doGet,
    opStatus_: opStatus_,
    opListTree_: opListTree_,
    opSearch_: opSearch_,
    opRead_: opRead_,
    assertDescendant_: assertDescendant_,
    getRoot_: getRoot_,
    consumeAuthCode_: consumeAuthCode_,
    cleanupExpiredAuthCodes_: cleanupExpiredAuthCodes_,
    MAX_TREE_NODES: MAX_TREE_NODES,
    MAX_SEARCH_SCAN: MAX_SEARCH_SCAN,
    MAX_SEARCH_CONTENT_READS: MAX_SEARCH_CONTENT_READS,
    MAX_NOTE_BYTES: MAX_NOTE_BYTES,
    MAX_SEARCH_CONTENT_BYTES: MAX_SEARCH_CONTENT_BYTES,
    READ_OPS: READ_OPS,
    META_OPS: META_OPS
  };
}
