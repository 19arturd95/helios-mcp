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
 *   WRITE_ENABLED    — (opcjonalne) "true" włącza operacje zapisu. Domyślnie wyłączone.
 *
 * Zasady bezpieczeństwa:
 *   - odrzuca żądania starsze niż 5 minut (okno ±300 s),
 *   - odrzuca ponownie użyte nonce (CacheService),
 *   - odrzuca nieprawidłowy podpis HMAC (porównanie w czasie stałym),
 *   - blokuje ścieżki absolutne, "..", traversal, "%", "\", znaki sterujące,
 *   - domyślnie tylko pliki .md, maksymalny zapis 1 MB,
 *   - nie loguje treści notatek, nie zwraca sekretów w błędach,
 *   - brak trwałego usuwania, brak zmian uprawnień, brak udostępniania.
 */

var MAX_SKEW_SECONDS = 300;
var MAX_WRITE_BYTES = 1024 * 1024;
var ALLOWED_EXTENSIONS = ['.md'];
var BACKUPS_DIR = '90 System/Backups';
var ARCHIVE_INBOX_DIR = '99 Archive/Inbox';

var READ_OPS = { status: true, listTree: true, search: true, read: true };
var WRITE_OPS = { create: true, update: true, append: true, backup: true, moveToArchive: true };

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
  var nonceKey = 'nonce:' + nonce;
  if (deps.cacheGet(nonceKey)) {
    return { ok: false, error: 'Nonce został już użyty.', code: 'replay' };
  }
  deps.cachePut(nonceKey, '1', skew * 2);

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

function writeEnabled_(props) {
  return String(props.getProperty('WRITE_ENABLED') || 'false').toLowerCase() === 'true';
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

function resolveByPath_(root, safePath, createMissing) {
  var parts = safePath.split('/');
  var fileName = parts.pop();
  var folder = root;
  for (var i = 0; i < parts.length; i++) {
    var next = childFolder_(folder, parts[i]);
    if (!next) {
      if (!createMissing) return { folder: null, file: null, fileName: fileName };
      next = folder.createFolder(parts[i]);
    }
    folder = next;
  }
  return { folder: folder, file: childFile_(folder, fileName), fileName: fileName };
}

function folderByPath_(root, safeFolderPath, createMissing) {
  var parts = safeFolderPath.split('/');
  var folder = root;
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    var next = childFolder_(folder, parts[i]);
    if (!next) {
      if (!createMissing) return null;
      next = folder.createFolder(parts[i]);
    }
    folder = next;
  }
  return folder;
}

function fileMeta_(file, path) {
  return {
    path: path,
    id: file.getId(),
    name: file.getName(),
    mimeType: file.getMimeType(),
    modifiedTime: file.getLastUpdated().toISOString()
  };
}

function assertSize_(content) {
  var bytes = Utilities.newBlob(content, 'text/plain').getBytes().length;
  if (bytes > MAX_WRITE_BYTES) {
    throw new Error('Zawartość przekracza limit ' + MAX_WRITE_BYTES + ' bajtów.');
  }
}

// ---------------------------------------------------------------------------
// Dyspozytor operacji
// ---------------------------------------------------------------------------

function dispatch_(request, props) {
  var op = request && request.op;
  if (!op || (!READ_OPS[op] && !WRITE_OPS[op])) {
    throw new Error('Nieznana operacja.');
  }
  if (WRITE_OPS[op] && !writeEnabled_(props)) {
    throw new Error('Operacje zapisu są wyłączone (Faza 1).');
  }
  var root = getRoot_(props);
  var rootId = root.getId();

  switch (op) {
    case 'status': return opStatus_(root, props);
    case 'listTree': return opListTree_(root, request);
    case 'search': return opSearch_(root, request);
    case 'read': return opRead_(root, rootId, request);
    case 'create': return opCreate_(root, rootId, request);
    case 'update': return opUpdate_(root, rootId, request);
    case 'append': return opAppend_(root, rootId, request);
    case 'backup': return opBackup_(root, rootId, request);
    case 'moveToArchive': return opMoveToArchive_(root, rootId, request);
    default: throw new Error('Nieobsługiwana operacja.');
  }
}

function opStatus_(root, props) {
  return {
    ok: true,
    rootId: root.getId(),
    rootName: root.getName(),
    serverTime: new Date().toISOString(),
    writeEnabled: writeEnabled_(props)
  };
}

function buildTree_(folder, basePath, depth, maxDepth) {
  var node = {
    path: basePath,
    name: folder.getName(),
    type: 'folder',
    id: folder.getId(),
    children: []
  };
  if (depth >= maxDepth) return node;
  var folders = folder.getFolders();
  while (folders.hasNext()) {
    var sub = folders.next();
    node.children.push(buildTree_(sub, basePath ? basePath + '/' + sub.getName() : sub.getName(), depth + 1, maxDepth));
  }
  var files = folder.getFiles();
  while (files.hasNext()) {
    var f = files.next();
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
    startFolder = folderByPath_(root, safe, false);
    if (!startFolder) throw new Error('Folder nie istnieje.');
    basePath = safe;
  }
  return { root: buildTree_(startFolder, basePath, 0, maxDepth) };
}

function opSearch_(root, request) {
  var query = String(request.query || '').toLowerCase();
  var limit = Math.min(Math.max(parseInt(request.limit, 10) || 10, 1), 50);
  if (!query) return { query: request.query || '', hits: [] };

  var hits = [];
  var scanned = 0;
  var MAX_SCAN = 800;

  function walk(folder, basePath) {
    if (hits.length >= limit || scanned >= MAX_SCAN) return;
    var files = folder.getFiles();
    while (files.hasNext() && hits.length < limit && scanned < MAX_SCAN) {
      var f = files.next();
      scanned++;
      var name = f.getName();
      var path = basePath ? basePath + '/' + name : name;
      var matched = name.toLowerCase().indexOf(query) !== -1;
      var snippet = undefined;
      if (!matched && /\.md$/i.test(name)) {
        var content = f.getBlob().getDataAsString();
        var idx = content.toLowerCase().indexOf(query);
        if (idx !== -1) {
          matched = true;
          var start = Math.max(0, idx - 40);
          snippet = content.substring(start, Math.min(content.length, idx + 80));
        }
      }
      if (matched) {
        hits.push({ path: path, id: f.getId(), name: name, modifiedTime: f.getLastUpdated().toISOString(), snippet: snippet });
      }
    }
    var folders = folder.getFolders();
    while (folders.hasNext() && hits.length < limit && scanned < MAX_SCAN) {
      var sub = folders.next();
      walk(sub, basePath ? basePath + '/' + sub.getName() : sub.getName());
    }
  }

  walk(root, '');
  return { query: request.query || '', hits: hits };
}

function opRead_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var resolved = resolveByPath_(root, safe, false);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);
  return {
    path: safe,
    id: resolved.file.getId(),
    name: resolved.file.getName(),
    modifiedTime: resolved.file.getLastUpdated().toISOString(),
    content: resolved.file.getBlob().getDataAsString()
  };
}

// --- operacje zapisu (Faza 2, domyślnie zablokowane przez WRITE_ENABLED) ---

function opCreate_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var content = String(request.content || '');
  assertSize_(content);
  var resolved = resolveByPath_(root, safe, true);
  if (resolved.file) throw new Error('Plik już istnieje — użyj update.');
  var created = resolved.folder.createFile(resolved.fileName, content, 'text/markdown');
  assertDescendant_(created, rootId);
  return fileMeta_(created, safe);
}

function opUpdate_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var content = String(request.content || '');
  assertSize_(content);
  var resolved = resolveByPath_(root, safe, false);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);

  var actual = resolved.file.getLastUpdated().toISOString();
  var expected = request.expectedModifiedTime;
  if (!expected || new Date(expected).getTime() !== new Date(actual).getTime()) {
    throw new Error('Konflikt wersji: oczekiwano ' + expected + ', bieżące ' + actual + '.');
  }
  backupFile_(root, resolved.file, safe);
  resolved.file.setContent(content);
  return fileMeta_(resolved.file, safe);
}

function opAppend_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var text = String(request.text || '');
  var resolved = resolveByPath_(root, safe, false);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);
  var current = resolved.file.getBlob().getDataAsString();
  var combined = current + (current.length && current.charAt(current.length - 1) !== '\n' ? '\n' : '') + text;
  assertSize_(combined);
  backupFile_(root, resolved.file, safe);
  resolved.file.setContent(combined);
  return fileMeta_(resolved.file, safe);
}

function backupFile_(root, file, safePath) {
  var backupsFolder = folderByPath_(root, BACKUPS_DIR, true);
  var stamp = new Date().toISOString().replace(/[:.]/g, '-');
  var backupName = safePath.replace(/\//g, '__') + '.' + stamp + '.bak.md';
  var copy = file.makeCopy(backupName, backupsFolder);
  return fileMeta_(copy, BACKUPS_DIR + '/' + backupName);
}

function opBackup_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var resolved = resolveByPath_(root, safe, false);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);
  return backupFile_(root, resolved.file, safe);
}

function opMoveToArchive_(root, rootId, request) {
  var safe = pathSafe_(request.path);
  var resolved = resolveByPath_(root, safe, false);
  if (!resolved.file) throw new Error('Notatka nie istnieje.');
  assertDescendant_(resolved.file, rootId);
  var archiveFolder = folderByPath_(root, ARCHIVE_INBOX_DIR, true);
  resolved.file.moveTo(archiveFolder);
  return fileMeta_(resolved.file, ARCHIVE_INBOX_DIR + '/' + resolved.fileName);
}

// ---------------------------------------------------------------------------
// Eksport dla testów w Node (ignorowany przez Apps Script).
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    verifyEnvelope_: verifyEnvelope_,
    canonicalString_: canonicalString_,
    constantTimeEqual_: constantTimeEqual_,
    pathSafe_: pathSafe_
  };
}
