/**
 * Permanent MCP Workspace Server — Security & Workspace Isolation Layer
 *
 * Implements workspace boundary validation, reparse-point checks, sensitive-file
 * filtering, binary detection, and resource limits. File contents are read from
 * verified open handles. Node does not provide Windows handle-relative opens or
 * a portable directory-handle fstat, so directory enumeration cannot be proven
 * race-free against a same-user process that swaps and restores a junction in
 * the narrow opendir window; see openWorkspaceDirectory below.
 */

const path = require('path');
const fs = require('fs/promises');
const fsConstants = require('fs').constants;

const TOOL_NAMES = Object.freeze([
  'get_workspace_context',
  'list_files',
  'read_file',
  'search_files'
]);

// Excluded directory names (case-insensitive)
const OMIT_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'out',
  'target',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.venv',
  'venv',
  '__pycache__',
  'vendor',
  '.aws',
  '.ssh',
  '.gnupg',
  '.azure',
  '.kube',
  '.idea'
]);

// Sensitive standalone file names (case-insensitive)
const OMIT_FILES = new Set([
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.git-credentials',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'known_hosts',
  'authorized_keys',
  '.dockercfg',
  'htpasswd'
]);

// Sensitive certificate and key extensions (case-insensitive)
const OMIT_EXTENSIONS = new Set([
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.p7b',
  '.p7c',
  '.p8',
  '.jks',
  '.keystore',
  '.crt',
  '.cer',
  '.der',
  '.kdbx'
]);

// Pattern for sensitive substrings in path components (tokens, credentials, secrets, private keys)
const SENSITIVE_SEGMENT_REGEX = /(^|[._-])(secret|secrets|credential|credentials|token|tokens|password|passwords|id_rsa|id_ed25519)([._-]|$)/i;

const MAX_FILE_BYTES = 1024 * 1024; // 1 MiB read limit
const MAX_SEARCH_FILES = 500;
const MAX_SEARCH_BYTES = 20 * 1024 * 1024; // 20 MiB search scan limit
const MAX_SEARCH_LINE_LENGTH = 500;

/**
 * Resolves and canonicalizes the workspace root directory.
 * @param {string|Function} workspaceRoot - Path string or async function returning path
 * @returns {Promise<string>} Canonical workspace root realpath
 */
async function resolveWorkspaceRoot(workspaceRoot) {
  const raw = typeof workspaceRoot === 'function' ? await workspaceRoot() : workspaceRoot;
  if (!raw || typeof raw !== 'string') {
    throw new Error('Workspace root directory must be a non-empty string.');
  }
  let real;
  try {
    real = await fs.realpath(raw);
  } catch (err) {
    throw new Error(`Workspace root does not exist or cannot be resolved: ${err.message}`);
  }
  const stat = await fs.stat(real);
  if (!stat.isDirectory()) {
    throw new Error(`Workspace root is not a directory: ${real}`);
  }
  return real;
}


function pathIsInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function assertCanonicalRoot(root) {
  let realRoot;
  try { realRoot = await fs.realpath(root); }
  catch { throw new Error('Workspace root changed or is no longer available.'); }
  const stat = await fs.lstat(root);
  if (path.relative(root, realRoot) !== '' || stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('Workspace root changed during access.');
  }
}

function assertSameIdentity(opened, current) {
  if (opened.dev !== current.dev || opened.ino === 0n || opened.ino !== current.ino) {
    throw new Error('Workspace path changed while it was being opened.');
  }
}

async function openWorkspaceFile(root, relativePath) {
  const initialPath = await resolveInside(root, relativePath);
  const initialStat = await fs.stat(initialPath, { bigint: true });
  if (!initialStat.isFile()) throw new Error('The requested path is not a regular file.');
  const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW || 0);
  const handle = await fs.open(initialPath, fsConstants.O_RDONLY | noFollow);
  try {
    const openedStat = await handle.stat({ bigint: true });
    if (!openedStat.isFile()) throw new Error('The requested path is not a regular file.');
    assertSameIdentity(initialStat, openedStat);
    const verifiedPath = await resolveInside(root, relativePath);
    const verifiedStat = await fs.stat(verifiedPath, { bigint: true });
    assertSameIdentity(openedStat, verifiedStat);
    return { handle, filePath: verifiedPath, stat: openedStat };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

async function openWorkspaceDirectory(root, relativePath) {
  const initialPath = await resolveInside(root, relativePath);
  const before = await fs.stat(initialPath, { bigint: true });
  if (!before.isDirectory()) throw new Error('The requested path is not a directory.');
  const directory = await fs.opendir(initialPath);
  try {
    // Dir handles are pinned for enumeration, but Node does not expose a
    // portable fstat for Dir, so identity of that handle cannot be proven.
    const verifiedPath = await resolveInside(root, relativePath);
    const after = await fs.stat(verifiedPath, { bigint: true });
    assertSameIdentity(before, after);
    return directory;
  } catch (error) {
    await directory.close().catch(() => {});
    throw error;
  }
}

/**
 * Checks if a relative path component or path string matches sensitive or generated exclusions.
 * @param {string|string[]} target - Path string or array of path segments
 * @returns {boolean} True if excluded
 */
function isExcluded(target) {
  let segments;
  if (Array.isArray(target)) {
    segments = target;
  } else if (typeof target === 'string') {
    segments = target.replace(/\\/g, '/').split('/').filter(Boolean);
  } else {
    return true;
  }

  for (const rawPart of segments) {
    const part = rawPart.toLowerCase();
    if (OMIT_DIRS.has(part)) return true;
    if (part.startsWith('.env')) return true;
    if (SENSITIVE_SEGMENT_REGEX.test(part)) return true;
  }

  const last = (segments[segments.length - 1] || '').toLowerCase();
  if (OMIT_FILES.has(last)) return true;
  const ext = path.extname(last).toLowerCase();
  if (OMIT_EXTENSIONS.has(ext)) return true;

  return false;
}

/**
 * Validates and resolves a workspace-relative path safely inside the canonical workspace root.
 * Enforces:
 * - Rejection of null bytes
 * - Rejection of absolute POSIX and Windows paths (including drive letters and UNC)
 * - Rejection of path traversal sequences ('..' or '.')
 * - Rejection of Windows Alternate Data Streams (contains ':')
 * - Rejection of sensitive and generated paths
 * - Canonical realpath validation preventing symlink escapes
 *
 * @param {string} root - Canonical workspace root (must already be realpath)
 * @param {string} input - Workspace-relative path to resolve
 * @returns {Promise<string>} Canonical realpath inside the workspace
 */
async function resolveInside(root, input) {
  if (typeof input !== 'string' || input.includes('\0')) throw new Error('Invalid workspace-relative path.');
  const normalized = input.replace(/\\/g, '/');
  if (path.posix.isAbsolute(normalized) || path.win32.isAbsolute(input) ||
      /^[a-zA-Z]:/.test(input) || input.startsWith('//') || input.startsWith('\\\\')) {
    throw new Error('Absolute paths are not allowed.');
  }
  const rawParts = normalized.split('/').filter(part => part !== '' && part !== '.');
  if (rawParts.some(part => part === '..' || part.includes(':'))) {
    throw new Error('Path traversal and alternate data streams are not allowed.');
  }
  if (isExcluded(rawParts)) throw new Error('This generated or sensitive path is excluded.');

  await assertCanonicalRoot(root);
  const candidate = path.resolve(root, ...rawParts);
  if (!pathIsInside(root, candidate)) throw new Error('Path escapes the workspace.');

  let current = root;
  for (const part of rawParts) {
    current = path.join(current, part);
    let component;
    try { component = await fs.lstat(current); }
    catch (error) {
      if (error.code === 'ENOENT') throw new Error(`Path not found: ${input}`);
      throw error;
    }
    if (component.isSymbolicLink()) throw new Error('Symbolic links and junctions are not allowed in workspace paths.');
  }

  let real;
  try { real = await fs.realpath(candidate); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error(`Path not found: ${input}`);
    throw error;
  }
  await assertCanonicalRoot(root);
  if (!pathIsInside(root, real)) throw new Error('Resolved path escapes the workspace.');
  if (isExcluded(path.relative(root, real).split(path.sep))) {
    throw new Error('This generated or sensitive path is excluded.');
  }
  return real;
}

/**
 * Checks if a buffer contains binary data (null bytes).
 * @param {Buffer} buffer
 * @returns {boolean}
 */
function isBinary(buffer) {
  // Check up to the first 8000 bytes or whole buffer
  const length = Math.min(buffer.length, 8000);
  for (let i = 0; i < length; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

/**
 * Lists workspace directory contents excluding sensitive and generated paths.
 * Symlinks to directories are never traversed.
 *
 * @param {string} root - Canonical workspace root
 * @param {string} startDir - Canonical starting directory inside root
 * @param {boolean} recursive - Whether to descend into subdirectories
 * @param {number} limit - Maximum entries to collect
 * @returns {Promise<string[]>} Array of relative paths (directories end with '/')
 */
async function listDirectory(root, startDir, recursive, limit = 500) {
  const found = [];
  const startRelative = path.relative(root, startDir).split(path.sep).join('/');

  async function visit(relativeDir, required = false) {
    let directory;
    try { directory = await openWorkspaceDirectory(root, relativeDir); }
    catch (error) { if (required) throw error; return; }
    try {
      while (found.length < limit) {
        const entry = await directory.read();
        if (!entry) break;
        const parts = [...(relativeDir ? relativeDir.split('/') : []), entry.name];
        if (isExcluded(parts) || entry.isSymbolicLink()) continue;
        const relativePath = parts.join('/');
        if (entry.isFile()) found.push(relativePath);
        else if (entry.isDirectory()) {
          found.push(relativePath + '/');
          if (recursive && found.length < limit) await visit(relativePath);
        }
      }
    } finally {
      await directory.close().catch(() => {});
    }
  }

  await visit(startRelative, true);
  return found;
}

/**
 * Reads a workspace file after strict validation.
 * @param {string} root - Canonical workspace root
 * @param {string} relativePath - Workspace-relative file path
 * @returns {Promise<{ path: string, content: string }>}
 */
async function readHandleBounded(handle) {
  const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
  let total = 0;
  while (total < buffer.length) {
    const { bytesRead } = await handle.read(buffer, total, buffer.length - total, null);
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  if (total > MAX_FILE_BYTES) throw new Error('File exceeds the 1 MiB read limit.');
  return buffer.subarray(0, total);
}

async function readWorkspaceFile(root, relativePath) {
  const opened = await openWorkspaceFile(root, relativePath);
  try {
    if (opened.stat.size > BigInt(MAX_FILE_BYTES)) throw new Error('File exceeds the 1 MiB read limit.');
    const bytes = await readHandleBounded(opened.handle);
    if (isBinary(bytes)) throw new Error('Binary files cannot be read by this tool.');
    const displayRel = path.relative(root, opened.filePath).split(path.sep).join('/');
    return { path: displayRel, content: bytes.toString('utf8') };
  } finally {
    await opened.handle.close().catch(() => {});
  }
}

/**
 * Searches text files across the workspace for literal substring matches.
 * @param {string} root - Canonical workspace root
 * @param {string} relativeDir - Workspace-relative search root
 * @param {string} query - Substring to find
 * @param {number} maxResults - Max matching lines
 * @returns {Promise<{ matches: Array<{ path: string, line: number, text: string }>, truncated: boolean }>}
 */
async function searchWorkspaceFiles(root, relativeDir, query, maxResults = 50) {
  const startDir = await resolveInside(root, relativeDir || '');
  const startStat = await fs.stat(startDir);
  if (!startStat.isDirectory()) throw new Error('The requested path is not a directory.');
  const files = await listDirectory(root, startDir, true, MAX_SEARCH_FILES);
  const matches = [];
  let bytesRead = 0;
  const needle = query.toLowerCase();

  for (const relativePath of files) {
    if (matches.length >= maxResults || bytesRead >= MAX_SEARCH_BYTES) break;
    if (relativePath.endsWith('/')) continue;
    let opened;
    try { opened = await openWorkspaceFile(root, relativePath); }
    catch { continue; }
    try {
      if (!opened.stat.isFile() || opened.stat.size > BigInt(MAX_FILE_BYTES)) continue;
      if (bytesRead + Number(opened.stat.size) > MAX_SEARCH_BYTES) break;
      const bytes = await readHandleBounded(opened.handle);
      bytesRead += bytes.length;
      if (isBinary(bytes)) continue;
      const lines = bytes.toString('utf8').split(/\r?\n/);
      for (let i = 0; i < lines.length && matches.length < maxResults; i++) {
        if (lines[i].toLowerCase().includes(needle)) {
          matches.push({ path: relativePath, line: i + 1, text: lines[i].slice(0, MAX_SEARCH_LINE_LENGTH) });
        }
      }
    } catch {
      // A file that changes while being read is skipped rather than exposed.
    } finally {
      await opened.handle.close().catch(() => {});
    }
  }
  return {
    matches,
    truncated: matches.length >= maxResults || files.length >= MAX_SEARCH_FILES || bytesRead >= MAX_SEARCH_BYTES
  };
}

/**
 * Generates structured context about the workspace.
 * @param {string} root - Canonical workspace root
 * @returns {Promise<object>}
 */
async function getWorkspaceContext(root) {
  const topLevel = await listDirectory(root, root, false, 80);
  const sampleFiles = await listDirectory(root, root, true, 100);

  const KNOWN_CONFIG_NAMES = new Set([
    'package.json',
    'tsconfig.json',
    'jsconfig.json',
    'cargo.toml',
    'pyproject.toml',
    'go.mod',
    'pom.xml',
    'build.gradle',
    'composer.json',
    'makefile',
    'cmakelists.txt',
    'readme.md',
    'license'
  ]);

  const configFiles = [];
  const sourceTypes = new Set();
  let directoryCount = 0;
  let fileCount = 0;

  for (const item of topLevel) {
    if (item.endsWith('/')) {
      directoryCount++;
    } else {
      fileCount++;
      const lower = item.toLowerCase();
      if (KNOWN_CONFIG_NAMES.has(lower)) {
        configFiles.push(item);
      }
    }
  }

  for (const item of sampleFiles) {
    if (!item.endsWith('/')) {
      const ext = path.extname(item).toLowerCase();
      if (ext) {
        sourceTypes.add(ext);
      }
    }
  }

  return {
    name: path.basename(root),
    root,
    topLevel,
    availableTools: TOOL_NAMES,
    configFiles,
    sourceTypes: Array.from(sourceTypes).sort(),
    structureSummary: {
      totalTopLevelEntries: topLevel.length,
      directories: directoryCount,
      files: fileCount
    }
  };
}

module.exports = {
  TOOL_NAMES,
  OMIT_DIRS,
  OMIT_FILES,
  OMIT_EXTENSIONS,
  MAX_FILE_BYTES,
  MAX_SEARCH_FILES,
  MAX_SEARCH_BYTES,
  MAX_SEARCH_LINE_LENGTH,
  resolveWorkspaceRoot,
  isExcluded,
  resolveInside,
  openWorkspaceFile,
  isBinary,
  listDirectory,
  readWorkspaceFile,
  searchWorkspaceFiles,
  getWorkspaceContext
};
