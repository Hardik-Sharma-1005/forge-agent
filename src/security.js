/**
 * Permanent MCP Workspace Server — Security & Workspace Isolation Layer
 *
 * Implements strict workspace boundary validation, symlink escape protection,
 * sensitive-file filtering, binary file detection, and resource limits.
 */

const path = require('path');
const fs = require('fs/promises');

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
  if (typeof input !== 'string' || input.includes('\0')) {
    throw new Error('Invalid workspace-relative path.');
  }

  // Normalize backslashes to forward slashes for cross-platform checking
  const normalized = input.replace(/\\/g, '/');

  // Reject absolute paths across POSIX, Windows drive letters (C:\), and UNC (\\server)
  if (
    path.posix.isAbsolute(normalized) ||
    path.win32.isAbsolute(input) ||
    /^[a-zA-Z]:/.test(input) ||
    input.startsWith('//') ||
    input.startsWith('\\\\')
  ) {
    throw new Error('Absolute paths are not allowed.');
  }

  const rawParts = normalized.split('/').filter(p => p !== '' && p !== '.');

  // Reject traversal sequences and Windows Alternate Data Streams
  if (rawParts.some(part => part === '..' || part.includes(':'))) {
    throw new Error('Path traversal and alternate data streams are not allowed.');
  }

  // Enforce sensitive path exclusion on raw relative segments
  if (isExcluded(rawParts)) {
    throw new Error('This generated or sensitive path is excluded.');
  }

  // Resolve candidate path
  const candidate = path.resolve(root, ...rawParts);
  const relative = path.relative(root, candidate);

  // Candidate must remain inside root
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('Path escapes the workspace.');
  }

  // Canonicalize real path to resolve symlinks and junction points
  let real;
  try {
    real = await fs.realpath(candidate);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Path not found: ${input}`);
    }
    throw err;
  }

  // Validate that the canonical realpath remains inside canonical root
  const realRelative = path.relative(root, real);
  if (realRelative === '..' || realRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realRelative)) {
    throw new Error('Resolved path escapes the workspace.');
  }

  // Re-verify exclusions against the canonical relative path
  if (isExcluded(realRelative.split(path.sep))) {
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

  async function visit(dir) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (found.length >= limit) return;
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full);
      const segments = rel.split(path.sep);

      if (isExcluded(segments)) continue;

      // Skip symlinks to prevent symlink traversal and infinite recursion
      if (entry.isSymbolicLink()) continue;

      if (entry.isFile()) {
        found.push(segments.join('/'));
      } else if (entry.isDirectory()) {
        found.push(segments.join('/') + '/');
        if (recursive) {
          await visit(full);
        }
      }
    }
  }

  await visit(startDir);
  return found;
}

/**
 * Reads a workspace file after strict validation.
 * @param {string} root - Canonical workspace root
 * @param {string} relativePath - Workspace-relative file path
 * @returns {Promise<{ path: string, content: string }>}
 */
async function readWorkspaceFile(root, relativePath) {
  const filePath = await resolveInside(root, relativePath);
  const stat = await fs.stat(filePath);

  if (!stat.isFile()) {
    throw new Error('The requested path is not a regular file.');
  }

  if (stat.size > MAX_FILE_BYTES) {
    throw new Error(`File exceeds the ${MAX_FILE_BYTES / (1024 * 1024)} MiB read limit.`);
  }

  const bytes = await fs.readFile(filePath);
  if (isBinary(bytes)) {
    throw new Error('Binary files cannot be read by this tool.');
  }

  const displayRel = path.relative(root, filePath).split(path.sep).join('/');
  return {
    path: displayRel,
    content: bytes.toString('utf8')
  };
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
  const stat = await fs.stat(startDir);
  if (!stat.isDirectory()) {
    throw new Error('The requested path is not a directory.');
  }

  const files = await listDirectory(root, startDir, true, MAX_SEARCH_FILES);
  const matches = [];
  let bytesRead = 0;
  const needle = query.toLowerCase();

  for (const rel of files) {
    if (matches.length >= maxResults || bytesRead >= MAX_SEARCH_BYTES) break;
    // Skip directory entries
    if (rel.endsWith('/')) continue;

    let target;
    try {
      target = await resolveInside(root, rel);
    } catch {
      continue;
    }

    let fileStat;
    try {
      fileStat = await fs.stat(target);
    } catch {
      continue;
    }

    if (!fileStat.isFile() || fileStat.size > MAX_FILE_BYTES) continue;
    bytesRead += fileStat.size;

    let bytes;
    try {
      bytes = await fs.readFile(target);
    } catch {
      continue;
    }

    if (isBinary(bytes)) continue;

    const lines = bytes.toString('utf8').split(/\r?\n/);
    for (let i = 0; i < lines.length && matches.length < maxResults; i++) {
      if (lines[i].toLowerCase().includes(needle)) {
        matches.push({
          path: rel,
          line: i + 1,
          text: lines[i].slice(0, MAX_SEARCH_LINE_LENGTH)
        });
      }
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
  isBinary,
  listDirectory,
  readWorkspaceFile,
  searchWorkspaceFiles,
  getWorkspaceContext
};
