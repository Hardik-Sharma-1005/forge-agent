/**
 * Security & Workspace Isolation Test Suite
 *
 * Validates path traversal prevention, symlink escape blocking,
 * Windows Alternate Data Streams rejection, sensitive file filtering,
 * binary file detection, and file read size limits.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');

const {
  resolveWorkspaceRoot,
  resolveInside,
  isExcluded,
  isBinary,
  listDirectory,
  readWorkspaceFile,
  searchWorkspaceFiles,
  getWorkspaceContext,
  MAX_FILE_BYTES
} = require('../src/security');

describe('Security & Workspace Isolation Layer', () => {
  let tempRoot;
  let outsideDir;

  before(async () => {
    // Create isolated temporary workspace root
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-sec-ws-'));
    outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-sec-outside-'));

    // Populate normal workspace files
    await fs.mkdir(path.join(tempRoot, 'src'), { recursive: true });
    await fs.writeFile(path.join(tempRoot, 'src', 'index.js'), 'console.log("hello world");\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, 'package.json'), '{"name":"test-project"}\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, 'README.md'), '# Test Project\n', 'utf8');

    // Populate outside files (for traversal/symlink escape testing)
    await fs.writeFile(path.join(outsideDir, 'external-secret.txt'), 'OUTSIDE_SECRET_DATA', 'utf8');

    // Create symlink inside workspace pointing to outside file
    try {
      await fs.symlink(
        path.join(outsideDir, 'external-secret.txt'),
        path.join(tempRoot, 'symlink-escape.txt'),
        'file'
      );
    } catch (e) {
      // Handled if symlink creation is restricted
    }

    // Populate sensitive and generated files inside workspace
    await fs.writeFile(path.join(tempRoot, '.env'), 'SECRET_API_KEY=12345\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, '.env.local'), 'LOCAL_KEY=secret\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, 'id_rsa'), '-----BEGIN RSA PRIVATE KEY-----\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, 'server.key'), 'PRIVATE_KEY_DATA\n', 'utf8');
    await fs.writeFile(path.join(tempRoot, 'credentials.json'), '{"token":"abc"}\n', 'utf8');

    await fs.mkdir(path.join(tempRoot, '.git'), { recursive: true });
    await fs.writeFile(path.join(tempRoot, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n', 'utf8');

    await fs.mkdir(path.join(tempRoot, 'node_modules', 'dep'), { recursive: true });
    await fs.writeFile(path.join(tempRoot, 'node_modules', 'dep', 'package.json'), '{"name":"dep"}\n', 'utf8');

    // Populate binary file
    const binaryData = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64]);
    await fs.writeFile(path.join(tempRoot, 'binary.bin'), binaryData);

    // Populate oversized file (> 1 MiB)
    const largeBuffer = Buffer.alloc(MAX_FILE_BYTES + 1024, 0x61);
    await fs.writeFile(path.join(tempRoot, 'large.txt'), largeBuffer);
  });

  after(async () => {
    if (tempRoot) await fs.rm(tempRoot, { recursive: true, force: true });
    if (outsideDir) await fs.rm(outsideDir, { recursive: true, force: true });
  });

  describe('Workspace Root Resolution', () => {
    it('resolves valid workspace directory to canonical realpath', async () => {
      const real = await resolveWorkspaceRoot(tempRoot);
      assert.equal(real, await fs.realpath(tempRoot));
    });

    it('rejects nonexistent workspace root', async () => {
      await assert.rejects(
        () => resolveWorkspaceRoot(path.join(tempRoot, 'does-not-exist')),
        /does not exist or cannot be resolved/
      );
    });

    it('rejects a file passed as workspace root', async () => {
      const filePath = path.join(tempRoot, 'package.json');
      await assert.rejects(
        () => resolveWorkspaceRoot(filePath),
        /is not a directory/
      );
    });
  });

  describe('Path Traversal & Boundaries', () => {
    it('rejects ../../package.json', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, '../../package.json'),
        /Path traversal and alternate data streams are not allowed|Path escapes the workspace/
      );
    });

    it('rejects ../../../Windows/win.ini', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, '../../../Windows/win.ini'),
        /Path traversal and alternate data streams are not allowed|Path escapes the workspace/
      );
    });

    it('rejects Windows traversal ..\\..\\secret.txt', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, '..\\..\\secret.txt'),
        /Path traversal and alternate data streams are not allowed|Path escapes the workspace/
      );
    });

    it('rejects POSIX absolute path /etc/passwd', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, '/etc/passwd'),
        /Absolute paths are not allowed/
      );
    });

    it('rejects Windows drive-letter absolute path C:\\Windows\\win.ini', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, 'C:\\Windows\\win.ini'),
        /Absolute paths are not allowed/
      );
    });

    it('rejects Windows UNC path \\\\server\\share\\file', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, '\\\\server\\share\\file'),
        /Absolute paths are not allowed/
      );
    });

    it('rejects null bytes in path', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, 'src/index.js\0.txt'),
        /Invalid workspace-relative path/
      );
    });

    it('rejects Windows Alternate Data Streams (contains :)', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => resolveInside(canonicalRoot, 'package.json:stream'),
        /Path traversal and alternate data streams are not allowed/
      );
    });
  });

  describe('Symlink Escape Protection', () => {
    it('rejects symlink pointing outside workspace', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      const symlinkPath = path.join(tempRoot, 'symlink-escape.txt');
      try {
        await fs.access(symlinkPath);
      } catch {
        // If symlink not created, skip assertion
        return;
      }
      await assert.rejects(
        () => resolveInside(canonicalRoot, 'symlink-escape.txt'),
        /Resolved path escapes the workspace/
      );
    });
  });

  describe('Sensitive-File Filtering (Deny-by-Default)', () => {
    it('excludes .env', () => {
      assert.equal(isExcluded('.env'), true);
      assert.equal(isExcluded(['.env']), true);
    });

    it('excludes .env.local and .env.production', () => {
      assert.equal(isExcluded('.env.local'), true);
      assert.equal(isExcluded('.env.production'), true);
    });

    it('excludes .git and .git/config', () => {
      assert.equal(isExcluded('.git'), true);
      assert.equal(isExcluded('.git/config'), true);
      assert.equal(isExcluded(['.git', 'config']), true);
    });

    it('excludes node_modules and node_modules/dep/package.json', () => {
      assert.equal(isExcluded('node_modules'), true);
      assert.equal(isExcluded('node_modules/dep/package.json'), true);
    });

    it('excludes private key files (id_rsa, id_ed25519, server.key, cert.pem)', () => {
      assert.equal(isExcluded('id_rsa'), true);
      assert.equal(isExcluded('id_ed25519'), true);
      assert.equal(isExcluded('server.key'), true);
      assert.equal(isExcluded('cert.pem'), true);
      assert.equal(isExcluded('keystore.p12'), true);
    });

    it('excludes files matching secret/credential patterns', () => {
      assert.equal(isExcluded('credentials.json'), true);
      assert.equal(isExcluded('app.secret.yml'), true);
      assert.equal(isExcluded('my_token.txt'), true);
      assert.equal(isExcluded('db_password.conf'), true);
    });

    it('refuses direct read on .env', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, '.env'),
        /This generated or sensitive path is excluded/
      );
    });

    it('refuses direct read on id_rsa', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, 'id_rsa'),
        /This generated or sensitive path is excluded/
      );
    });

    it('refuses direct read on .git/config', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, '.git/config'),
        /This generated or sensitive path is excluded/
      );
    });

    it('refuses direct read on node_modules/dep/package.json', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, 'node_modules/dep/package.json'),
        /This generated or sensitive path is excluded/
      );
    });

    it('excludes sensitive files from directory listing', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      const items = await listDirectory(canonicalRoot, canonicalRoot, true);
      assert.ok(!items.includes('.env'), 'Listing must not include .env');
      assert.ok(!items.includes('.env.local'), 'Listing must not include .env.local');
      assert.ok(!items.some(i => i.startsWith('.git')), 'Listing must not include .git');
      assert.ok(!items.some(i => i.startsWith('node_modules')), 'Listing must not include node_modules');
      assert.ok(!items.includes('id_rsa'), 'Listing must not include id_rsa');
      assert.ok(!items.includes('server.key'), 'Listing must not include server.key');
      assert.ok(items.includes('package.json'), 'Listing must include package.json');
      assert.ok(items.includes('README.md'), 'Listing must include README.md');
      assert.ok(items.includes('src/index.js'), 'Listing must include src/index.js');
    });
  });

  describe('Binary & Size Limits', () => {
    it('detects binary files via null byte check', () => {
      assert.equal(isBinary(Buffer.from('Hello world')), false);
      assert.equal(isBinary(Buffer.from([0x48, 0x00, 0x49])), true);
    });

    it('refuses to read binary files', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, 'binary.bin'),
        /Binary files cannot be read by this tool/
      );
    });

    it('refuses to read files exceeding 1 MiB limit', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      await assert.rejects(
        () => readWorkspaceFile(canonicalRoot, 'large.txt'),
        /File exceeds the 1 MiB read limit/
      );
    });
  });

  describe('Search Files Security', () => {
    it('does not return matches from sensitive files (.env, id_rsa)', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      const result = await searchWorkspaceFiles(canonicalRoot, '', '12345', 50);
      assert.equal(result.matches.length, 0, 'Must not find matches inside .env');
    });

    it('finds valid matches in regular files', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      const result = await searchWorkspaceFiles(canonicalRoot, '', 'hello world', 50);
      assert.equal(result.matches.length, 1);
      assert.equal(result.matches[0].path, 'src/index.js');
      assert.equal(result.matches[0].line, 1);
      assert.ok(result.matches[0].text.includes('hello world'));
    });
  });

  describe('Workspace Context Security', () => {
    it('does not leak environment variables or sensitive files', async () => {
      const canonicalRoot = await fs.realpath(tempRoot);
      const ctx = await getWorkspaceContext(canonicalRoot);
      assert.ok(ctx.name);
      assert.ok(ctx.root);
      assert.ok(!ctx.topLevel.includes('.env'));
      assert.ok(!ctx.topLevel.some(i => i.startsWith('.git')));
      assert.ok(!ctx.topLevel.includes('id_rsa'));
      assert.ok(ctx.configFiles.includes('package.json'));
      assert.ok(ctx.sourceTypes.includes('.js'));
      assert.ok(ctx.sourceTypes.includes('.md'));
    });
  });
});
