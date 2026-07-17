import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { readFile } from 'node:fs/promises';
import { encryptPdf, decryptPdf } from '../src/index.js';

// Cross-validates our AES-256 output against independent PDF readers (qpdf,
// poppler) instead of just round-tripping through our own encrypt/decrypt -
// self-consistency tests can't catch a hash2B bug that both sides share.

const PASSWORD = 'correct horse battery staple';
const CONTENT = 'Interop test content.';

async function makeTestPdf(text) {
    const doc = await PDFDocument.create();
    const page = doc.addPage([595, 842]);
    const font = await doc.embedFont(StandardFonts.Helvetica);
    page.drawText(text, { x: 50, y: 780, size: 14, font });
    return doc.save();
}

// True if the binary itself exists - only a missing-executable error counts
// as "not found"; any other outcome of this probe call means it's present.
function commandExists(cmd, args) {
    try {
        execFileSync(cmd, args, { stdio: 'ignore' });
        return true;
    } catch (err) {
        return err.code !== 'ENOENT';
    }
}

const qpdfAvailable = commandExists('qpdf', ['--version']);

// poppler: prefer a native pdftotext, fall back to WSL - Windows dev machines
// in this project run poppler-utils inside a WSL distro rather than natively.
const popplerMode = commandExists('pdftotext', ['-v'])
    ? 'native'
    : process.platform === 'win32' && commandExists('wsl', ['--', 'pdftotext', '-v'])
        ? 'wsl'
        : null;

function toWslPath(winPath) {
    return execFileSync('wsl', ['wslpath', '-a', winPath]).toString().trim();
}

function pdftotext(pdfPath, password) {
    if (popplerMode === 'native') {
        return execFileSync('pdftotext', ['-upw', password, pdfPath, '-']).toString('utf8');
    }
    return execFileSync('wsl', ['--', 'pdftotext', '-upw', password, toWslPath(pdfPath), '-']).toString('utf8');
}

async function withTempEncryptedPdf(fn) {
    const dir = await mkdtemp(path.join(tmpdir(), 'pdf-interop-'));
    try {
        const encPath = path.join(dir, 'enc.pdf');
        const encrypted = await encryptPdf(await makeTestPdf(CONTENT), PASSWORD);
        await writeFile(encPath, encrypted);
        return await fn(encPath, dir);
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
}

test(
    'qpdf accepts the correct password and rejects a wrong one',
    { skip: qpdfAvailable ? false : 'qpdf not found on this machine' },
    () => withTempEncryptedPdf(async (encPath, dir) => {
        const outPath = path.join(dir, 'out.pdf');
        execFileSync('qpdf', [`--password=${PASSWORD}`, '--decrypt', encPath, outPath]);
        assert.throws(() =>
            execFileSync('qpdf', ['--password=wrong password', '--decrypt', encPath, outPath], { stdio: 'ignore' })
        );
    })
);

test(
    'qpdf-encrypted PDF is decrypted correctly by our library',
    { skip: qpdfAvailable ? false : 'qpdf not found on this machine' },
    () => withTempEncryptedPdf(async (_encPath, dir) => {
        const plainPath = path.join(dir, 'plain.pdf');
        const qpdfEncPath = path.join(dir, 'qpdf-enc.pdf');
        const plainBytes = await makeTestPdf(CONTENT);
        await writeFile(plainPath, plainBytes);
        // --object-streams=disable forces a traditional xref table; pdf-lib cannot
        // load encrypted PDFs that use xref streams (a pdf-lib parser limitation).
        execFileSync('qpdf', ['--object-streams=disable', '--encrypt', PASSWORD, PASSWORD, '256', '--', plainPath, qpdfEncPath]);
        const encrypted = await readFile(qpdfEncPath);
        const result = await decryptPdf(encrypted, PASSWORD);
        assert.ok(result.bytes.length > 0);
    })
);

test(
    'poppler (native or WSL) extracts the original text with the correct password',
    { skip: popplerMode ? false : 'poppler not found natively or via WSL on this machine' },
    () => withTempEncryptedPdf(async (encPath) => {
        const text = pdftotext(encPath, PASSWORD);
        assert.match(text, /Interop test content\./);
    })
);
