import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inflateSync } from 'node:zlib';
import { PDFDocument, StandardFonts, PDFName, PDFArray, PDFRawStream } from 'pdf-lib';
import { encryptPdf, decryptPdf, changePdfPassword } from '../src/index.js';

async function makeTestPdf(text) {
    const doc = await PDFDocument.create();
    doc.setTitle('Test title with unicode: café');
    const page = doc.addPage([595, 842]);
    const font = await doc.embedFont(StandardFonts.Helvetica);
    page.drawText(text, { x: 50, y: 780, size: 14, font });
    return doc.save();
}

// pdf-lib has no text-extraction API, and encodes drawn text as hex-string Tj
// operands (`<...>` rather than `(...)`). Content streams are also
// Flate-compressed by default. Pull the raw stream via the low-level object
// model, inflate it, and decode every hex string operand back to text.
async function extractFirstPageText(bytes) {
    const doc = await PDFDocument.load(bytes);
    assert.equal(doc.getPageCount(), 1);
    const page = doc.getPage(0);
    let contents = page.node.get(PDFName.of('Contents'));
    contents = doc.context.lookup(contents instanceof PDFArray ? contents.get(0) : contents);
    assert.ok(contents instanceof PDFRawStream, 'expected a raw content stream');
    const stream = inflateSync(Buffer.from(contents.contents)).toString('latin1');
    return [...stream.matchAll(/<([0-9A-Fa-f]+)>/g)]
        .map((m) => Buffer.from(m[1], 'hex').toString('latin1'))
        .join('');
}

test('encrypt then decrypt round-trips and produces readable content', async () => {
    const plain = await makeTestPdf('Hello, secret document.');
    const encrypted = await encryptPdf(plain, 'correct horse battery staple');

    // structurally different from the plaintext (content streams are now ciphertext)
    assert.notEqual(Buffer.from(encrypted).toString('latin1').includes('Hello, secret document.'), true);

    const wrongPwdAttempt = await decryptPdf(encrypted, 'wrong password').catch((e) => e);
    assert.equal(wrongPwdAttempt.message, 'WRONG_PASSWORD');

    const result = await decryptPdf(encrypted, 'correct horse battery staple');
    assert.equal(result.owner, false);
    const text = await extractFirstPageText(result.bytes);
    assert.match(text, /Hello, secret document\./);
});

test('decryptPdf throws NOT_ENCRYPTED on a plain PDF', async () => {
    const plain = await makeTestPdf('not encrypted');
    await assert.rejects(() => decryptPdf(plain, 'anything'), /NOT_ENCRYPTED/);
});

test('changePdfPassword invalidates the old password and accepts the new one', async () => {
    const plain = await makeTestPdf('rotate me');
    const encrypted = await encryptPdf(plain, 'old-pass');
    const rotated = await changePdfPassword(encrypted, 'old-pass', 'new-pass');

    await assert.rejects(() => decryptPdf(rotated, 'old-pass'), /WRONG_PASSWORD/);
    const result = await decryptPdf(rotated, 'new-pass');
    const text = await extractFirstPageText(result.bytes);
    assert.match(text, /rotate me/);
});

test('a distinct owner password also authenticates and unlocks the file', async () => {
    const plain = await makeTestPdf('owner test');
    const encrypted = await encryptPdf(plain, 'view-only-pass', { ownerPassword: 'master-pass' });

    const asUser = await decryptPdf(encrypted, 'view-only-pass');
    assert.equal(asUser.owner, false);
    assert.match(await extractFirstPageText(asUser.bytes), /owner test/);

    const asOwner = await decryptPdf(encrypted, 'master-pass');
    assert.equal(asOwner.owner, true);
    assert.match(await extractFirstPageText(asOwner.bytes), /owner test/);
});

test('unicode password round-trips correctly', async () => {
    const plain = await makeTestPdf('unicode password test');
    const pwd = 'Päsśwörð-\u{1F511}';
    const encrypted = await encryptPdf(plain, pwd);
    const result = await decryptPdf(encrypted, pwd);
    assert.match(await extractFirstPageText(result.bytes), /unicode password test/);
});

test('empty string password round-trips correctly', async () => {
    const plain = await makeTestPdf('empty password test');
    const encrypted = await encryptPdf(plain, '');
    const result = await decryptPdf(encrypted, '');
    assert.match(await extractFirstPageText(result.bytes), /empty password test/);
});

test('decryptPdf throws CORRUPT_PDF on unparseable input', async () => {
    const garbage = new Uint8Array(128).fill(0x42);
    await assert.rejects(() => decryptPdf(garbage, 'any'), /CORRUPT_PDF/);
});
