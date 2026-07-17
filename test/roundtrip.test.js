import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inflateSync } from 'node:zlib';
import { PDFDocument, StandardFonts, PDFName, PDFNumber, PDFArray, PDFRawStream } from 'pdf-lib';
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
    assert.equal(result.permissionsValid, true);
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

test('changePdfPassword preserves custom permissions instead of resetting to DEFAULT_PERMISSIONS', async () => {
    const plain = await makeTestPdf('permissions rotate test');
    const customPermissions = (4 | 0xFFFFF000 | 0xC0) >>> 0; // print only, reserved bits set
    const encrypted = await encryptPdf(plain, 'old-pass', { permissions: customPermissions });
    const rotated = await changePdfPassword(encrypted, 'old-pass', 'new-pass');

    const result = await decryptPdf(rotated, 'new-pass');
    assert.equal(result.permissions, customPermissions | 0);
});

test('SASLprep-normalizes the password, so NFC and NFD forms of the same password are equivalent', async () => {
    const plain = await makeTestPdf('saslprep test');
    const nfc = 'café'.normalize('NFC');
    const nfd = 'café'.normalize('NFD');
    assert.notEqual(nfc, nfd);

    const encrypted = await encryptPdf(plain, nfc);
    const result = await decryptPdf(encrypted, nfd);
    assert.match(await extractFirstPageText(result.bytes), /saslprep test/);
});

test('only the first 127 UTF-8 bytes of a password are significant', async () => {
    const plain = await makeTestPdf('long password test');
    const base = 'x'.repeat(127);
    const longPwd = base + 'A'.repeat(50);
    const alsoValidPwd = base + 'B'.repeat(50);

    const encrypted = await encryptPdf(plain, longPwd);
    const result = await decryptPdf(encrypted, alsoValidPwd);
    assert.match(await extractFirstPageText(result.bytes), /long password test/);
});

test('decryptPdf throws CORRUPT_PDF instead of silently emptying a too-short encrypted object', async () => {
    const plain = await makeTestPdf('short ciphertext test');
    const encrypted = await encryptPdf(plain, 'shrink-me');

    // The minimum valid AESV3 ciphertext is 32 bytes: 16-byte IV + at least one
    // 16-byte PKCS7-padded AES block. Test both sides of that boundary: well
    // below it (5 bytes, hits the old <= 16 guard) and in the 17-31 byte band
    // that previously slipped through and threw WRONG_PASSWORD instead.
    for (const size of [5, 17]) {
        const doc = await PDFDocument.load(encrypted, { ignoreEncryption: true, updateMetadata: false });
        const [, someStream] = doc.context.enumerateIndirectObjects().find(([, obj]) => obj instanceof PDFRawStream);
        someStream.contents = new Uint8Array(size);
        const corrupted = await doc.save({ useObjectStreams: false });
        await assert.rejects(() => decryptPdf(corrupted, 'shrink-me'), /CORRUPT_PDF/,
            `expected CORRUPT_PDF for ${size}-byte ciphertext`);
    }
});

test('decryptPdf flags permissionsValid: false when /P is tampered with, without rejecting the file', async () => {
    const plain = await makeTestPdf('perms tamper test');
    const encrypted = await encryptPdf(plain, 'perms-pass');

    // Flip /P to "grant everything" without touching /Perms, simulating an
    // attacker with the correct password hand-editing the plaintext permission
    // bits. /Perms was computed from the original /P, so decrypting it with the
    // (still-correct) file key won't reproduce this new /P value.
    const doc = await PDFDocument.load(encrypted, { ignoreEncryption: true, updateMetadata: false });
    const encDict = doc.context.lookup(doc.context.trailerInfo.Encrypt);
    encDict.set(PDFName.of('P'), PDFNumber.of(-1));
    const tampered = await doc.save({ useObjectStreams: false });

    const result = await decryptPdf(tampered, 'perms-pass');
    assert.equal(result.permissionsValid, false);
    assert.match(await extractFirstPageText(result.bytes), /perms tamper test/);
});
