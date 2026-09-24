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

async function makeTestPdfWithMetadata(text) {
    const doc = await PDFDocument.create();
    const page = doc.addPage([595, 842]);
    const font = await doc.embedFont(StandardFonts.Helvetica);
    page.drawText(text, { x: 50, y: 780, size: 14, font });

    const xmp = '<x:xmpmeta xmlns:x="adobe:ns:meta/">PLAINTEXT-METADATA-MARKER</x:xmpmeta>';
    const metadataStream = doc.context.flateStream(xmp, { Type: 'Metadata', Subtype: 'XML' });
    const metadataRef = doc.context.register(metadataStream);
    doc.catalog.set(PDFName.of('Metadata'), metadataRef);

    return doc.save();
}

// Loads without decrypting (ignoreEncryption) and inflates the /Metadata stream's
// raw bytes directly - only valid deflate data (i.e. plaintext) inflates cleanly.
async function extractMetadataStreamRaw(bytes) {
    const doc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false });
    const metaRef = doc.catalog.get(PDFName.of('Metadata'));
    const metaStream = doc.context.lookup(metaRef);
    return inflateSync(Buffer.from(metaStream.contents)).toString('latin1');
}

// Info-dictionary-only PDF (no XMP), the shape pdf-lib's setTitle()/setAuthor() produce.
async function makeInfoOnlyPdf(info) {
    const doc = await PDFDocument.create();
    doc.setTitle(info.title);
    doc.setAuthor(info.author);
    if (info.subject) doc.setSubject(info.subject);
    if (info.keywords) doc.setKeywords(info.keywords);
    doc.addPage([200, 200]);
    return doc.save();
}

// Reads the /Metadata stream bytes as UTF-8 without decrypting; returns null if absent.
// Generated XMP is stored uncompressed, so no inflate here.
async function readXmpUnencrypted(bytes) {
    const doc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false });
    const ref = doc.catalog.get(PDFName.of('Metadata'));
    if (!ref) return null;
    return Buffer.from(doc.context.lookup(ref).contents).toString('utf8');
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

test('SASLprep bidi rules: an all-RandALCat password round-trips', async () => {
    const plain = await makeTestPdf('bidi ok test');
    const hebrew = 'שלום';
    const encrypted = await encryptPdf(plain, hebrew);
    const result = await decryptPdf(encrypted, hebrew);
    assert.match(await extractFirstPageText(result.bytes), /bidi ok test/);
});

test('SASLprep bidi rules: mixing RandALCat and LCat throws INVALID_PASSWORD', async () => {
    const plain = await makeTestPdf('bidi mixed test');
    await assert.rejects(() => encryptPdf(plain, 'abcשלום'), /INVALID_PASSWORD/);
});

test('SASLprep bidi rules: RandALCat must be first and last character', async () => {
    const plain = await makeTestPdf('bidi edge test');
    await assert.rejects(() => encryptPdf(plain, 'שלום1'), /INVALID_PASSWORD/);
});

test('SASLprep prohibits control characters and maps non-ASCII spaces and soft hyphens', async () => {
    const plain = await makeTestPdf('prohibit map test');
    await assert.rejects(() => encryptPdf(plain, 'a\u0007b'), /INVALID_PASSWORD/);

    const encrypted = await encryptPdf(plain, 'a b');
    const result = await decryptPdf(encrypted, 'a b­');
    assert.match(await extractFirstPageText(result.bytes), /prohibit map test/);
});

test('a non-empty password that SASLprep maps to nothing is rejected, not silently emptied', async () => {
    const plain = await makeTestPdf('maps to nothing test');
    await assert.rejects(() => encryptPdf(plain, '­'), /INVALID_PASSWORD/);
});

test('src has no saslprep or fs import, so the library loads in a browser bundle', async () => {
    const { readdir, readFile } = await import('node:fs/promises');
    const dir = new URL('../src/', import.meta.url);
    for (const name of await readdir(dir)) {
        const source = await readFile(new URL(name, dir), 'utf8');
        assert.doesNotMatch(source, /from\s+['"](saslprep|fs|node:fs|path|node:path)['"]/, name);
    }
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

test('/ID first element is preserved and second element is rotated on re-encryption', async () => {
    const plain = await makeTestPdf('id rotation test');
    const encrypted = await encryptPdf(plain, 'pass');

    const doc1 = await PDFDocument.load(encrypted, { ignoreEncryption: true, updateMetadata: false });
    const firstId1 = Buffer.from(doc1.context.trailerInfo.ID.get(0).asBytes());
    const secondId1 = Buffer.from(doc1.context.trailerInfo.ID.get(1).asBytes());

    const rotated = await changePdfPassword(encrypted, 'pass', 'new-pass');
    const doc2 = await PDFDocument.load(rotated, { ignoreEncryption: true, updateMetadata: false });
    const firstId2 = Buffer.from(doc2.context.trailerInfo.ID.get(0).asBytes());
    const secondId2 = Buffer.from(doc2.context.trailerInfo.ID.get(1).asBytes());

    assert.deepEqual(firstId1, firstId2, 'first /ID element must be preserved across re-encryption');
    assert.notDeepEqual(secondId1, secondId2, 'second /ID element must be rotated on re-encryption');
});

test('changePdfPassword with options.ownerPassword sets a distinct new owner password', async () => {
    const plain = await makeTestPdf('two-password rotate test');
    const encrypted = await encryptPdf(plain, 'user-pass', { ownerPassword: 'old-owner' });
    const rotated = await changePdfPassword(encrypted, 'old-owner', 'new-user', { ownerPassword: 'new-owner' });

    await assert.rejects(() => decryptPdf(rotated, 'old-owner'), /WRONG_PASSWORD/);
    const asUser = await decryptPdf(rotated, 'new-user');
    assert.equal(asUser.owner, false);
    const asOwner = await decryptPdf(rotated, 'new-owner');
    assert.equal(asOwner.owner, true);
    assert.match(await extractFirstPageText(asOwner.bytes), /two-password rotate test/);
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

test('encryptMetadata:false leaves the /Metadata stream in plaintext', async () => {
    const plain = await makeTestPdfWithMetadata('metadata test');
    const encrypted = await encryptPdf(plain, 'pw', { encryptMetadata: false });

    const metaText = await extractMetadataStreamRaw(encrypted);
    assert.match(metaText, /PLAINTEXT-METADATA-MARKER/);

    const result = await decryptPdf(encrypted, 'pw');
    assert.equal(result.encryptMetadata, false);
    assert.match(await extractFirstPageText(result.bytes), /metadata test/);
});

test('encryptMetadata defaults to true and encrypts the /Metadata stream', async () => {
    const plain = await makeTestPdfWithMetadata('metadata default test');
    const encrypted = await encryptPdf(plain, 'pw');

    await assert.rejects(() => extractMetadataStreamRaw(encrypted));

    const result = await decryptPdf(encrypted, 'pw');
    assert.equal(result.encryptMetadata, true);
    assert.match(await extractFirstPageText(result.bytes), /metadata default test/);
});

test('changePdfPassword preserves encryptMetadata:false across rotation', async () => {
    const plain = await makeTestPdfWithMetadata('metadata rotate test');
    const encrypted = await encryptPdf(plain, 'old-pass', { encryptMetadata: false });
    const rotated = await changePdfPassword(encrypted, 'old-pass', 'new-pass');

    const metaText = await extractMetadataStreamRaw(rotated);
    assert.match(metaText, /PLAINTEXT-METADATA-MARKER/);

    const result = await decryptPdf(rotated, 'new-pass');
    assert.equal(result.encryptMetadata, false);
    assert.match(await extractFirstPageText(result.bytes), /metadata rotate test/);
});

test('encryptMetadata:false generates a plaintext XMP from the Info dictionary when the PDF has none', async () => {
    const plain = await makeInfoOnlyPdf({ title: 'Quarterly Report', author: 'Jane Doe', subject: 'Finance', keywords: ['q3', 'budget'] });
    const encrypted = await encryptPdf(plain, 'pw', { encryptMetadata: false });

    const xmp = await readXmpUnencrypted(encrypted);
    assert.ok(xmp, 'expected a /Metadata stream to be generated');
    assert.match(xmp, /Quarterly Report/);
    assert.match(xmp, /Jane Doe/);
    assert.match(xmp, /Finance/);
    assert.match(xmp, /q3 budget/);

    const result = await decryptPdf(encrypted, 'pw');
    assert.equal(result.encryptMetadata, false);
});

test('generated XMP escapes XML special characters and keeps non-ASCII text', async () => {
    const plain = await makeInfoOnlyPdf({ title: 'Tom & Jerry <"draft">', author: 'Zoë Müller' });
    const encrypted = await encryptPdf(plain, 'pw', { encryptMetadata: false });

    const xmp = await readXmpUnencrypted(encrypted);
    assert.match(xmp, /Tom &amp; Jerry &lt;&quot;draft&quot;&gt;/);
    assert.match(xmp, /Zoë Müller/);
    assert.doesNotMatch(xmp, /Tom & Jerry/);
});

test('encryptMetadata:false does not overwrite an existing XMP stream', async () => {
    const plain = await makeTestPdfWithMetadata('existing xmp');
    const encrypted = await encryptPdf(plain, 'pw', { encryptMetadata: false });
    assert.match(await extractMetadataStreamRaw(encrypted), /PLAINTEXT-METADATA-MARKER/);
});

test('no XMP is generated when encryptMetadata is true or the Info dictionary carries no fields', async () => {
    const withInfo = await makeInfoOnlyPdf({ title: 'Secret Title', author: 'Secret Author' });
    assert.equal(await readXmpUnencrypted(await encryptPdf(withInfo, 'pw')), null);

    const doc = await PDFDocument.create();
    doc.setProducer('');
    doc.setCreator('');
    doc.addPage([200, 200]);
    const empty = await doc.save();
    assert.equal(await readXmpUnencrypted(await encryptPdf(empty, 'pw', { encryptMetadata: false })), null);
});