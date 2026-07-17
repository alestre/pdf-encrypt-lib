// PDF Standard Security Handler (ISO 32000-2, Version 5 / Revision 6, AES-256).
// pdf-lib has no built-in encryption support - this implements the spec directly
// on top of pdf-lib's low-level object model and node-forge's AES-CBC/SHA-2.
//
// Revision 6 (rather than the older Revision 4/AES-128) is used because it does
// not require RC4 anywhere (unlike R4, which needs RC4 for key derivation even
// when the content itself is AES-128-encrypted) - only AES-CBC and SHA-256/384/512,
// both provided by node-forge.

import forge from 'node-forge';
import saslprep from 'saslprep';
import { PDFDocument, PDFName, PDFHexString, PDFNumber, PDFBool, PDFDict, PDFStream, PDFRawStream, PDFString, PDFArray } from 'pdf-lib';

function randomBytes(n) {
    const arr = new Uint8Array(n);
    globalThis.crypto.getRandomValues(arr);
    return uint8ToBinaryString(arr);
}

function uint8ToBinaryString(u8) {
    const chunk = 8192;
    let s = '';
    for (let i = 0; i < u8.length; i += chunk) {
        s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return s;
}

function binaryStringToUint8(s) {
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i) & 0xff;
    return u8;
}

function bytesToHex(bin) {
    let hex = '';
    for (let i = 0; i < bin.length; i++) {
        const h = bin.charCodeAt(i).toString(16);
        hex += h.length === 1 ? '0' + h : h;
    }
    return hex;
}

// ISO 32000-2 §7.6.4.3.3 - SASLprep (RFC 4013) the password before UTF-8 encoding
// it, then truncate the resulting UTF-8 bytes to 127 (forge.util.encodeUtf8
// returns a JS binary string, one char per byte, so substring() truncates bytes,
// not code points). saslprep() throws on prohibited/unassigned characters or
// invalid bidi mixing (RFC 4013 §2.3-2.4); surfaced as a typed error to match
// the rest of this file's error-handling convention.
function preparePassword(password) {
    let prepped;
    try {
        // allowUnassigned: RFC 3454's "unassigned code points" table is frozen at
        // Unicode 3.2 (2002) - without this, any modern character absent from that
        // table (most emoji, many newer scripts) is rejected as "unassigned" even
        // though it's perfectly valid Unicode today. Mapping, NFKC normalization,
        // the prohibited-character list, and the bidi check all still apply.
        prepped = saslprep(password, { allowUnassigned: true });
    } catch (err) {
        throw new Error(`INVALID_PASSWORD: ${err.message}`);
    }
    return forge.util.encodeUtf8(prepped).substring(0, 127);
}

// PDF 1.5+ cross-reference streams almost always come with compressed object
// streams, which pdf-lib decompresses while parsing/accessing the document -
// before this library can supply the file key. Detect the structural feature
// up front instead of letting pdf-lib corrupt its object graph on encrypted,
// still-undecrypted object-stream bytes.
function usesXRefStream(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const s = uint8ToBinaryString(u8);
    const last = s.lastIndexOf('startxref');
    if (last === -1) return false; // ambiguous - let normal load/CORRUPT_PDF handling take over
    const m = /startxref\s+(\d+)/.exec(s.slice(last));
    if (!m) return false;
    const offset = Number(m[1]);
    if (offset < 0 || offset >= s.length) return false;
    const atOffset = s.slice(offset, offset + 4);
    if (!/^xref\b/.test(atOffset)) return true; // no classic keyword at the xref offset -> stream-based
    // classic table found, but a hybrid file can still carry object streams via /XRefStm
    const trailerIdx = s.indexOf('trailer', offset);
    const trailerBlock = trailerIdx === -1 ? '' : s.slice(trailerIdx, last);
    return /\/XRefStm\b/.test(trailerBlock);
}

function sha256(s) { const m = forge.md.sha256.create(); m.update(s); return m.digest().getBytes(); }
function sha384(s) { const m = forge.md.sha384.create(); m.update(s); return m.digest().getBytes(); }
function sha512(s) { const m = forge.md.sha512.create(); m.update(s); return m.digest().getBytes(); }

function aesCbcNoPad(key, iv, data, decrypt) {
    const op = decrypt ? forge.cipher.createDecipher('AES-CBC', key) : forge.cipher.createCipher('AES-CBC', key);
    op.start({ iv });
    op.update(forge.util.createBuffer(data));
    op.finish(() => true); // data is already block-aligned - skip PKCS7 pad/unpad
    return op.output.getBytes();
}

function aesCbcPkcs7Encrypt(key, iv, data) {
    const c = forge.cipher.createCipher('AES-CBC', key);
    c.start({ iv });
    c.update(forge.util.createBuffer(data));
    c.finish();
    return c.output.getBytes();
}

function aesCbcPkcs7Decrypt(key, iv, data) {
    const d = forge.cipher.createDecipher('AES-CBC', key);
    d.start({ iv });
    d.update(forge.util.createBuffer(data));
    if (!d.finish()) throw new Error('WRONG_PASSWORD');
    return d.output.getBytes();
}

// ISO 32000-2 Algorithm 2.B - hardened password hash (revision 6).
function hash2B(passwordBytes, saltBytes, userKeyBytes) {
    userKeyBytes = userKeyBytes || '';
    let K = sha256(passwordBytes + saltBytes + userKeyBytes);
    let round = 0;
    while (true) {
        const one = passwordBytes + K + userKeyBytes;
        const K1 = new Array(64).fill(one).join('');
        const E = aesCbcNoPad(K.substring(0, 16), K.substring(16, 32), K1, false);
        let sum = 0;
        for (let i = 0; i < 16; i++) sum += E.charCodeAt(i);
        const mod = sum % 3;
        K = mod === 0 ? sha256(E) : mod === 1 ? sha384(E) : sha512(E);
        round++;
        if (round >= 64 && E.charCodeAt(E.length - 1) <= round - 32) break;
    }
    return K.substring(0, 32);
}

function le32(n) {
    n = n >>> 0;
    return String.fromCharCode(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

function readLE32(s) {
    return (s.charCodeAt(0) | (s.charCodeAt(1) << 8) | (s.charCodeAt(2) << 16) | (s.charCodeAt(3) << 24)) >>> 0;
}

// Permission bits (ISO 32000-1 Table 22): grant print + high-res print + fill
// forms + accessibility extraction; deny modify/copy/annotate/assemble.
// Reserved bits (7, 8, 13-32) forced to 1 as required by the spec.
const DEFAULT_PERMISSIONS = ((4 | 2048 | 256 | 512) | (0xFFFFF000 | 0xC0)) >>> 0;

function computePerms(P, encryptMetadata, fileKey32) {
    const buf = le32(P) + '\xff\xff\xff\xff' + (encryptMetadata ? 'T' : 'F') + 'adb' + randomBytes(4);
    return aesCbcNoPad(fileKey32, '\x00'.repeat(16), buf, false);
}

function computeUandUE(userPwdBytes, fileKey32) {
    const validationSalt = randomBytes(8), keySalt = randomBytes(8);
    const hash = hash2B(userPwdBytes, validationSalt, null);
    const intermediateKey = hash2B(userPwdBytes, keySalt, null);
    return {
        U: hash + validationSalt + keySalt,
        UE: aesCbcNoPad(intermediateKey, '\x00'.repeat(16), fileKey32, false),
    };
}

function computeOandOE(ownerPwdBytes, U48, fileKey32) {
    const validationSalt = randomBytes(8), keySalt = randomBytes(8);
    const hash = hash2B(ownerPwdBytes, validationSalt, U48);
    const intermediateKey = hash2B(ownerPwdBytes, keySalt, U48);
    return {
        O: hash + validationSalt + keySalt,
        OE: aesCbcNoPad(intermediateKey, '\x00'.repeat(16), fileKey32, false),
    };
}

function authenticatePdfPassword(password, U48, O48, UE32, OE32) {
    const pwdBytes = preparePassword(password);
    const uVal = U48.substring(0, 32), uVSalt = U48.substring(32, 40), uKSalt = U48.substring(40, 48);
    if (hash2B(pwdBytes, uVSalt, null) === uVal) {
        const ik = hash2B(pwdBytes, uKSalt, null);
        return { fileKey: aesCbcNoPad(ik, '\x00'.repeat(16), UE32, true), owner: false };
    }
    const oVal = O48.substring(0, 32), oVSalt = O48.substring(32, 40), oKSalt = O48.substring(40, 48);
    if (hash2B(pwdBytes, oVSalt, U48) === oVal) {
        const ik2 = hash2B(pwdBytes, oKSalt, U48);
        return { fileKey: aesCbcNoPad(ik2, '\x00'.repeat(16), OE32, true), owner: true };
    }
    return null;
}

function encryptObjectAESV3(fileKey32, plaintext) {
    const iv = randomBytes(16);
    return iv + aesCbcPkcs7Encrypt(fileKey32, iv, plaintext);
}

function decryptObjectAESV3(fileKey32, data) {
    if (data.length <= 16) throw new Error('CORRUPT_PDF');
    return aesCbcPkcs7Decrypt(fileKey32, data.substring(0, 16), data.substring(16));
}

// Walk every indirect object in the document, transforming every PDFString/
// PDFHexString value and every raw stream's contents via fn(binaryString).
function walkDict(dict, fn) {
    dict.entries().forEach(([key, val]) => {
        const replaced = transformLeaf(val, fn);
        if (replaced !== val) dict.set(key, replaced);
        else transformPdfValue(val, fn);
    });
}

function transformPdfValue(obj, fn) {
    if (obj instanceof PDFStream) {
        walkDict(obj.dict, fn);
        if (obj instanceof PDFRawStream) obj.contents = binaryStringToUint8(fn(uint8ToBinaryString(obj.contents)));
    } else if (obj instanceof PDFDict) {
        walkDict(obj, fn);
    } else if (obj instanceof PDFArray) {
        for (let i = 0; i < obj.size(); i++) {
            const v = obj.get(i);
            const replaced = transformLeaf(v, fn);
            if (replaced !== v) obj.set(i, replaced);
            else transformPdfValue(v, fn);
        }
    }
}

function transformLeaf(val, fn) {
    if (val instanceof PDFHexString || val instanceof PDFString) {
        return PDFHexString.of(bytesToHex(fn(uint8ToBinaryString(val.asBytes()))));
    }
    return val;
}

function walkAndTransform(pdfDoc, fn) {
    pdfDoc.context.enumerateIndirectObjects().forEach(([, obj]) => transformPdfValue(obj, fn));
}

/**
 * Encrypt a PDF with AES-256.
 * @param {Uint8Array|ArrayBuffer} bytes - source PDF bytes
 * @param {string} password - the user (viewing) password
 * @param {{ ownerPassword?: string, permissions?: number }} [options] -
 *   ownerPassword defaults to `password` if not given, i.e. a single password
 *   unlocks the file with full permissions. Pass a different ownerPassword to
 *   issue a separate restricted viewing password vs. a full-access master
 *   password (see the PDF spec's user/owner password model).
 * @returns {Promise<Uint8Array>} encrypted PDF bytes
 */
export async function encryptPdf(bytes, password, options = {}) {
    // updateMetadata defaults to true - pdf-lib writes /Producer and /ModDate into
    // the Info dict right here in the constructor, so they're already real
    // objects in the graph before we enumerate and encrypt everything below.
    const doc = await PDFDocument.load(bytes);
    const fileKey = randomBytes(32);
    const pwdBytes = preparePassword(password);
    const ownerPwdBytes = preparePassword(options.ownerPassword ?? password);
    const permissions = options.permissions ?? DEFAULT_PERMISSIONS;

    walkAndTransform(doc, (raw) => encryptObjectAESV3(fileKey, raw));

    const uPair = computeUandUE(pwdBytes, fileKey);
    const oPair = computeOandOE(ownerPwdBytes, uPair.U, fileKey);
    const perms = computePerms(permissions, true, fileKey);

    const cf = doc.context.obj({
        StdCF: doc.context.obj({ CFM: PDFName.of('AESV3'), AuthEvent: PDFName.of('DocOpen'), Length: PDFNumber.of(32) }),
    });
    const encryptDict = doc.context.obj({
        Filter: PDFName.of('Standard'),
        V: PDFNumber.of(5),
        R: PDFNumber.of(6),
        Length: PDFNumber.of(256),
        O: PDFHexString.of(bytesToHex(oPair.O)),
        U: PDFHexString.of(bytesToHex(uPair.U)),
        OE: PDFHexString.of(bytesToHex(oPair.OE)),
        UE: PDFHexString.of(bytesToHex(uPair.UE)),
        P: PDFNumber.of(permissions | 0),
        Perms: PDFHexString.of(bytesToHex(perms)),
        EncryptMetadata: PDFBool.True,
        CF: cf,
        StmF: PDFName.of('StdCF'),
        StrF: PDFName.of('StdCF'),
    });
    doc.context.trailerInfo.Encrypt = doc.context.register(encryptDict);

    const idHex = PDFHexString.of(bytesToHex(randomBytes(16)));
    doc.context.trailerInfo.ID = doc.context.obj([idHex, idHex]);

    return doc.save({ useObjectStreams: false });
}

/**
 * Remove password protection from an encrypted PDF.
 * @param {Uint8Array|ArrayBuffer} bytes - encrypted PDF bytes
 * @param {string} password - either the user or the owner password
 * @returns {Promise<{ bytes: Uint8Array, owner: boolean, permissions: number, permissionsValid: boolean }>}
 *   permissionsValid is a non-fatal, defense-in-depth check (ISO 32000-2 Algorithm
 *   13): false means the plaintext /P entry doesn't match the encrypted /Perms
 *   value, e.g. because someone hand-edited /P after encryption. Permissions are
 *   advisory per spec, so this never rejects the file, callers may check it and
 *   decide what a mismatch should mean for them.
 * @throws {Error} with message 'NOT_ENCRYPTED', 'WRONG_PASSWORD', 'CORRUPT_PDF',
 *   'XREF_STREAM_UNSUPPORTED', or 'INVALID_PASSWORD'
 */
export async function decryptPdf(bytes, password) {
    // updateMetadata:false - otherwise pdf-lib's constructor unconditionally
    // overwrites /Producer and /ModDate with plaintext values before we get
    // a chance to decrypt the (still-encrypted) originals.
    let doc, encRef;
    try {
        doc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false });
        encRef = doc.context.trailerInfo.Encrypt;
    } catch {
        throw new Error('CORRUPT_PDF');
    }
    if (!encRef) throw new Error('NOT_ENCRYPTED');
    // Only a problem once we know there's actually something to decrypt - an
    // unencrypted xref-stream PDF loads and (re)saves through pdf-lib just fine.
    if (usesXRefStream(bytes)) {
        throw new Error(
            'XREF_STREAM_UNSUPPORTED: this PDF uses PDF 1.5+ cross-reference/object streams, ' +
            'which this library cannot decrypt. Pre-process it first, e.g. ' +
            '`qpdf --object-streams=disable in.pdf out.pdf`.'
        );
    }

    let U48, O48, UE32, OE32, P, Perms32;
    try {
        const encDict = doc.context.lookup(encRef);
        U48 = uint8ToBinaryString(encDict.lookup(PDFName.of('U')).asBytes());
        O48 = uint8ToBinaryString(encDict.lookup(PDFName.of('O')).asBytes());
        UE32 = uint8ToBinaryString(encDict.lookup(PDFName.of('UE')).asBytes());
        OE32 = uint8ToBinaryString(encDict.lookup(PDFName.of('OE')).asBytes());
        P = encDict.lookup(PDFName.of('P')).asNumber();
        Perms32 = uint8ToBinaryString(encDict.lookup(PDFName.of('Perms')).asBytes());
    } catch {
        throw new Error('CORRUPT_PDF');
    }

    const auth = authenticatePdfPassword(password, U48, O48, UE32, OE32);
    if (!auth) throw new Error('WRONG_PASSWORD');

    // ISO 32000-2 §7.6.4.4.7, Algorithm 13 (verification direction) - non-fatal
    // confirmation that /P wasn't hand-edited after encryption; see the JSDoc
    // above for why this doesn't throw.
    const permsPlain = aesCbcNoPad(auth.fileKey, '\x00'.repeat(16), Perms32, true);
    const permissionsValid = permsPlain.substring(9, 12) === 'adb' && readLE32(permsPlain) === (P >>> 0);

    doc.context.enumerateIndirectObjects().forEach(([ref, obj]) => {
        if (ref === encRef) return;
        transformPdfValue(obj, (raw) => decryptObjectAESV3(auth.fileKey, raw));
    });

    delete doc.context.trailerInfo.Encrypt;
    return { bytes: await doc.save({ useObjectStreams: false }), owner: auth.owner, permissions: P, permissionsValid };
}

/**
 * Change the password of an encrypted PDF (decrypt then re-encrypt).
 * @param {Uint8Array|ArrayBuffer} bytes
 * @param {string} oldPassword
 * @param {string} newPassword
 * @returns {Promise<Uint8Array>}
 */
export async function changePdfPassword(bytes, oldPassword, newPassword) {
    const plain = await decryptPdf(bytes, oldPassword);
    return encryptPdf(plain.bytes, newPassword, { permissions: plain.permissions });
}

export { DEFAULT_PERMISSIONS };
