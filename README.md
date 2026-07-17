# pdf-encrypt-lib

Password protection for [pdf-lib](https://github.com/Hopding/pdf-lib), which has no built-in encryption support ([long-standing open feature request](https://github.com/Hopding/pdf-lib/issues?q=encrypt)).

Built for [PDF File Manager](https://ascend-digital.net/tools/pdffile/) by [Ascend Digital](https://ascend-digital.net).

[Codeberg](https://codeberg.org/alestre/pdf-encrypt-lib) · [GitHub](https://github.com/alestre/pdf-encrypt-lib)

Implements the PDF Standard Security Handler, Version 5 / Revision 6 (AES-256), as specified in ISO 32000-2, directly on top of pdf-lib's object model. Works in both Node.js (18.19+/19+, for `globalThis.crypto`) and modern browsers.

Revision 6 was chosen over the older Revision 4 (AES-128) because R4's key derivation requires RC4 even though the content itself is AES-encrypted. R6 needs only AES-CBC and SHA-256/384/512, both already provided by [node-forge](https://github.com/digitalbazaar/forge).

## Scope

This is an open-source building block, not a managed solution. It is published so other developers can build on it. If you integrate it into your own project, you own that integration - review the source, run your own tests, and decide for yourself whether it fits your security requirements.

## Known limitation: xref streams

This library cannot decrypt PDFs that use PDF 1.5+ cross-reference streams (object streams / xref streams). Most modern PDF generators produce this format by default, including qpdf, Acrobat, and most web-based PDF tools.

**Symptom:** `Error('XREF_STREAM_UNSUPPORTED: ...')` when calling `decryptPdf`.

**Workaround:** pre-process the file with [qpdf](https://qpdf.readthedocs.io/):

```
qpdf --object-streams=disable input.pdf output.pdf
```

This is a limitation of [pdf-lib's parser](https://github.com/Hopding/pdf-lib), which decompresses object streams during load - before this library can supply the file key. It cannot be worked around at this layer without replacing the parser.

## Install

Not yet published to npm. Install directly from the repository:

```
npm install git+https://codeberg.org/alestre/pdf-encrypt-lib.git pdf-lib node-forge
```

`pdf-lib` and `node-forge` are peer dependencies. Install them alongside this package.

## Usage

```js
import { PDFDocument } from 'pdf-lib';
import { encryptPdf, decryptPdf, changePdfPassword } from 'pdf-encrypt-lib';

const doc = await PDFDocument.create();
// ... build your document ...
const plainBytes = await doc.save();

// Protect
const encryptedBytes = await encryptPdf(plainBytes, 'my-password');

// Open (throws Error('WRONG_PASSWORD') or Error('NOT_ENCRYPTED'))
const { bytes: decryptedBytes, owner } = await decryptPdf(encryptedBytes, 'my-password');

// Change password (decrypt + re-encrypt)
const rotatedBytes = await changePdfPassword(encryptedBytes, 'my-password', 'new-password');

// Remove protection entirely
const { bytes: unprotectedBytes } = await decryptPdf(encryptedBytes, 'my-password');
```

### Separate user and owner passwords

The PDF spec distinguishes a *user* password (needed to open/view the file) from an *owner* password (grants full permissions regardless of the `permissions` restrictions below). By default both are the same value; pass `ownerPassword` to set a master password separate from the viewing password:

```js
await encryptPdf(bytes, 'view-only-password', { ownerPassword: 'master-password' });
```

`decryptPdf()` accepts either password and returns `{ bytes, owner }`, where `owner` tells you which one was used. `changePdfPassword()` accepts the same `options` as `encryptPdf`, so you can rotate both passwords independently:

```js
await changePdfPassword(bytes, 'old-pass', 'new-user-pass', { ownerPassword: 'new-owner-pass' });
```

### Permissions

```js
import { encryptPdf, DEFAULT_PERMISSIONS } from 'pdf-encrypt-lib';

await encryptPdf(bytes, 'password', { permissions: DEFAULT_PERMISSIONS });
```

`permissions` is the raw 32-bit `/P` permission bitmask from ISO 32000-1 Table 22 (bit 3 = print, bit 4 = modify, bit 5 = copy, bit 6 = annotate, bit 9 = fill forms, bit 10 = extract for accessibility, bit 11 = assemble document, bit 12 = high-res print; reserved bits 7, 8 and 13-32 must stay `1`). `DEFAULT_PERMISSIONS` grants printing and denies modify/copy/annotate/assemble.

## API

- `encryptPdf(bytes, password, options?) -> Promise<Uint8Array>`
- `decryptPdf(bytes, password) -> Promise<{ bytes: Uint8Array, owner: boolean }>`
- `changePdfPassword(bytes, oldPassword, newPassword, options?) -> Promise<Uint8Array>`
- `DEFAULT_PERMISSIONS`: the permission bitmask used when `options.permissions` isn't given

`decryptPdf` throws `Error('NOT_ENCRYPTED')` if the input has no `/Encrypt` dictionary, and `Error('WRONG_PASSWORD')` if authentication fails.

## How it works

- Every indirect string and raw stream in the document is walked and encrypted/decrypted individually with AES-256-CBC, using a random 16-byte IV prepended to each ciphertext (`walkAndTransform` in `src/index.js`).
- The file encryption key is a random 32 bytes, wrapped separately for the user and owner password via ISO 32000-2 Algorithm 2.B (a "hardened" hash: SHA-256, then 64+ rounds of AES-128-CBC re-encryption alternating between SHA-256/384/512 depending on a checksum of each round's output).
- Unlike Revision 4, V5/R6 uses the file encryption key directly for every object, without per-object key derivation.
- Two pdf-lib quirks are worked around: `PDFRawStream` is not a `PDFDict` (separate class, so its `.dict` needs walking separately from its `.contents`), and `PDFDocument`'s constructor unconditionally overwrites `/Producer`/`/ModDate` unless `updateMetadata: false` is passed when loading an already-encrypted file for decryption.

## Testing

```
npm test
```

The test suite has two parts:

- [`test/roundtrip.test.js`](test/roundtrip.test.js) round-trips encrypt/decrypt/change-password through this library's own code.
- [`test/interop.test.js`](test/interop.test.js) cross-validates against independent tools: [qpdf](https://qpdf.readthedocs.io/) (our output decrypted by qpdf, and qpdf-encrypted files decrypted by us) and [poppler](https://poppler.freedesktop.org/) (text extraction from our encrypted output). These tests are skipped automatically if the tools are not installed. They exist to catch spec compliance bugs that pure self-consistency tests cannot find.

## Changelog

See [CHANGES.md](CHANGES.md).

## License

MIT

---

If this library saved you time, [Monero donations are welcome](https://xmrchat.com/alestre).
