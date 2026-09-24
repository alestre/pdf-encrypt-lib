# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- The library now loads in browser bundles. The `saslprep` package reads its
  code point tables with `fs.readFileSync` at import time, which crashed the
  whole page in a browser. It is replaced by `src/saslprep.js` and
  `src/saslprep-tables.js`: a plain-JS SASLprep (RFC 4013) with the full RFC 3454
  bidi check and no `fs` or `path` usage. The `saslprep` dependency is removed.
  Results are identical to the old package for every Unicode code point (checked
  exhaustively, alone and embedded in ASCII and Hebrew context), so existing
  encrypted files still open with the same passwords in Node and in the browser.

### Tests

- Bidi rules (RandALCat only, RandALCat mixed with LCat, RandALCat not at both
  ends), prohibited characters, space and soft hyphen mapping, a password that
  maps to nothing is rejected, and `src` contains no `saslprep`, `fs` or `path`
  import.

## [0.1.10] (2026-09-21)

### Added

- With `encryptMetadata: false`, `encryptPdf` now generates a minimal
  unencrypted XMP stream from the Info dictionary (title, author, subject,
  keywords) when the PDF has no `/Metadata` stream of its own. Previously the
  option only exempted an existing XMP stream, so PDFs that carry their
  metadata solely in the Info dictionary (e.g. anything written with pdf-lib's
  `setTitle()`) got no readable metadata at all, because Info entries are
  ordinary strings and stay encrypted per the spec. An existing XMP stream is
  left untouched; the Info dictionary itself remains encrypted.

### Tests

- Generated XMP contains the Info fields, escapes XML special characters and
  keeps non-ASCII text; it is not generated when `encryptMetadata` is true,
  when the Info dictionary has no fields, or when an XMP stream already exists.
- Interop: qpdf decrypts such a file and the Info dictionary and generated XMP
  both come out intact.

## [0.1.9] (2026-09-17)

### Added

- `encryptPdf` accepts `options.encryptMetadata` (default `true`). When set to
  `false`, the document's `/Metadata` (XMP) stream is left in plaintext, per
  ISO 32000-2, so indexing tools can read it without a password. `decryptPdf`
  reads the flag back from the `/Encrypt` dict and skips re-decrypting an
  already-plaintext metadata stream accordingly. `changePdfPassword` preserves
  the original document's `encryptMetadata` choice across rotation, same as it
  already does for `permissions`.

### Tests

- `encryptMetadata:false` leaves the `/Metadata` stream in plaintext; defaults
  to `true` and encrypts it otherwise.
- `changePdfPassword` preserves `encryptMetadata:false` across rotation.
- Interop: qpdf (an independent AES-256 implementation) confirms the
  `/Metadata` stream is readable and not corrupted by AES when
  `encryptMetadata:false` is used.

## [0.1.8] (2026-07-17)

### Fixed

- `encryptPdf` now preserves the document's permanent first `/ID` element
  (ISO 32000-2 §14.4) across re-encryption and rotates only the second
  element. Previously both elements were set to the same fresh random value on
  every call, discarding the document's permanent identity and making the two
  elements identical, both of which are spec violations.

### Tests

- Re-encrypting via `changePdfPassword` asserts that the first `/ID` element
  is unchanged and the second element is different.

## [0.1.7] (2026-07-17)

### Changed

- `changePdfPassword` now accepts an optional fourth argument `options`
  (same shape as `encryptPdf`'s `options`). Pass `options.ownerPassword` to
  set a distinct owner password on the re-encrypted document, preserving a
  two-password model across a rotation. Without it the behaviour is unchanged:
  both user and owner roles use `newPassword`. Original document permissions
  are still preserved unless explicitly overridden via `options.permissions`.

### Tests

- Rotating a two-password document with `options.ownerPassword` asserts that
  the old owner password is rejected, the new user password authenticates as
  user, and the new owner password authenticates as owner.

## [0.1.6] (2026-07-17)

### Fixed

- `decryptObjectAESV3` now correctly throws `Error('CORRUPT_PDF')` for any
  ciphertext shorter than 32 bytes (16-byte IV + one minimum 16-byte PKCS7
  block). Previously only lengths 0-16 were caught; lengths 17-31 passed the
  guard and reached `aesCbcPkcs7Decrypt`, which threw `WRONG_PASSWORD` because
  forge's CBC decrypter fails PKCS7 unpadding on a sub-block input. A caller
  receiving `WRONG_PASSWORD` would naturally suspect the password, not file
  corruption.

### Documented

- `changePdfPassword` JSDoc now explicitly states that it collapses a
  two-password document (distinct user/owner passwords) into a single password,
  and points callers who need to preserve the two-password model to `decryptPdf`
  + `encryptPdf` directly.

### Tests

- The short-ciphertext test now exercises both the 0-16 byte range (previous
  guard) and the 17-31 byte range (newly fixed), asserting `CORRUPT_PDF` for
  both.

## [0.1.5] (2026-07-17)

### Added

- `decryptPdf` now returns a `permissionsValid` field (ISO 32000-2 Algorithm 13
  verification): decrypts `/Perms` with the derived file key and checks it
  against the plaintext `/P` entry, catching the case where `/P` was hand-edited
  after encryption. Non-fatal, matching pypdf/qpdf's own behavior, since
  permissions are advisory per spec; callers may check the field and decide what
  a mismatch should mean for them.

### Tests

- Encrypt/decrypt round-trip asserts `permissionsValid: true`.
- Tampering with `/P` after encryption (without touching `/Perms`) asserts
  `permissionsValid: false`, while decryption still succeeds and content is
  still correctly decrypted.

## [0.1.4] (2026-07-17)

### Fixed

- `decryptObjectAESV3` now throws `Error('CORRUPT_PDF')` instead of silently
  returning an empty string for a per-object ciphertext of 16 bytes or fewer.
  Nothing legitimate should ever be that short (minimum valid encrypted output
  is 32 bytes), so this only affects corrupted or adversarial input, which
  previously decrypted to silent empty content instead of a diagnostic error.

### Tests

- Corrupted per-object ciphertext (shrunk below the minimum valid length)
  asserts `CORRUPT_PDF` instead of silently succeeding with empty content.

## [0.1.3] (2026-07-17)

### Fixed

- `changePdfPassword` now preserves the original document's `permissions`
  across a password rotation instead of silently resetting them to
  `DEFAULT_PERMISSIONS`. `decryptPdf`'s return value gained a `permissions`
  field carrying the decrypted `/P` value.
- Passwords are now processed with SASLprep (RFC 4013, ISO 32000-2 §7.6.4.3.3)
  before UTF-8 encoding, so Unicode-equivalent but differently-composed
  passwords (e.g. NFC vs NFD) are treated as the same password, matching
  spec-compliant readers. Unassigned-code-point rejection is relaxed
  (`allowUnassigned: true`) since RFC 3454's table is frozen at Unicode 3.2
  and would otherwise reject most modern characters, including emoji.
  Malformed passwords (prohibited characters, invalid bidi mixing) now throw
  `Error('INVALID_PASSWORD: ...')` instead of silently hashing them as-is.
- The UTF-8-encoded password is now truncated to 127 bytes before hashing,
  matching the V5/R6 key-computation algorithm; previously a longer password
  derived a different key than a spec-compliant reader.

### Tests

- Password rotation preserves custom `permissions`.
- NFC vs NFD forms of the same password both authenticate the same file.
- Two passwords sharing the same first 127 UTF-8 bytes both authenticate the
  same file.

## [0.1.2] (2026-07-17)

### Fixed

- `decryptPdf` now throws `Error('XREF_STREAM_UNSUPPORTED: ...')` with guidance to
  pre-process via `qpdf --object-streams=disable` for PDFs that use PDF 1.5+
  cross-reference/object streams (the default output of qpdf, Acrobat, and most
  modern generators). Previously this either surfaced a misleading `CORRUPT_PDF`
  or crashed deep inside pdf-lib with `Expected instance of PDFDict, but got
  instance of undefined`, because pdf-lib decompresses object streams while
  parsing/accessing the document, before this library can supply the file key.

## [0.1.1] (2026-07-17)

### Fixed

- `decryptPdf` now throws `Error('CORRUPT_PDF')` instead of leaking raw
  pdf-lib or forge exceptions when the input bytes are unparseable or the
  encryption dictionary is missing required fields (U, O, UE, OE). The
  existing `NOT_ENCRYPTED` and `WRONG_PASSWORD` errors are unaffected.

### Tests

- Unicode and non-BMP password round-trip (`"Päsśwörð-🔑"`)
- Empty string password round-trip
- Garbage input to `decryptPdf` asserts `CORRUPT_PDF`
- Reverse interop: qpdf-encrypted PDF decrypted by this library

## [0.1.0] (2026-07-15)

Initial release. AES-256 PDF encryption and decryption implementing
ISO 32000-2 revision 6 (V=5, R=6, AESV3) on top of pdf-lib and
node-forge.
