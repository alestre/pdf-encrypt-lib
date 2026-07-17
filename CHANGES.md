# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-07-17

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

## [0.1.4] - 2026-07-17

### Fixed

- `decryptObjectAESV3` now throws `Error('CORRUPT_PDF')` instead of silently
  returning an empty string for a per-object ciphertext of 16 bytes or fewer.
  Nothing legitimate should ever be that short (minimum valid encrypted output
  is 32 bytes), so this only affects corrupted or adversarial input, which
  previously decrypted to silent empty content instead of a diagnostic error.

### Tests

- Corrupted per-object ciphertext (shrunk below the minimum valid length)
  asserts `CORRUPT_PDF` instead of silently succeeding with empty content.

## [0.1.3] - 2026-07-17

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

## [0.1.2] - 2026-07-17

### Fixed

- `decryptPdf` now throws `Error('XREF_STREAM_UNSUPPORTED: ...')` with guidance to
  pre-process via `qpdf --object-streams=disable` for PDFs that use PDF 1.5+
  cross-reference/object streams (the default output of qpdf, Acrobat, and most
  modern generators). Previously this either surfaced a misleading `CORRUPT_PDF`
  or crashed deep inside pdf-lib with `Expected instance of PDFDict, but got
  instance of undefined`, because pdf-lib decompresses object streams while
  parsing/accessing the document, before this library can supply the file key.

## [0.1.1] - 2026-07-17

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

## [0.1.0] - 2026-07-15

Initial release. AES-256 PDF encryption and decryption implementing
ISO 32000-2 revision 6 (V=5, R=6, AESV3) on top of pdf-lib and
node-forge.
