# Changelog

All notable changes to this project will be documented in this file.

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
