# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Added

#### Imported passkey credential (2026-09-04)

- `AuthenticatorAPI._parse_import_file` parses a raw `bwu fido2 get` `key: value`
  block (with embedded PEM private key), or a legacy JSON document.
- `AuthenticatorAPI._maybe_imported_assertion` signs `getAssertion` with the
  imported credential, enforcing a **strict `allowList`** match: the returned
  credential ID must be present in IBKR's `allowList` (or the request must be
  discoverable / empty list).
- New env var `SOFT_FIDO2_IMPORT_FILE` points at the imported passkey file.
  The `SOFT_FIDO2_IMPORT_IGNORE_ALLOWLIST` escape hatch was removed — bypassing
  `allowList` is futile because the browser enforces it locally.

See [`docs/IBKR-UNATTENDED.md`](docs/IBKR-UNATTENDED.md) for the full account.

#### Multiple imported passkeys (2026-09-04)

- `SOFT_FIDO2_IMPORT_DIR` loads every regular file in a directory as an imported
  passkey, so a single authenticator can serve several IBKR accounts.
- `SOFT_FIDO2_IMPORT_FILE` now also accepts a comma-separated list of paths.
- `_maybe_imported_assertion` picks the first imported credential whose `rpId`
  matches and whose id is in the incoming `allowList` (or the first matching
  credential for a discoverable / empty-list request).

---

### ⚠️ BREAKING CHANGES

#### Passkey Storage Format Change (2026-05-18)

**Passkey files now split into two separate files:**
- `.passkey` - Contains encrypted credential data
- `.stash` - Contains encrypted hash header (230 bytes)

**Migration Required:**
- Old single-file format is **NOT supported**
- You **MUST regenerate** all passkey files before upgrading
- Old passkey files will be ignored by the system

**What to do:**
1. Back up your existing passkey files (optional)
2. Delete old `.passkey` files from `~/.fido/` (or `$FIDO_HOME`)
3. Re-register your passkeys with websites/applications
4. New passkeys will automatically use the two-file format

---
