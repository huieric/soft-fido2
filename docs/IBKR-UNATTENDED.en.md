# Unattended IBKR Passkey Login — Full Journey & Conclusions

This document records the complete process of enabling **unattended passkey
login for IB Gateway** on AWS, the dead-ends we hit, and the final engineering
conclusions. Its intended audience is whoever maintains this system next.

## 1. Final architecture (working)

```
┌─────────────────────────────── AWS host ───────────────────────────────┐
│                                                                        │
│  soft-fido2 container           IB Gateway container (ibga)            │
│  (network_mode: host)           (mounts /dev/bus/usb + /dev/hidraw*)   │
│  software authenticator +       embedded Chromium (JxBrowser)          │
│  imported private key                                                   │
│  TCP :3240 USB/IP server ─────▶ libusb enumerates a real USB device    │
│                                      │                                  │
│                                auto-click Authenticate (xdotool/JAuto) │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

- **Authenticator**: `huieric/soft-fido2`, imports a Bitwarden-exported passkey
  private key and presents it as a real USB device (`vendor/product 0x3713`)
  over USB/IP.
- **Clicker**: `huieric/ibga-docker`, auto-clicks the Authenticate button when
  `AUTH_METHOD=passkey`.
- **Why USB/IP instead of UHID**: IB Gateway's passkey UI runs in an embedded
  Chromium that enumerates FIDO keys on the **USB bus** via libusb; a `/dev/uhid`
  virtual HID device is not on the USB bus, so Chromium cannot see it.

## 2. Key conclusion: `allowList` is enforced by the browser

This is the single most important conclusion of the whole effort; it determined
the approach.

IBKR's `getAssertion` request carries an `allowList` (the set of allowed
credential IDs). **This list is enforced locally by the browser
(Chromium/Firefox/JxBrowser)**, not just verified by the server:

- The returned credential ID **must be in the allowList**; otherwise the browser
  drops the response and raises `SecurityError`, and the request never reaches
  the server.
- Trying to make the authenticator "force-return a credential outside the list"
  (e.g. `IGNORE_ALLOWLIST`) is **futile** — it fails at the browser.

This means: **you cannot log in with a credential registered elsewhere.** The
credential must be registered under this IBKR account, and its ID appears in the
allowList.

## 3. Dead-ends we hit (chronological)

1. **A cascade of transport-layer bugs**: byte order, exact-fit single-frame
   dispatch, U2F cross-frame reassembly (`bcnt=73`), multi-frame response
   starvation (missing `response_ready`), and `colour_print` only emitting DEBUG.
   Lesson: **diagnostic logs must be INFO level**, otherwise a headless
   environment cannot be debugged at all.

2. **The PIN dialog cannot be driven**: the embedded Chromium PIN input in
   JxBrowser does not accept X11 keyboard events (manual noVNC input fails too;
   screen-grab OCR shows the dialog timing out). Lesson: **do not try to automate
   Chromium's PIN prompt**.

3. **Switching to built-in UV mode**: `getInfo` advertises
   `{'rk': True, 'up': True, 'uv': True, 'plat': False}` (no `clientPin`), and
   `SOFT_FIDO2_SKIP_UP=true` caches the "verified" state to bypass PIN. UV
   negotiation succeeds; `getAssertion` arrives.

4. **Credential mismatch (the key blocker)**: IBKR's allowList contained only the
   Windows Hello credential `1024xxxx...`, while the local Bitwarden credential
   `b09axxxx...` was not listed → `NO_CREDENTIALS` → "Try a different security key".

5. **Attempting to force-return the Bitwarden credential**: added
   `SOFT_FIDO2_IMPORT_IGNORE_ALLOWLIST` so the authenticator signs regardless of
   allowList. Result: the same challenge was retried 3 times (rejected locally by
   the browser); login still failed. This confirmed conclusion 2.

6. **Trying to register a new credential directly via Firefox/Chromium**:
   - Firefox strictly enforces `transports:["internal"]` and does not route the
     request to a USB device.
   - Under Marionette automation, WebAuthn is disabled (`SecurityError: insecure`).
   - The rpId `interactivebrokers.com.hk` does not match the page origin
     `ndcdyn.interactivebrokers.com` → domain-suffix validation fails.

## 4. Final solution (working)

**Register a new passkey for the IBKR account in Bitwarden, export it, import it
into soft-fido2.**

1. Register a new passkey via the Bitwarden browser extension in Client Portal.
   IBKR accepts `none` attestation (the legitimate path for software/synced
   passkeys).
2. Export it with `bwu fido2 get "<entry>"`, keeping the raw `key: value` text
   format (no JSON conversion).
3. Mount the file into soft-fido2 and set `SOFT_FIDO2_IMPORT_FILE` (or
   `SOFT_FIDO2_IMPORT_DIR` for multiple accounts). The authenticator parses the
   `key: value` block (with the embedded PEM private key), decodes the hyphenated
   `credentialId` to 16 bytes, and signs `getAssertion` when the credential is in
   the allowList.
4. The new credential `01234567-89ab-cdef-0123-456789abcdef` now appears in the
   allowList → strict match → signature → login succeeds.

Verification markers (IB Gateway log):
```
Passed session token authentication
Authenticated via ccp conman
Connected to cdc1.ibllc.com:4000
```

## 5. Key lessons

| Lesson | Detail |
|------|------|
| allowList is browser-enforced | Returning a credential outside the list always fails |
| Credential must be account-bound | Only credentials registered under the IBKR account are listed |
| Bitwarden uses `none` attestation | Software passkeys are legitimate; IBKR accepts them |
| rpId must match the page origin | An `.com.hk` rpId can only verify on an `.com.hk` origin |
| Marionette disables WebAuthn | Firefox refuses credential ops under automation |
| Firefox enforces `transports` | Won't route to USB when only platform authenticators are requested |
| Diagnostic logs at INFO level | The only way to debug a headless environment |
| Don't automate the PIN prompt | X11 key events don't reach Chromium's HTML input |

## 6. Credential file format (`bwu fido2 get` verbatim)

```
name: example-ibkr
credentialId: 01234567-89ab-cdef-0123-456789abcdef
rpId: interactivebrokers.com.hk
userHandle: <redacted>
keyType: public-key
keyCurve: P-256
privateKey (base64url): <redacted>
-----BEGIN PRIVATE KEY-----
<redacted>
-----END PRIVATE KEY-----
```

`_parse_import_file` in `soft_fido2/ctap_interface.py` accepts both this format
and the legacy JSON form (`credentialId` / `rpId` / `userHandle` / `privateKeyPem`).
