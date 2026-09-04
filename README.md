# soft-fido2-headless

[English](README.md) · [中文](README.zh-CN.md)

> **Forked from** [`lachlan-ibm/soft-fido2`](https://github.com/lachlan-ibm/soft-fido2) (MIT).
> The `upstream` remote points at that official project; this fork keeps the official
> CTAP2/U2F engine but repackages it for headless Docker + USB/IP.

A **headless** software FIDO2 passkey authenticator, built on the official
[`lachlan-ibm/soft-fido2`](https://github.com/lachlan-ibm/soft-fido2) (MIT) code
base, and packaged to run in Docker as a **real USB device over USB/IP**.

It serves IB Gateway's embedded Chromium (JxBrowser) so that a passkey login can
be completed with no GUI, no fingerprint scanner, and no physical security key.

> **Companion project**: [`huieric/ibga-docker`](https://github.com/huieric/ibga-docker) —
> runs IB Gateway headless in Docker and drives this authenticator for fully
> unattended IBKR passkey login. The two containers are designed to work together.

## Why USB/IP instead of UHID?

UHID (`/dev/uhid`) creates a *virtual HID device* under
`/sys/devices/virtual/`, **not** on the USB bus. Chromium (and IB Gateway's
embedded Chromium) enumerates FIDO keys through libusb on the **USB bus**, so a
UHID device is invisible to it. USB/IP presents the authenticator as a real USB
device (`vendor/product 0x3713`), which libusb can enumerate normally.

The official project defaults to UHID + a Qt system-tray GUI. This repository
keeps the official CTAP2/U2F/resident-key engine but runs it in **headless
USB/IP mode** (`--transport usbip --no-systray`) inside a slim container, with
two small patches so it does not pull in PyQt6 at import time.

## How it works (architecture)

```
┌─────────────────────────────── AWS host ───────────────────────────────┐
│                                                                        │
│  ┌───────────────────────┐       ┌──────────────────────────────────┐  │
│  │ soft-fido2 container  │       │ IB Gateway container             │  │
│  │ (network_mode: host)  │       │ (mounts /dev/bus/usb + hidraw)   │  │
│  │ TCP :3240 USB/IP      │       │ embedded Chromium → libusb       │  │
│  └──────────┬────────────┘       └────────────────▲─────────────────┘  │
│             │  usbip attach -r 127.0.0.1 -b 1-1.1   │                 │
│             ▼               (systemd oneshot)        │                 │
│     vhci-hcd kernel module ──────────────────────────┘                 │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

1. The authenticator listens on TCP `3240` as a USB/IP *server*.
2. A systemd oneshot unit runs `usbip attach -r 127.0.0.1 -b 1-1.1`, which makes
   the host kernel see a real USB device (via the `vhci-hcd` module).
3. The host's `/dev/bus/usb` and `/dev/hidraw*` are bind-mounted into the IB
   Gateway container, so its Chromium enumerates the virtual key normally.

## Image build (CI)

GitHub Actions builds and publishes the image on every push to `master`/`main`
and every `v*` tag (`.github/workflows/docker.yml`):

```
ghcr.io/huieric/soft-fido2:latest
```

To build locally:

```bash
docker build -t ghcr.io/huieric/soft-fido2:latest .
```

## Deploy (AWS, via compose)

Create a `compose.yml` (an example is in `compose.yml.example`):

```yaml
services:
  soft-fido2:
    image: ghcr.io/huieric/soft-fido2:latest
    container_name: soft-fido2
    network_mode: host          # usbip client on the host connects to 127.0.0.1:3240
    restart: unless-stopped
    volumes:
      - soft-fido2-data:/run/fido
    environment:
      SOFT_FIDO2_PORT: "3240"

volumes:
  soft-fido2-data:
```

```bash
docker compose up -d
docker compose logs -f soft-fido2
# expect: "Starting the AyeBeKey Passkey USB/IP Service on port 3240"
```

> The `FIDO_HOME` directory defaults to `/run/fido` inside the entrypoint, so
> no env var is required. The persisted volume keeps across restarts:
> - `platform.key` — generated automatically on first boot (still used by the
>   platform-assertion fallback)
> - the imported passkey file (`ibkr_passkey.txt`)

## Auto-attach as a host USB device (systemd)

The only systemd unit shipped is `usbip-watchdog.service` (plus its script,
`usbip-watchdog.sh`). It continuously checks the `vhci-hcd` attachment and
re-attaches after a reboot, container restart, USB/IP disconnect, or host-side
device reset — the recommended (and only) configuration for production.

It checks `usbip port` every 10 seconds, waits for the Docker USB/IP server,
runs `usbip attach -r 127.0.0.1 -b 1-1.1`, and repairs permissions on
`/dev/bus/usb` and `/dev/hidraw*` after every attach.

> The previous one-shot `usbip-attach.service` and the upstream desktop UHID
> units (`passkey.service`, `setup_uhid.sh`, `passkey.env`) have been removed.
> Use only the watchdog.

### Install the watchdog

```bash
sudo install -m 0755 systemd/usbip-watchdog.sh /usr/local/bin/usbip-watchdog.sh
sudo install -m 0644 systemd/usbip-watchdog.service /etc/systemd/system/usbip-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable --now usbip-watchdog.service
sudo systemctl status usbip-watchdog.service
```

Optional watchdog environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `USBIP_SERVER_HOST` | `127.0.0.1` | USB/IP server host |
| `USBIP_PORT` | `3240` | USB/IP server port |
| `USBIP_BUSID` | `1-1.1` | Exported device bus ID |
| `USBIP_CHECK_INTERVAL` | `10` | Poll interval in seconds |

Watchdog logs:

```bash
journalctl -u usbip-watchdog -f
```

Expected messages include:

```text
[usbip-watchdog] ... started (...)
[usbip-watchdog] ... attached 1-1.1
```

Verify:

```bash
usbip port          # should show "Port 00: <Port in Use>" for vendor 3713
lsusb -v -d 3713:3713
```

## Expose the device to IB Gateway

The virtual key appears on the host under `/dev/bus/usb` and `/dev/hidraw*`.
Bind-mount them into the IB Gateway container and allow the device major numbers:

```yaml
# in ibga's compose.yml
services:
  my-ibga:
    volumes:
      - /dev/bus/usb:/dev/bus/usb
    device_cgroup_rules:
      - 'c 189:* rwm'          # USB major number
      # - 'c 239:* rwm'        # hidraw major (kernel-dependent; 239 on AWS 6.8)
```

## First-time passkey provisioning (import a Bitwarden credential)

IBKR enforces a strict `allowList` on `getAssertion`: the authenticator may
only return a credential whose ID is listed. That list is checked **locally by
the browser** (and again by the server), so it cannot be bypassed — you cannot
log in with a credential that IBKR did not issue to this account.

The reliable path is therefore:

1. Register a **new passkey** for your IBKR account in Bitwarden (the browser
   extension intercepts the WebAuthn call and registers with `none`
   attestation, which IBKR accepts for software/synced passkeys).
2. Export that passkey with `bwu fido2 get "<entry>"` and keep the raw
   `key: value` text output (no JSON conversion needed).
3. Mount the exported file(s) into the container and point `SOFT_FIDO2_IMPORT_DIR`
   at the directory (or `SOFT_FIDO2_IMPORT_FILE` at a single file / comma-separated
   list). See below.

The authenticator's `_parse_import_file` reads each `key: value` block (with the
embedded PEM private key), decodes the hyphenated `credentialId` to its 16 raw
bytes, and signs `getAssertion` when — and only when — the credential is present
in IBKR's `allowList`.

**Multiple passkeys / multiple accounts**: soft-fido2 can serve several IBKR
accounts from one authenticator. Put one `bwu fido2 get` export per account in a
directory and point `SOFT_FIDO2_IMPORT_DIR` at it. On each `getAssertion`, it
picks the imported credential whose `rpId` matches and whose id is listed in that
account's `allowList`.

```yaml
services:
  soft-fido2:
    image: ghcr.io/huieric/soft-fido2:latest
    volumes:
      - ./passkeys:/run/fido/passkeys:ro   # one file per IBKR account
    environment:
      SOFT_FIDO2_IMPORT_DIR: /run/fido/passkeys
```

The imported file format is the verbatim `bwu fido2 get` output:

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

The legacy JSON form (`credentialId`, `rpId`, `userHandle`, `privateKeyPem`)
is also still accepted. See [`docs/IBKR-UNATTENDED.md`](docs/IBKR-UNATTENDED.md)
for the full end-to-end account of this deployment and the dead-ends we hit.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `SOFT_FIDO2_PORT` | `3240` | USB/IP server port |
| `SOFT_FIDO2_SKIP_UP` | `true` | Skip the user-presence check (headless) |
| `SOFT_FIDO2_IMPORT_DIR` | *(unset)* | Directory of imported `bwu fido2 get` passkey files (one per account) |
| `SOFT_FIDO2_IMPORT_FILE` | *(unset)* | Single imported passkey file, or comma-separated list of files |
| `SOFT_FIDO2_DEBUG_LEVEL` | `INFO` | Log level |
| `SOFT_FIDO2_LOG_FILE` | *(stdout)* | Log file relative to `FIDO_HOME` |

## Branches

- `master` — the only maintained branch; the headless USB/IP build documented here.

## License

MIT, as per the upstream `lachlan-ibm/soft-fido2` project.

## Topics

`ibkr` `interactive-brokers` `ib-gateway` `docker` `headless` `unattended` `passkey` `fido2` `webauthn` `usbip` `security-key` `trading` `automation`

