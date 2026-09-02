# soft-fido2-headless

A **headless** software FIDO2 passkey authenticator, built on the official
[`lachlan-ibm/soft-fido2`](https://github.com/lachlan-ibm/soft-fido2) (MIT) code
base, and packaged to run in Docker as a **real USB device over USB/IP**.

It serves IB Gateway's embedded Chromium (JxBrowser) so that a passkey login can
be completed with no GUI, no fingerprint scanner, and no physical security key.

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
      FIDO_HOME: /run/fido
      SOFT_FIDO2_PORT: "3240"

volumes:
  soft-fido2-data:
```

```bash
docker compose up -d
docker compose logs -f soft-fido2
# expect: "Starting the AyeBeKey Passkey USB/IP Service on port 3240"
```

> `FIDO_HOME` (`/run/fido`, persisted as a named volume) holds three things the
> container must keep across restarts:
> - `platform.key` — generated automatically on first boot
> - `<name>.passkey` / `<name>.stash` — the registered resident credentials

## Auto-attach as a host USB device (systemd)

The `usbip attach` binding does not survive a reboot or container restart. Install
the provided oneshot unit to keep it attached automatically:

```bash
sudo cp systemd/usbip-attach.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now usbip-attach.service
sudo systemctl status usbip-attach.service
```

It loads `vhci-hcd`, waits for `127.0.0.1:3240`, attaches `1-1.1`, and detaches
on stop. Verify:

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

## First-time passkey registration

On the **first** login (or after wiping `FIDO_HOME`), there is no stored
credential yet. The flow is:

1. IB Gateway prompts for password, then shows the "Second Factor
   Authentication → Use your Passkey device → Authenticate" dialog.
2. An auto-clicker in the IB Gateway image clicks **Authenticate**.
3. The IBKR WebAuthn page performs a resident-key (`makeCredential`) registration
   against the soft-fido2 authenticator. The new credential is stored in
   `FIDO_HOME`.
4. Subsequent logins reuse that credential via `getAssertion`.

> Registration and assertion are fully automatic once the authenticator is
> reachable; no manual key import is required. The earlier "import a Bitwarden
> private key" approach is no longer used.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `FIDO_HOME` | `/run/fido` | Directory for `platform.key` + `.passkey` files |
| `SOFT_FIDO2_PORT` | `3240` | USB/IP server port |
| `SOFT_FIDO2_SKIP_UP` | `true` | Skip the user-presence check (headless) |
| `SOFT_FIDO2_DEBUG_LEVEL` | `INFO` | Log level |
| `SOFT_FIDO2_LOG_FILE` | *(stdout)* | Log file relative to `FIDO_HOME` |

## Branches

- `master` — official-code headless build (this documentation).
- `archive/self-developed-ctap2` — the earlier self-written CTAP2 core
  (frozen; import-based, no registration).
- `official-platform-passkey` — tracks upstream `development` with the headless
  patches applied.

## License

MIT, as per the upstream `lachlan-ibm/soft-fido2` project.

