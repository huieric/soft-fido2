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

There are **three** service-related files in this repository, but only two are
for the current Docker/USB/IP deployment. Do not enable both USB/IP attachment
services at the same time:

| Unit | Type | Purpose |
|------|------|---------|
| `usbip-attach.service` | `oneshot` | Load `vhci-hcd`, wait for port 3240, attach once, and detach on stop. Useful for manual testing. |
| `usbip-watchdog.service` | long-running | Continuously poll the attachment and re-attach after a reboot, container restart, USB/IP disconnect, or device reset. **Recommended for production.** |

`passkey.service` is the upstream **desktop UHID + Qt system-tray** service. It
is not used by this Docker/USB/IP deployment and should not be enabled on the
AWS host. Likewise, `setup_uhid.sh` is only for the upstream desktop UHID
installation.

The watchdog is the configuration previously used successfully on AWS. It
checks `usbip port` every 10 seconds, waits for the Docker USB/IP server, runs
`usbip attach -r 127.0.0.1 -b 1-1.1`, and repairs permissions on `/dev/bus/usb`
and `/dev/hidraw*` after every attach.

### Recommended: continuous watchdog

```bash
sudo install -m 0755 systemd/usbip-watchdog.sh /usr/local/bin/usbip-watchdog.sh
sudo install -m 0644 systemd/usbip-watchdog.service /etc/systemd/system/usbip-watchdog.service
sudo systemctl daemon-reload

# Make sure the one-shot alternative is disabled first.
sudo systemctl disable --now usbip-attach.service 2>/dev/null || true
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

### One-shot alternative: manual/testing mode

```bash
sudo cp systemd/usbip-attach.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl disable --now usbip-watchdog.service 2>/dev/null || true
sudo systemctl enable --now usbip-attach.service
```

This mode attaches only once. It does **not** repair the device if the
USB/IP connection later dies, and it does not automatically re-attach after a
container restart. For AWS production use the watchdog above.

Verify either mode:

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

### Optional FIDO2 PIN for unattended UV

IBKR/JxBrowser may require user verification and display `PIN required`. The
official authenticator supports CTAP2 `clientPIN`. For unattended operation,
create one secret file on AWS and mount it read-only into both containers:

```bash
cd /home/opadmin/run/global_futures/docker/ibkr/soft-fido2
umask 077
printf '%s\n' 'your-fido2-pin' > fido2_pin
chmod 600 fido2_pin
```

This is the PIN for the software authenticator, not the IBKR, Linux, SSH, or
Bitwarden password. Never commit or log this file.

For the soft-fido2 compose service:

```yaml
volumes:
  - ./fido2_pin:/run/secrets/fido2_pin:ro
environment:
  SOFT_FIDO2_PIN_FILE: /run/secrets/fido2_pin
  SOFT_FIDO2_WALLET: ibkr
```

For the IB Gateway compose service, mount the same host file:

```yaml
volumes:
  - /home/opadmin/run/global_futures/docker/ibkr/soft-fido2/fido2_pin:/run/secrets/fido2_pin:ro
environment:
  FIDO2_PIN_FILE: /run/secrets/fido2_pin
```

The soft-fido2 entrypoint creates an official PIN-protected `ibkr.passkey` /
`ibkr.stash` wallet on first boot. The IBGA clicker enters the PIN into the
Chromium security-key dialog with `xdotool`; the PIN value is never logged.
Existing wallets are not overwritten.

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

