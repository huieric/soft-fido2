#!/usr/bin/env python3
"""Create the official soft-fido2 passkey wallet on first container boot."""
from __future__ import annotations

import os

from soft_fido2.key_pair import KeyUtils


fido_home = os.environ.get("FIDO_HOME", "/run/fido")
pin_file = os.environ.get("SOFT_FIDO2_PIN_FILE", "/run/secrets/fido2_pin")
wallet_name = os.environ.get("SOFT_FIDO2_WALLET", "ibkr")
wallet_path = os.path.join(fido_home, wallet_name + ".passkey")

if os.path.exists(wallet_path):
    print(f"[provision] Existing wallet found: {wallet_path}")
    raise SystemExit(0)

with open(pin_file, encoding="utf-8") as fh:
    pin = fh.read().strip()
if not pin:
    raise SystemExit(f"PIN secret is empty: {pin_file}")
if len(pin) < 4:
    raise SystemExit("FIDO2 PIN must contain at least 4 characters")

os.makedirs(fido_home, exist_ok=True)
if not os.path.exists(os.path.join(fido_home, "platform.key")):
    KeyUtils.create_platform_key()

passkey = KeyUtils.generate_passkey()
pin_hash = KeyUtils.get_pin_hash(pin)
KeyUtils._save_passkey(
    passkey["key"],
    passkey["x5c"],
    [],
    pin_hash,
    wallet_path,
)
os.chmod(wallet_path, 0o600)
stash_path = os.path.join(fido_home, wallet_name + ".stash")
if os.path.exists(stash_path):
    os.chmod(stash_path, 0o600)
print(f"[provision] Created official passkey wallet in {fido_home}")
