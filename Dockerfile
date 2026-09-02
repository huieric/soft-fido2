FROM python:3.12-slim

# No system packages required: the USB/IP server is pure Python (stdlib
# socketserver) + cbor2 + cryptography + asn1 + PyJWT. The host does the
# kernel-side work (vhci-hcd / usbip attach).
RUN pip install --no-cache-dir cbor2 cryptography asn1 PyJWT

WORKDIR /app
COPY soft_fido2/ soft_fido2/
COPY pyproject.toml README.md ./
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Writable directory that stores the platform key and registered passkeys
# (`.passkey` / `.stash` / `platform.key`). Mount a volume here to persist
# registered credentials across container restarts.
RUN mkdir -p /run/fido && chmod 777 /run/fido
VOLUME ["/run/fido"]

# The authenticator requires FIDO_HOME to locate its key material.
ENV FIDO_HOME=/run/fido

EXPOSE 3240

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 3240), 2); s.close()" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
