#!/usr/bin/env python3
"""
secure_sender_tls.py — TLS 1.3 Mutual-Authentication File Sender (Way 1)

CIAA Analysis:
  Confidentiality — TLS 1.3 encrypts all traffic; older protocol versions
                    are explicitly disabled.
  Integrity      — SHA-256 hash is computed while streaming and sent after
                    the file data so the receiver can verify.
  Authentication — Mutual TLS (mTLS): the client presents its certificate
                    and verifies the server certificate against the CA.
  Availability   — Chunked 1 MB streaming keeps memory constant; timeouts
                    and error handling prevent hangs.

Usage:
    python secure_sender_tls.py <input_file> [host] [port]
"""

import socket
import ssl
import hashlib
import os
import sys
import struct

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CHUNK_SIZE = 1 * 1024 * 1024          # 1 MB per send
PROGRESS_INTERVAL = 100 * 1024 * 1024 # Print every 100 MB
SOCKET_TIMEOUT = 300                  # 5-minute idle timeout (seconds)

CA_CERT    = "ca.crt"
CLIENT_CERT = "client.crt"
CLIENT_KEY  = "client.key"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443


def build_tls_context() -> ssl.SSLContext:
    """
    Build a client-side TLS context enforcing:
      - TLS 1.3 only (TLS 1.0–1.2 disabled)
      - mTLS: client presents its certificate
      - Server certificate verified against the trusted CA
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Enforce TLS 1.3 minimum — disables TLS 1.0, 1.1, 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Load client identity for mTLS (Authentication)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    # Verify server certificate against CA (Authentication)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CA_CERT)

    return ctx


def send_file(conn: ssl.SSLSocket, file_path: str) -> None:
    """
    Protocol (sender's view):
      1. Send 8-byte big-endian file size.
      2. Stream file data in CHUNK_SIZE pieces, computing SHA-256 on the fly.
      3. Send 64-byte hex-encoded SHA-256 hash for receiver to verify (Integrity).
    """

    file_size = os.path.getsize(file_path)
    print(f"[*] File size: {file_size / (1024**3):.2f} GB "
          f"({file_size:,} bytes)")

    # --- Step 1: send file size header ---
    conn.sendall(struct.pack("!Q", file_size))

    # --- Step 2: stream & hash (Integrity + Availability) ---
    sha256 = hashlib.sha256()
    sent = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            conn.sendall(chunk)
            sha256.update(chunk)
            sent += len(chunk)

            if sent % PROGRESS_INTERVAL < CHUNK_SIZE:
                pct = sent / file_size * 100
                print(f"    Sent {sent / (1024**3):.2f} GB "
                      f"/ {file_size / (1024**3):.2f} GB  ({pct:.1f}%)")

    print(f"[+] File data sent: {sent:,} bytes")

    # --- Step 3: send SHA-256 hash (Integrity) ---
    file_hash = sha256.hexdigest()
    conn.sendall(file_hash.encode("ascii"))
    print(f"[+] SHA-256 sent: {file_hash}")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [host] [port]")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT

    tls_ctx = build_tls_context()

    # Plain TCP connection (Availability — timeout prevents indefinite hang)
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as raw_sock:
        print(f"[*] TCP connected to {host}:{port}")

        # Wrap in TLS (Confidentiality + Authentication)
        # server_hostname must match the CN/SAN in the server certificate
        with tls_ctx.wrap_socket(raw_sock, server_hostname=host) as tls_conn:
            tls_conn.settimeout(SOCKET_TIMEOUT)
            peer_cert = tls_conn.getpeercert()
            peer_cn = dict(
                x[0] for x in peer_cert.get("subject", ())
            ).get("commonName", "<unknown>")
            print(f"[✓] mTLS handshake complete — server CN: {peer_cn}")
            print(f"    TLS version : {tls_conn.version()}")
            print(f"    Cipher suite: {tls_conn.cipher()[0]}")

            send_file(tls_conn, file_path)

    print("[+] Transfer complete.")


if __name__ == "__main__":
    main()
