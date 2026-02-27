#!/usr/bin/env python3
"""
secure_receiver_tls.py — TLS 1.3 Mutual-Authentication File Receiver (Way 1)

CIAA Analysis:
  Confidentiality — TLS 1.3 encrypts every byte on the wire; older protocol
                    versions are explicitly disabled.
  Integrity      — SHA-256 hash computed on the received byte stream is compared
                    against the hash the sender transmits after the file data.
  Authentication — Mutual TLS (mTLS): the server presents its certificate *and*
                    demands a valid client certificate signed by the same CA.
  Availability   — Chunked streaming (1 MB) keeps memory constant regardless of
                    file size; timeouts and error handling prevent hangs.

Usage:
    python secure_receiver_tls.py <output_file> [host] [port]
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
CHUNK_SIZE = 1 * 1024 * 1024          # 1 MB per read
PROGRESS_INTERVAL = 100 * 1024 * 1024 # Print every 100 MB
SOCKET_TIMEOUT = 300                  # 5-minute idle timeout (seconds)

CA_CERT     = "ca.crt"
SERVER_CERT = "server.crt"
SERVER_KEY  = "server.key"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9443


def build_tls_context() -> ssl.SSLContext:
    """
    Build a server-side TLS context enforcing:
      - TLS 1.3 only (TLS 1.0–1.2 disabled)
      - mTLS: client certificate required, verified against CA
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Enforce TLS 1.3 minimum — disables TLS 1.0, 1.1, 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Load server identity
    ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    # Require and verify client certificate (mTLS — Authentication)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CA_CERT)

    return ctx


def receive_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly *n* bytes from the connection or raise an error."""
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        data.extend(chunk)
    return bytes(data)


def receive_file(conn: ssl.SSLSocket, output_path: str) -> None:
    """
    Protocol (receiver's view):
      1. Receive 8-byte big-endian file size.
      2. Stream file data in CHUNK_SIZE pieces, computing SHA-256 on the fly.
      3. Receive 64-byte hex-encoded SHA-256 from sender.
      4. Compare hashes — reject if mismatch (Integrity).
    """

    # --- Step 1: file size header (8 bytes, big-endian unsigned long long) ---
    raw_size = receive_exact(conn, 8)
    file_size = struct.unpack("!Q", raw_size)[0]
    print(f"[*] Incoming file size: {file_size / (1024**3):.2f} GB "
          f"({file_size:,} bytes)")

    # --- Step 2: stream & hash (Integrity + Availability) ---
    sha256 = hashlib.sha256()
    received = 0

    with open(output_path, "wb") as f:
        while received < file_size:
            to_read = min(CHUNK_SIZE, file_size - received)
            chunk = receive_exact(conn, to_read)
            f.write(chunk)
            sha256.update(chunk)
            received += len(chunk)

            if received % PROGRESS_INTERVAL < CHUNK_SIZE:
                pct = received / file_size * 100
                print(f"    Received {received / (1024**3):.2f} GB "
                      f"/ {file_size / (1024**3):.2f} GB  ({pct:.1f}%)")

    print(f"[+] File data received: {received:,} bytes")

    # --- Step 3: receive sender's SHA-256 hash (64 hex chars) ---
    sender_hash_hex = receive_exact(conn, 64).decode("ascii")

    # --- Step 4: integrity verification ---
    local_hash_hex = sha256.hexdigest()
    if local_hash_hex == sender_hash_hex:
        print(f"[✓] Integrity check PASSED — SHA-256: {local_hash_hex}")
    else:
        print(f"[✗] Integrity check FAILED!")
        print(f"    Local : {local_hash_hex}")
        print(f"    Sender: {sender_hash_hex}")
        os.remove(output_path)
        raise ValueError("SHA-256 mismatch — file deleted for safety")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_file> [host] [port]")
        sys.exit(1)

    output_path = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT

    tls_ctx = build_tls_context()

    # Plain TCP listen socket (Availability — standard backlog)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.bind((host, port))
        sock.listen(1)
        print(f"[*] Listening on {host}:{port} (TLS 1.3 mTLS)")

        raw_conn, addr = sock.accept()
        print(f"[*] TCP connection from {addr}")

        # Wrap accepted socket in TLS (Confidentiality + Authentication)
        with tls_ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
            tls_conn.settimeout(SOCKET_TIMEOUT)
            peer_cert = tls_conn.getpeercert()
            peer_cn = dict(
                x[0] for x in peer_cert.get("subject", ())
            ).get("commonName", "<unknown>")
            print(f"[✓] mTLS handshake complete — client CN: {peer_cn}")
            print(f"    TLS version : {tls_conn.version()}")
            print(f"    Cipher suite: {tls_conn.cipher()[0]}")

            receive_file(tls_conn, output_path)

    print("[+] Transfer complete.")


if __name__ == "__main__":
    main()
