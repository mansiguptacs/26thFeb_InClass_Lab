#!/usr/bin/env python3
"""
secure_receiver_e2ee.py — End-to-End Encrypted File Receiver (Way 2)

This program receives a file over a *raw* TCP socket (no TLS). Security is
implemented entirely at the application layer using:

  AES-256-GCM   — symmetric encryption of file chunks  (Confidentiality)
  RSA-OAEP      — asymmetric key exchange of the AES session key
  RSA-PSS       — digital signature of the SHA-256 file hash (Authentication)
  SHA-256       — full-file hash verified after transfer   (Integrity)
  Per-chunk ACK — flow control & error recovery            (Availability)

CIAA Analysis:
  Confidentiality — Each chunk is encrypted with AES-256-GCM using a random
                    session key that was encrypted with RSA-OAEP and can only
                    be decrypted by the receiver's private key.
  Integrity      — AES-GCM provides per-chunk authentication tags that detect
                    any tampering. A full-file SHA-256 hash is verified at the
                    end.
  Authentication — The sender signs the final SHA-256 hash with its RSA
                    private key; the receiver verifies using the sender's
                    public key.
  Availability   — 1 MB chunked streaming with per-chunk ACKs; timeouts and
                    graceful error handling keep the system responsive.

Protocol phases:
  Phase 1 — Key Exchange:  receive RSA-OAEP-encrypted AES-256 key + IV
  Phase 2 — Data Transfer: receive AES-GCM encrypted chunks with ACKs
  Phase 3 — Verification:  receive & verify SHA-256 hash + RSA-PSS signature

Usage:
    python secure_receiver_e2ee.py <output_file> [host] [port]

Key files expected:
    receiver_private.pem  — receiver's RSA private key (to decrypt session key)
    sender_public.pem     — sender's RSA public key   (to verify signature)
"""

import socket
import hashlib
import os
import sys
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CHUNK_SIZE = 1 * 1024 * 1024          # 1 MB plaintext per chunk
PROGRESS_INTERVAL = 100 * 1024 * 1024 # Print every 100 MB
SOCKET_TIMEOUT = 300                  # 5-minute idle timeout

RECEIVER_PRIVATE_KEY = "receiver_private.pem"
SENDER_PUBLIC_KEY    = "sender_public.pem"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9444

ACK = b"ACK"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes or raise on premature close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        buf.extend(chunk)
    return bytes(buf)


def recv_length_prefixed(sock: socket.socket) -> bytes:
    """Receive a message preceded by a 4-byte big-endian length header."""
    raw_len = recv_exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    return recv_exact(sock, length)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------------------------------------------------------------------------
# Phase 1 — Key Exchange
# ---------------------------------------------------------------------------
def phase_key_exchange(sock: socket.socket, receiver_privkey) -> tuple:
    """
    Receive and decrypt the AES-256 session key and IV.

    The sender encrypts (key ‖ iv) with the receiver's RSA public key using
    OAEP padding.  Only the receiver's private key can recover it
    (Confidentiality).
    """
    print("[*] Phase 1 — Key Exchange")

    encrypted_blob = recv_length_prefixed(sock)
    print(f"    Received encrypted key blob ({len(encrypted_blob)} bytes)")

    # Decrypt with receiver's RSA private key (Confidentiality)
    plaintext = receiver_privkey.decrypt(
        encrypted_blob,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aes_key = plaintext[:32]   # 256-bit AES key
    iv      = plaintext[32:]   # 12-byte GCM nonce base
    print(f"    AES-256 session key decrypted (IV base: {iv.hex()[:16]}...)")

    sock.sendall(ACK)
    return aes_key, iv


# ---------------------------------------------------------------------------
# Phase 2 — Secure Data Transfer
# ---------------------------------------------------------------------------
def phase_data_transfer(
    sock: socket.socket,
    aes_key: bytes,
    iv_base: bytes,
    output_path: str,
) -> tuple:
    """
    Receive AES-256-GCM encrypted chunks, decrypt, write to disk, and ACK
    each one.

    - Each chunk uses a unique nonce derived from iv_base + chunk counter
      (never reuse a nonce — critical for GCM security).
    - GCM authentication tags provide per-chunk integrity.
    - SHA-256 is accumulated over the *plaintext* for full-file integrity.
    """
    print("[*] Phase 2 — Secure Data Transfer")

    aesgcm = AESGCM(aes_key)
    sha256 = hashlib.sha256()

    # Receive file size
    raw_size = recv_exact(sock, 8)
    file_size = struct.unpack("!Q", raw_size)[0]
    print(f"    Expected file size: {file_size / (1024**3):.2f} GB "
          f"({file_size:,} bytes)")

    received_plaintext = 0
    chunk_index = 0

    with open(output_path, "wb") as f:
        while received_plaintext < file_size:
            # Each chunk: 4-byte length header + ciphertext (includes GCM tag)
            ciphertext = recv_length_prefixed(sock)

            # Derive unique nonce: iv_base XOR chunk_index (Confidentiality)
            nonce = bytearray(iv_base)
            counter_bytes = chunk_index.to_bytes(len(iv_base), "big")
            for i in range(len(nonce)):
                nonce[i] ^= counter_bytes[i]

            # Decrypt and authenticate (Integrity via GCM tag)
            plaintext = aesgcm.decrypt(bytes(nonce), ciphertext, None)

            f.write(plaintext)
            sha256.update(plaintext)
            received_plaintext += len(plaintext)
            chunk_index += 1

            # ACK each chunk (Availability)
            sock.sendall(ACK)

            if received_plaintext % PROGRESS_INTERVAL < CHUNK_SIZE:
                pct = received_plaintext / file_size * 100
                print(f"    Received {received_plaintext / (1024**3):.2f} GB "
                      f"/ {file_size / (1024**3):.2f} GB  ({pct:.1f}%)")

    print(f"[+] All chunks received: {received_plaintext:,} bytes, "
          f"{chunk_index} chunks")
    return sha256.hexdigest(), received_plaintext


# ---------------------------------------------------------------------------
# Phase 3 — Integrity Verification
# ---------------------------------------------------------------------------
def phase_verify(
    sock: socket.socket,
    local_hash_hex: str,
    sender_pubkey,
) -> None:
    """
    Receive the sender's SHA-256 hash and its RSA-PSS signature, then:
      1. Compare hashes (Integrity).
      2. Verify the digital signature (Authentication).
    """
    print("[*] Phase 3 — Integrity & Authentication Verification")

    # Receive sender's hash
    sender_hash_hex = recv_length_prefixed(sock).decode("ascii")

    # Receive digital signature of the hash
    signature = recv_length_prefixed(sock)

    # --- Integrity check ---
    if local_hash_hex != sender_hash_hex:
        print(f"[✗] SHA-256 MISMATCH!")
        print(f"    Local : {local_hash_hex}")
        print(f"    Sender: {sender_hash_hex}")
        raise ValueError("File integrity check failed")

    print(f"[✓] SHA-256 match: {local_hash_hex}")

    # --- Authentication: verify RSA-PSS signature ---
    sender_pubkey.verify(
        signature,
        local_hash_hex.encode("ascii"),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("[✓] Digital signature verified — sender is authenticated")

    sock.sendall(ACK)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_file> [host] [port]")
        sys.exit(1)

    output_path = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT

    receiver_privkey = load_private_key(RECEIVER_PRIVATE_KEY)
    sender_pubkey    = load_public_key(SENDER_PUBLIC_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(SOCKET_TIMEOUT)
        srv.bind((host, port))
        srv.listen(1)
        print(f"[*] Listening on {host}:{port} (E2EE — no TLS)")

        conn, addr = srv.accept()
        print(f"[*] TCP connection from {addr}")
        conn.settimeout(SOCKET_TIMEOUT)

        try:
            aes_key, iv = phase_key_exchange(conn, receiver_privkey)
            local_hash, _ = phase_data_transfer(conn, aes_key, iv, output_path)
            phase_verify(conn, local_hash, sender_pubkey)
            print("[+] Transfer complete — file is authentic and intact.")
        except Exception as e:
            print(f"[!] Transfer failed: {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            raise
        finally:
            conn.close()


if __name__ == "__main__":
    main()
