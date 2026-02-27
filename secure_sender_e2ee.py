#!/usr/bin/env python3
"""
secure_sender_e2ee.py — End-to-End Encrypted File Sender (Way 2)

This program sends a file over a *raw* TCP socket (no TLS). Security is
implemented entirely at the application layer using:

  AES-256-GCM   — symmetric encryption of file chunks  (Confidentiality)
  RSA-OAEP      — asymmetric key exchange of the AES session key
  RSA-PSS       — digital signature of the SHA-256 file hash (Authentication)
  SHA-256       — full-file hash sent for receiver verification (Integrity)
  Per-chunk ACK — flow control & error recovery               (Availability)

CIAA Analysis:
  Confidentiality — A random 256-bit AES key encrypts every chunk with
                    AES-256-GCM.  The key itself is RSA-OAEP encrypted so only
                    the receiver can decrypt it.
  Integrity      — GCM authentication tags protect each chunk.  A full-file
                    SHA-256 hash is sent at the end for end-to-end verification.
  Authentication — The sender signs the SHA-256 hash with its RSA private key
                    (RSA-PSS); the receiver verifies with the sender's public
                    key.
  Availability   — 1 MB chunked streaming with per-chunk ACKs; timeouts and
                    graceful error handling prevent resource exhaustion.

Protocol phases:
  Phase 1 — Key Exchange:  generate AES key, RSA-encrypt, send to receiver
  Phase 2 — Data Transfer: encrypt file chunks with AES-GCM, send with ACKs
  Phase 3 — Verification:  send SHA-256 hash + RSA-PSS signature

Usage:
    python secure_sender_e2ee.py <input_file> [host] [port]

Key files expected:
    sender_private.pem    — sender's RSA private key  (to sign the hash)
    receiver_public.pem   — receiver's RSA public key (to encrypt session key)
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

SENDER_PRIVATE_KEY  = "sender_private.pem"
RECEIVER_PUBLIC_KEY = "receiver_public.pem"

DEFAULT_HOST = "127.0.0.1"
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


def send_length_prefixed(sock: socket.socket, data: bytes) -> None:
    """Send data preceded by a 4-byte big-endian length header."""
    sock.sendall(struct.pack("!I", len(data)) + data)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------------------------------------------------------------------------
# Phase 1 — Key Exchange
# ---------------------------------------------------------------------------
def phase_key_exchange(sock: socket.socket, receiver_pubkey) -> tuple:
    """
    Generate a random AES-256 key + 12-byte GCM IV base, encrypt them with
    the receiver's RSA public key (OAEP), and send.

    Only the receiver's private key can recover the session key
    (Confidentiality).
    """
    print("[*] Phase 1 — Key Exchange")

    aes_key = os.urandom(32)   # 256-bit AES key
    iv_base = os.urandom(12)   # 96-bit GCM nonce base

    # RSA-OAEP encrypt (key ‖ iv_base) with receiver's public key
    plaintext = aes_key + iv_base
    encrypted_blob = receiver_pubkey.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    send_length_prefixed(sock, encrypted_blob)
    print(f"    Sent encrypted key blob ({len(encrypted_blob)} bytes)")

    ack = recv_exact(sock, len(ACK))
    if ack != ACK:
        raise RuntimeError("Key exchange ACK not received")
    print("    Key exchange acknowledged")

    return aes_key, iv_base


# ---------------------------------------------------------------------------
# Phase 2 — Secure Data Transfer
# ---------------------------------------------------------------------------
def phase_data_transfer(
    sock: socket.socket,
    aes_key: bytes,
    iv_base: bytes,
    file_path: str,
) -> str:
    """
    Read the file in 1 MB chunks, encrypt each with AES-256-GCM, send, and
    wait for an ACK before proceeding.

    - Each chunk uses a unique nonce: iv_base XOR chunk_index.
    - GCM provides per-chunk authentication tags (Integrity).
    - SHA-256 is accumulated over plaintext for full-file integrity.
    """
    print("[*] Phase 2 — Secure Data Transfer")

    file_size = os.path.getsize(file_path)
    print(f"    File size: {file_size / (1024**3):.2f} GB "
          f"({file_size:,} bytes)")

    aesgcm = AESGCM(aes_key)
    sha256 = hashlib.sha256()

    # Send file size so receiver knows when transfer is complete
    sock.sendall(struct.pack("!Q", file_size))

    sent_plaintext = 0
    chunk_index = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            sha256.update(chunk)

            # Derive unique nonce: iv_base XOR chunk_index (Confidentiality)
            nonce = bytearray(iv_base)
            counter_bytes = chunk_index.to_bytes(len(iv_base), "big")
            for i in range(len(nonce)):
                nonce[i] ^= counter_bytes[i]

            # Encrypt (Confidentiality + Integrity via GCM tag)
            ciphertext = aesgcm.encrypt(bytes(nonce), chunk, None)

            # Send length-prefixed ciphertext
            send_length_prefixed(sock, ciphertext)

            # Wait for per-chunk ACK (Availability — flow control)
            ack = recv_exact(sock, len(ACK))
            if ack != ACK:
                raise RuntimeError(f"Chunk {chunk_index}: ACK not received")

            sent_plaintext += len(chunk)
            chunk_index += 1

            if sent_plaintext % PROGRESS_INTERVAL < CHUNK_SIZE:
                pct = sent_plaintext / file_size * 100
                print(f"    Sent {sent_plaintext / (1024**3):.2f} GB "
                      f"/ {file_size / (1024**3):.2f} GB  ({pct:.1f}%)")

    file_hash = sha256.hexdigest()
    print(f"[+] All chunks sent: {sent_plaintext:,} bytes, "
          f"{chunk_index} chunks")
    print(f"    SHA-256: {file_hash}")
    return file_hash


# ---------------------------------------------------------------------------
# Phase 3 — Integrity & Authentication Verification
# ---------------------------------------------------------------------------
def phase_sign_and_send(
    sock: socket.socket,
    file_hash_hex: str,
    sender_privkey,
) -> None:
    """
    Send the SHA-256 hash and its RSA-PSS digital signature so the receiver
    can verify both Integrity and Authentication.
    """
    print("[*] Phase 3 — Sending hash + digital signature")

    # Send hash
    send_length_prefixed(sock, file_hash_hex.encode("ascii"))

    # Sign hash with sender's RSA private key (Authentication)
    signature = sender_privkey.sign(
        file_hash_hex.encode("ascii"),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    send_length_prefixed(sock, signature)
    print(f"    Signature sent ({len(signature)} bytes)")

    # Wait for final ACK
    ack = recv_exact(sock, len(ACK))
    if ack != ACK:
        raise RuntimeError("Final verification ACK not received")
    print("[✓] Receiver confirmed integrity & authentication")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
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

    sender_privkey  = load_private_key(SENDER_PRIVATE_KEY)
    receiver_pubkey = load_public_key(RECEIVER_PUBLIC_KEY)

    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        print(f"[*] Connected to {host}:{port} (E2EE — no TLS)")

        try:
            aes_key, iv = phase_key_exchange(sock, receiver_pubkey)
            file_hash   = phase_data_transfer(sock, aes_key, iv, file_path)
            phase_sign_and_send(sock, file_hash, sender_privkey)
            print("[+] Transfer complete.")
        except Exception as e:
            print(f"[!] Transfer failed: {e}")
            raise


if __name__ == "__main__":
    main()
