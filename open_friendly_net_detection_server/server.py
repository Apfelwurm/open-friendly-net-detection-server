#!/usr/bin/env python3
"""Friendly Network Detection (FND) server implementation.

Listens on UDP (default 32125) for probes of format:
  MAGIC (4 bytes 'FND1') + 2 byte big-endian TCP port + 32 byte nonce
On receipt, validates length and optionally source filtering, then establishes
an outbound TCP connection back to the client's given port on the source IP.

Over that TCP connection it sends:
  MAGIC + 2 byte length + DER certificate + 64 byte Ed25519 signature over nonce
Then it waits (with timeout) for a 32 byte acknowledgement:
  SHA256(raw_pubkey || nonce)   (not used except for optional logging / anti replay)

Certificate is only a container for the Ed25519 public key (self-signed acceptable).

Runtime options:
  --config path/to/config.yaml (default: ./config.yaml)

Config example:
listen_address: "0.0.0.0"
udp_port: 32125
certificate: "certs/server.der"
private_key: "certs/server.key"
log_level: INFO
allowed_probe_sources: []
"""
import argparse
import logging
import os
import socket
import struct
import threading
import time
import yaml
import hashlib
import ipaddress  # added for CIDR support
from typing import List
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b'FND1'
# ACK_TIMEOUT: seconds to wait for the optional 32‑byte client acknowledgement
# (SHA256(raw_pubkey || nonce)) after sending certificate + signature. Keeping
# this as a named constant (instead of an inline literal) documents the
# protocol expectation and allows easy tuning (e.g., raising in high-latency
# environments or lowering to release resources sooner). A missing / invalid
# ack does not mark the probe as failed; it is purely informational here.
ACK_TIMEOUT = 5
TCP_CONNECT_TIMEOUT = 5
MAX_CERT_LEN = 4096  # sanity cap (matches client expectation)

logger = logging.getLogger('open-friendly-net-detection-server')

class ServerConfig:
    def __init__(self, data: dict):
        self.listen_address: str = data.get('listen_address', '0.0.0.0')
        self.udp_port: int = int(data.get('udp_port', 32125))
        self.certificate: str = data.get('certificate', 'certs/server.der')
        self.private_key: str = data.get('private_key', 'certs/server.key')
        self.log_level: str = data.get('log_level', 'INFO')
        raw_sources: List[str] = data.get('allowed_probe_sources', [])
        self.allowed_ip_literals: set[str] = set()
        self.allowed_cidrs: List[ipaddress._BaseNetwork] = []
        for entry in raw_sources:
            try:
                if '/' in entry:
                    self.allowed_cidrs.append(ipaddress.ip_network(entry, strict=False))
                else:
                    # normalize literal IP to string form
                    self.allowed_ip_literals.add(str(ipaddress.ip_address(entry)))
            except ValueError:
                # Skip invalid entry but log later in load_config
                pass
        self._raw_sources = raw_sources  # for logging

    def source_allowed(self, ip: str) -> bool:
        if not self.allowed_ip_literals and not self.allowed_cidrs:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip in self.allowed_ip_literals:
            return True
        for net in self.allowed_cidrs:
            if ip_obj in net:
                return True
        return False


def load_config(path: str) -> ServerConfig:
    try:
        with open(path, 'r') as f:
            raw = yaml.safe_load(f) or {}
        cfg = ServerConfig(raw)
        level = getattr(logging, cfg.log_level.upper(), logging.INFO)
        logging.basicConfig(level=level, format='[%(asctime)s] %(levelname)s %(message)s')
        logger.setLevel(level)
        if cfg.allowed_ip_literals or cfg.allowed_cidrs:
            logger.info('Config loaded (udp_port=%d, allowed_sources=%s)', cfg.udp_port, cfg._raw_sources)
        else:
            logger.info('Config loaded (udp_port=%d, allowed_sources=ANY)', cfg.udp_port)
        return cfg
    except FileNotFoundError:
        raise SystemExit(f'Config file not found: {path}')
    except Exception as e:
        raise SystemExit(f'Failed to load config {path}: {e}')


def load_keys(cert_path: str, key_path: str):
    try:
        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()
    except FileNotFoundError:
        raise SystemExit(f'Certificate file not found: {cert_path}')
    if len(cert_bytes) > MAX_CERT_LEN:
        raise SystemExit('Certificate too large')
    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
    except Exception as e:
        raise SystemExit(f'Cannot parse DER certificate {cert_path}: {e}')
    pubkey = cert.public_key()
    if not isinstance(pubkey, Ed25519PublicKey):
        raise SystemExit('Certificate must contain Ed25519 public key')
    try:
        with open(key_path, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        raise SystemExit(f'Private key file not found: {key_path}')
    except Exception as e:
        raise SystemExit(f'Cannot load private key {key_path}: {e}')
    if not isinstance(priv, Ed25519PrivateKey):
        raise SystemExit('Private key must be Ed25519')
    raw_pub = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    fingerprint = hashlib.sha256(raw_pub).hexdigest()
    logger.info('Loaded keypair (pub=%s..., sha256=%s)', raw_pub.hex()[:16], fingerprint[:16] + '...')
    return cert_bytes, priv, raw_pub


def handle_probe(cfg: ServerConfig, cert_bytes: bytes, priv: Ed25519PrivateKey, raw_pub: bytes, data: bytes, addr):
    if len(data) != 4 + 2 + 32:
        logger.debug('Invalid probe length from %s (%d)', addr, len(data))
        return
    if not data.startswith(MAGIC):
        logger.debug('Magic mismatch from %s', addr)
        return
    tcp_port = struct.unpack('!H', data[4:6])[0]
    nonce = data[6:]
    src_ip = addr[0]
    if not cfg.source_allowed(src_ip):
        logger.debug('Source %s not permitted', src_ip)
        return
    logger.info('Probe from %s (callback port %d)', src_ip, tcp_port)
    # Connect back
    try:
        with socket.create_connection((src_ip, tcp_port), timeout=TCP_CONNECT_TIMEOUT) as s:
            s.settimeout(TCP_CONNECT_TIMEOUT)
            sig = priv.sign(nonce)
            payload = MAGIC + struct.pack('!H', len(cert_bytes)) + cert_bytes + sig
            s.sendall(payload)
            logger.debug('Sent certificate (%d bytes) + signature to %s:%d', len(cert_bytes), src_ip, tcp_port)
            # Await ack (optional)
            try:
                s.settimeout(ACK_TIMEOUT)
                ack = s.recv(32)
                if len(ack) == 32:
                    expected = hashlib.sha256(raw_pub + nonce).digest()
                    if ack == expected:
                        logger.info('Ack valid from %s', src_ip)
                    else:
                        logger.debug('Ack mismatch from %s', src_ip)
                else:
                    logger.debug('No/short ack from %s', src_ip)
            except socket.timeout:
                logger.debug('Ack timeout from %s', src_ip)
    except Exception as e:
        logger.debug('Callback error to %s:%d - %s', src_ip, tcp_port, e)


def udp_listener(cfg: ServerConfig, cert_bytes: bytes, priv: Ed25519PrivateKey, raw_pub: bytes, stop_event: threading.Event):  # noqa: PLR0913 (many params)
    # Parameters required to pass static objects into loop; all are used.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow quick restart
    sock.bind((cfg.listen_address, cfg.udp_port))
    logger.info('Listening UDP %s:%d', cfg.listen_address, cfg.udp_port)
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(4096)
            handle_probe(cfg, cert_bytes, priv, raw_pub, data, addr)
        except socket.timeout:
            continue
        except Exception as e:  # noqa: BLE001 (broad for robustness)
            logger.debug('UDP error: %s', e)
    sock.close()


def main():
    parser = argparse.ArgumentParser(description='Friendly Network Detection server')
    parser.add_argument('--config', default='config.yaml')
    args = parser.parse_args()
    cfg = load_config(args.config)
    cert_bytes, priv, raw_pub = load_keys(cfg.certificate, cfg.private_key)
    stop_event = threading.Event()
    t = threading.Thread(target=udp_listener, args=(cfg, cert_bytes, priv, raw_pub, stop_event), daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('Interrupt received, shutting down')
        stop_event.set()
        t.join()

if __name__ == '__main__':
    main()
