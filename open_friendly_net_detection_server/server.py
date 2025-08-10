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
from typing import List
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b'FND1'
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
        self.allowed_probe_sources: List[str] = data.get('allowed_probe_sources', [])


def load_config(path: str) -> ServerConfig:
    try:
        with open(path, 'r') as f:
            raw = yaml.safe_load(f) or {}
        cfg = ServerConfig(raw)
        level = getattr(logging, cfg.log_level.upper(), logging.INFO)
        logging.basicConfig(level=level, format='[%(asctime)s] %(levelname)s %(message)s')
        logger.setLevel(level)
        logger.info('Config loaded (udp_port=%d)', cfg.udp_port)
        return cfg
    except FileNotFoundError:
        raise SystemExit(f'Config file not found: {path}')


def load_keys(cert_path: str, key_path: str):
    with open(cert_path, 'rb') as f:
        cert_bytes = f.read()
    if len(cert_bytes) > MAX_CERT_LEN:
        raise SystemExit('Certificate too large')
    cert = x509.load_der_x509_certificate(cert_bytes)
    pubkey = cert.public_key()
    if not isinstance(pubkey, Ed25519PublicKey):
        raise SystemExit('Certificate must contain Ed25519 public key')
    with open(key_path, 'rb') as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise SystemExit('Private key must be Ed25519')
    raw_pub = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    logger.info('Loaded keypair (pub=%s...)', raw_pub.hex()[:16])
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
    if cfg.allowed_probe_sources and src_ip not in cfg.allowed_probe_sources:
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


def udp_listener(cfg: ServerConfig, cert_bytes: bytes, priv: Ed25519PrivateKey, raw_pub: bytes, stop_event: threading.Event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((cfg.listen_address, cfg.udp_port))
    logger.info('Listening UDP %s:%d', cfg.listen_address, cfg.udp_port)
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(4096)
            handle_probe(cfg, cert_bytes, priv, raw_pub, data, addr)
        except socket.timeout:
            continue
        except Exception as e:
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
