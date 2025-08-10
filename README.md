# Friendly Network Detection (FND) Server

Implements the reverse handshake protocol to allow FND clients to determine if they are on a trusted / friendly network.

Protocol overview:
1. Client sends UDP probe to server port 32125 containing: MAGIC (FND1) + 2-byte TCP listen port + 32-byte nonce
2. Server validates basic structure, then connects back to the client on provided TCP port.
3. Server sends: MAGIC + 2-byte length + DER-encoded Ed25519 certificate + 64-byte Ed25519 signature over the raw nonce.
4. Server waits for 32-byte acknowledgment: SHA256(raw_pubkey || nonce). (Ack is optional for server logic but enables replay defense on client.)

Configuration file `config.yaml` example:
```yaml
listen_address: "0.0.0.0"   # UDP bind address
udp_port: 32125
certificate: "certs/server.der"   # DER-encoded self-signed Ed25519 certificate
private_key: "certs/server.key"   # PEM PKCS8 Ed25519 private key (un-encrypted)
log_level: INFO
# Optional static allowed CIDR list (string match only) for probe source IPs
allowed_probe_sources: []
```

Usage:
```bash
pip install -e .
open-friendly-net-detection-server --config config.yaml
```

Generate Ed25519 key + self-signed certificate (example):
```bash
python scripts/gen_cert.py certs/server.key certs/server.der
```

Docker build:
```bash
docker build -f linux.Dockerfile -t fnd-server:dev .
```

License: MIT
