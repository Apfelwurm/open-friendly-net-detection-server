#!/usr/bin/env python3
"""Generate Ed25519 private key + self-signed certificate (minimal) for FND server.
Usage: gen_cert.py server.key server.der

The certificate is self-signed and has long validity; clients pin raw public key.
"""
import sys
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

def main():
    if len(sys.argv) != 3:
        print('Usage: gen_cert.py <private_key.pem> <certificate.der>')
        return 1
    key_path, cert_path = sys.argv[1], sys.argv[2]
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'FND Server'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .sign(private_key=priv, algorithm=None)
    )
    with open(key_path, 'wb') as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    print('Wrote private key', key_path)
    print('Wrote certificate', cert_path)
    # Output base64 raw public key for client config convenience
    import base64
    raw_pub = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    print('Base64 raw public key:', base64.b64encode(raw_pub).decode())

if __name__ == '__main__':
    raise SystemExit(main())
