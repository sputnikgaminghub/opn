#!/usr/bin/env python3
"""Generate VAPID keys for Web Push.

Outputs:
- VAPID_PUBLIC_KEY (base64url, no padding) -> use in frontend
- VAPID_PRIVATE_KEY_PEM (PEM) -> use in backend env var VAPID_PRIVATE_KEY
"""

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def main():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Private key PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8").strip()

    # Public key in uncompressed point format (65 bytes): 0x04 || X(32) || Y(32)
    nums = public_key.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    public_uncompressed = b"\x04" + x + y
    public_b64url = b64url_nopad(public_uncompressed)

    print("VAPID_PUBLIC_KEY=" + public_b64url)
    print("\n# Set this whole PEM as VAPID_PRIVATE_KEY (preserve newlines):\n")
    print(private_pem)

if __name__ == "__main__":
    main()
