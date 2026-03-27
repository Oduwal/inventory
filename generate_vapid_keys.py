"""
Run once to generate VAPID keys for web push.
Then add the output values to your Railway environment variables.

Usage:
    python generate_vapid_keys.py
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import base64

private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Private key — raw 32-byte big-endian integer, base64url-encoded
private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
VAPID_PRIVATE_KEY = base64.urlsafe_b64encode(private_bytes).rstrip(b'=').decode()

# Public key — uncompressed EC point (0x04 || X || Y), base64url-encoded
pub = private_key.public_key().public_numbers()
pub_bytes = b'\x04' + pub.x.to_bytes(32, 'big') + pub.y.to_bytes(32, 'big')
VAPID_PUBLIC_KEY = base64.urlsafe_b64encode(pub_bytes).rstrip(b'=').decode()

print("Add these to your Railway environment variables:\n")
print(f"VAPID_PUBLIC_KEY={VAPID_PUBLIC_KEY}")
print(f"VAPID_PRIVATE_KEY={VAPID_PRIVATE_KEY}")
