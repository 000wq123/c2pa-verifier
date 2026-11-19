"""Ed25519 key for signing audit reports. Generated on first run."""
import base64, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEY_PATH = os.environ.get("C2PA_AUDIT_KEY", "data/audit_ed25519.pem")

def _key() -> Ed25519PrivateKey:
    if not os.path.exists(KEY_PATH):
        os.makedirs(os.path.dirname(KEY_PATH) or ".", exist_ok=True)
        k = Ed25519PrivateKey.generate()
        with open(KEY_PATH, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        os.chmod(KEY_PATH, 0o600)
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sign(obj) -> str:
    return base64.b64encode(_key().sign(canonical(obj))).decode()

def public_key_b64() -> str:
    pub = _key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()
