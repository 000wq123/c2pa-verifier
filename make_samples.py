"""Generate a throwaway test CA + Ed25519 signing cert and C2PA-signed sample images."""
import datetime, io, json, os, sys
import c2pa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from PIL import Image, ImageDraw

def _certs():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Prototype")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ed25519.Ed25519PrivateKey.generate()
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prototype Signer"),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Prototype")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    chain = leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return chain, pem

def base_jpeg(size=(640, 480)) -> bytes:
    im = Image.new("RGB", size, (30, 90, 160)); d = ImageDraw.Draw(im)
    for i in range(0, size[0], 40):
        d.ellipse([i, i % size[1], i + 80, (i % size[1]) + 80], fill=(i % 255, 200, 255 - i % 255))
    d.rectangle([50, 300, 300, 420], fill=(240, 220, 20))
    b = io.BytesIO(); im.save(b, "JPEG", quality=90); return b.getvalue()

def sign_jpeg(src: bytes) -> bytes:
    chain, pem = _certs()
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(b"ed25519", chain, pem, None))
    manifest = {"claim_generator_info": [{"name": "c2pa-verifier-prototype", "version": "0.1"}],
                "title": "sample.jpg",
                "assertions": [{"label": "c2pa.actions", "data": {"actions": [{
                    "action": "c2pa.created",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]}}]}
    out = io.BytesIO()
    with c2pa.Builder.from_json(json.dumps(manifest)) as b:
        b.sign(signer, "image/jpeg", io.BytesIO(src), out)
    return out.getvalue()

def tamper(signed: bytes) -> bytes:
    """Flip bytes inside the JPEG entropy-coded data (after the manifest), keeping the manifest."""
    buf = bytearray(signed)
    eoi = buf.rfind(b"\xff\xd9")
    for i in range(eoi - 400, eoi - 300):
        if buf[i] not in (0xFF, 0x00) and buf[i] ^ 0x01 != 0xFF:
            buf[i] ^= 0x01
    return bytes(buf)

def strip(signed: bytes) -> bytes:
    """Re-encode with Pillow (drops APP11/JUMBF), like a social platform would."""
    b = io.BytesIO(); Image.open(io.BytesIO(signed)).convert("RGB").save(b, "JPEG", quality=80)
    return b.getvalue()

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples"
    os.makedirs(out, exist_ok=True)
    s = sign_jpeg(base_jpeg())
    for name, data in {"signed.jpg": s, "tampered.jpg": tamper(s), "stripped.jpg": strip(s)}.items():
        open(os.path.join(out, name), "wb").write(data); print("wrote", os.path.join(out, name))
