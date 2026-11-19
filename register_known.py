"""Register a C2PA-signed image's pHash + active manifest ID for soft-binding lookup."""
import argparse, mimetypes
from PIL import Image
from app import db
from app.verify import phash, read_manifest

def register(path: str) -> tuple[str, str]:
    data = open(path, "rb").read()
    found = read_manifest(data, mimetypes.guess_type(path)[0] or "image/jpeg")
    if not found:
        raise SystemExit(f"{path}: no C2PA manifest")
    mid = found[0]["active_manifest"]
    ph = phash(Image.open(path))
    db.add_known(ph, mid)
    return ph, mid

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("image"); a = p.parse_args()
    print("registered", *register(a.image))
