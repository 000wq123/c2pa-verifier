import io
from fastapi import FastAPI, File, HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel
from . import db, keys
from .verify import verify_bytes

MAX_BYTES = 20 * 1024 * 1024
MIME = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}
app = FastAPI(title="C2PA verifier (prototype)")

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/v1/verify")
async def verify(file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "file too large")
    if not data:
        raise HTTPException(400, "empty upload")
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError):
        raise HTTPException(415, "not a supported image")
    if img.format not in MIME:
        raise HTTPException(415, f"unsupported format {img.format}")
    result = verify_bytes(data, MIME[img.format], img)
    db.save_result(result)
    return result

@app.get("/v1/verify/{rid}")
def get_verify(rid: str):
    r = db.get_result(rid)
    if not r:
        raise HTTPException(404, "not found")
    return r

@app.get("/v1/verify/{rid}/report")
def report(rid: str):
    r = db.get_result(rid)
    if not r:
        raise HTTPException(404, "not found")
    log = {"result_id": rid, "input_sha256": r["audit"]["sha256"],
           "verified_at": r["audit"]["verified_at"], "status": r["status"], "result": r}
    return {"report": log, "signature": keys.sign(log), "alg": "Ed25519",
            "public_key": keys.public_key_b64()}

class Lookup(BaseModel):
    phash: str

@app.post("/v1/lookup")
def lookup(q: Lookup):
    try:
        best = db.nearest(q.phash)
    except ValueError:
        raise HTTPException(422, "bad phash hex")
    if not best:
        return {"match": None}
    return {"match": {"manifest_id": best[1], "distance": best[0],
                      "within_threshold": best[0] <= 8}}
