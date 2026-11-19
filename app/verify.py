import hashlib, io, json, uuid
from datetime import datetime, timezone
import c2pa, imagehash
from PIL import Image
from . import db, keys
from .heuristics import platform_hint
from .watermark import decode_watermark

PHASH_MAX_DISTANCE = 8  # prototype threshold
# Failure codes that only concern trust-list membership, not integrity.
TRUST_ONLY_CODES = {"signingCredential.untrusted"}

def phash(img: Image.Image) -> str:
    return str(imagehash.phash(img))

def read_manifest(data: bytes, mime: str):
    """Returns (store_dict, active_manifest_dict) or None if no manifest."""
    reader = c2pa.Reader.try_create(mime, io.BytesIO(data))
    if reader is None:
        return None
    with reader:
        store = json.loads(reader.json())
    active = store.get("manifests", {}).get(store.get("active_manifest"), {})
    return store, active

def _failures(store: dict) -> list[str]:
    vr = (store.get("validation_results") or {}).get("activeManifest") or {}
    codes = [f.get("code") for f in vr.get("failure", [])]
    codes += [s.get("code") for s in store.get("validation_status", []) or []]
    return sorted({c for c in codes if c})

def verify_bytes(data: bytes, mime: str, img: Image.Image) -> dict:
    result = {"id": str(uuid.uuid4()), "status": None, "confidence": None,
              "manifest": None,
              "soft_binding": {"matched": False, "method": None, "distance": None,
                               "recovered_manifest_id": None},
              "platform_hint": None}
    found = read_manifest(data, mime)
    if found:
        store, active = found
        fails = _failures(store)
        integrity_fails = [c for c in fails if c not in TRUST_ONLY_CODES]
        si = active.get("signature_info", {}) or {}
        result["manifest"] = {
            "id": store.get("active_manifest"),
            "signer": si.get("common_name") or si.get("issuer"),
            "claims": [a.get("label") for a in active.get("assertions", [])],
            "trust_list_status": "trusted" if store.get("validation_state") == "Trusted"
                                 else ("untrusted" if "signingCredential.untrusted" in fails else "unknown"),
            "validation_state": store.get("validation_state"),
            "failure_codes": fails,
        }
        if integrity_fails:
            result["status"], result["confidence"] = "tampered", "high"
        else:
            result["status"], result["confidence"] = "verified", "high"
    else:
        result["status"] = "stripped"
        wm = decode_watermark(img)  # stub, always None for now
        ph = phash(img)
        best = db.nearest(ph)
        if wm:
            result["soft_binding"].update(matched=True, method="watermark", recovered_manifest_id=wm)
            result["confidence"] = "high"
        elif best and best[0] <= PHASH_MAX_DISTANCE:
            result["soft_binding"].update(matched=True, method="phash", distance=best[0],
                                          recovered_manifest_id=best[1])
            result["confidence"] = "medium"
        else:
            result["soft_binding"].update(method="phash", distance=best[0] if best else None)
            result["confidence"] = "low"
        result["platform_hint"] = platform_hint(img)
    audit = {"sha256": hashlib.sha256(data).hexdigest(),
             "verified_at": datetime.now(timezone.utc).isoformat()}
    result["audit"] = audit
    audit["signature"] = keys.sign({k: v for k, v in result.items() if k != "audit"} | {"audit": {k: audit[k] for k in ("sha256", "verified_at")}})
    return result
