# C2PA content verifier — PROTOTYPE

FastAPI service that checks an image for C2PA provenance and returns `verified`, `tampered` or `stripped`.
**"stripped" means no provenance was found / it can't be verified. It does NOT mean the image is fake.**

## Run
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python make_samples.py samples          # signed / tampered / stripped JPEGs (throwaway test CA)
.venv/bin/python register_known.py samples/signed.jpg   # store pHash + manifest ID for lookup
.venv/bin/uvicorn app.main:app --reload
curl -F file=@samples/stripped.jpg localhost:8000/v1/verify
.venv/bin/python -m pytest -q
```
State lives in `data/` (SQLite DB + Ed25519 audit key, created on first run).

## Routes
`POST /v1/verify` (multipart `file`) · `GET /v1/verify/{id}` · `GET /v1/verify/{id}/report` (Ed25519-signed JSON, public key included) · `POST /v1/lookup` `{"phash": "<hex>"}` · `GET /healthz`

## Logic
- Manifest read with `c2pa.Reader` (c2pa-python 0.39). Failure codes from `validation_results.activeManifest.failure`.
  Any failure except `signingCredential.untrusted` → `tampered`; otherwise `verified`.
  Trust-list membership is reported separately as `manifest.trust_list_status` (`trusted`/`untrusted`/`unknown`).
- No manifest → watermark decode (stub) → pHash nearest neighbour in SQLite; distance ≤ 8 → recovered manifest ID, else low confidence.

## Stubbed / heuristic / prototype-grade
- `decode_watermark()` is a **stub that always returns None** (TODO: real decoder, e.g. TrustMark).
- `platform_hint` is **heuristic only**: missing EXIF, long edge 1080/1600/2048 mapped to instagram/whatsapp/facebook_or_x from folk knowledge, JPEG quant-table mean reported as evidence only (no fingerprint DB).
- pHash threshold 8 and the confidence labels are arbitrary prototype values; pHash collisions/near-duplicates can give wrong recovered IDs.
- No trust list is configured, so real-world signers show `untrusted`/`unknown` unless you configure c2pa trust settings.
- Sample images are signed with a throwaway test CA generated at runtime.
- Upload limit 20 MB, JPEG/PNG/WEBP only. No auth, no rate limiting, linear scan over known hashes.
