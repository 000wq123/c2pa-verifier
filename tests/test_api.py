import base64, io
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app import keys

def up(client, data, name="x.jpg", ct="image/jpeg"):
    return client.post("/v1/verify", files={"file": (name, io.BytesIO(data), ct)})

def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}

def test_verified(client, samples):
    r = up(client, samples["signed"]); assert r.status_code == 200
    j = r.json()
    assert j["status"] == "verified"
    assert j["manifest"]["signer"] == "Prototype Signer"
    assert j["manifest"]["trust_list_status"] == "untrusted"  # test CA not on trust list
    assert "c2pa.actions.v2" in j["manifest"]["claims"] or "c2pa.actions" in j["manifest"]["claims"]
    # stored + report signature verifies
    assert client.get(f"/v1/verify/{j['id']}").json() == j
    rep = client.get(f"/v1/verify/{j['id']}/report").json()
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(rep["public_key"]))
    pub.verify(base64.b64decode(rep["signature"]), keys.canonical(rep["report"]))

def test_tampered(client, samples):
    j = up(client, samples["tampered"]).json()
    assert j["status"] == "tampered"
    assert "assertion.dataHash.mismatch" in j["manifest"]["failure_codes"]

def test_stripped_unknown(client, samples):
    j = up(client, samples["stripped"]).json()
    assert j["status"] == "stripped" and j["confidence"] == "low"
    assert j["soft_binding"]["recovered_manifest_id"] is None
    assert j["platform_hint"]["heuristic"] is True

def test_stripped_recovered(client, samples, tmp_path):
    import register_known
    p = tmp_path / "signed.jpg"; p.write_bytes(samples["signed"])
    ph, mid = register_known.register(str(p))
    j = up(client, samples["stripped"]).json()
    assert j["status"] == "stripped"
    sb = j["soft_binding"]
    assert sb["matched"] and sb["method"] == "phash" and sb["distance"] <= 8
    assert sb["recovered_manifest_id"] == mid
    lk = client.post("/v1/lookup", json={"phash": ph}).json()
    assert lk["match"]["manifest_id"] == mid and lk["match"]["distance"] == 0

def test_bad_uploads(client, monkeypatch):
    assert up(client, b"hello not an image", "a.txt", "text/plain").status_code == 415
    assert up(client, b"").status_code == 400
    from app import main
    monkeypatch.setattr(main, "MAX_BYTES", 10)
    assert up(client, b"x" * 100).status_code == 413
    assert client.get("/v1/verify/nope").status_code == 404
    assert client.post("/v1/lookup", json={"phash": "zz"}).status_code == 422
