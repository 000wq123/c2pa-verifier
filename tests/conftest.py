import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture(autouse=True)
def tmp_state(tmp_path, monkeypatch):
    from app import db, keys
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(keys, "KEY_PATH", str(tmp_path / "k.pem"))

@pytest.fixture(scope="session")
def samples():
    import make_samples as m
    s = m.sign_jpeg(m.base_jpeg())
    return {"signed": s, "tampered": m.tamper(s), "stripped": m.strip(s)}

@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)
