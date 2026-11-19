import json, os, sqlite3
DATA_DIR = "/tmp" if os.environ.get("VERCEL") else "data"  # Vercel: only /tmp is writable (ephemeral)
DB_PATH = os.environ.get("C2PA_DB", f"{DATA_DIR}/verifier.db")

def conn():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS known (phash TEXT, manifest_id TEXT PRIMARY KEY)")
    c.execute("CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, body TEXT)")
    return c

def add_known(phash: str, manifest_id: str):
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO known VALUES (?,?)", (phash, manifest_id))

def nearest(phash: str):
    import imagehash
    target = imagehash.hex_to_hash(phash)
    best = None
    with conn() as c:
        for h, mid in c.execute("SELECT phash, manifest_id FROM known"):
            d = int(target - imagehash.hex_to_hash(h))
            if best is None or d < best[0]:
                best = (d, mid)
    return best  # (distance, manifest_id) or None

def save_result(r: dict):
    with conn() as c:
        c.execute("INSERT INTO results VALUES (?,?)", (r["id"], json.dumps(r)))

def get_result(rid: str):
    with conn() as c:
        row = c.execute("SELECT body FROM results WHERE id=?", (rid,)).fetchone()
    return json.loads(row[0]) if row else None
