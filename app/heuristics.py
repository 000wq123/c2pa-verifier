"""PROTOTYPE HEURISTICS ONLY. Not evidence of anything; hints for humans."""
from PIL import Image

# Common resize targets. Rough folk knowledge, not verified per platform/version.
LONG_EDGE_HINTS = {1080: "instagram", 1600: "whatsapp", 2048: "facebook_or_x"}

def platform_hint(img: Image.Image) -> dict:
    evidence, guess = [], None
    if not img.getexif():
        evidence.append("no EXIF metadata")
    long_edge = max(img.size)
    if long_edge in LONG_EDGE_HINTS:
        guess = LONG_EDGE_HINTS[long_edge]
        evidence.append(f"long edge exactly {long_edge}px")
    q = getattr(img, "quantization", None)
    if q:
        luma = q.get(0)
        if luma is not None:
            sig = sum(luma) / len(luma)
            evidence.append(f"JPEG luma quant table mean={sig:.1f} ({len(q)} tables)")
    return {"likely_stripped_by": guess, "evidence": evidence, "heuristic": True}
