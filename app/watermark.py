from PIL import Image

def decode_watermark(image: Image.Image) -> str | None:
    """Return a manifest ID recovered from an invisible watermark, or None.

    TODO: integrate a real watermark decoder (e.g. TrustMark). Stub: always None.
    """
    return None
