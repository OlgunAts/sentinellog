"""Safe, bounded handling of untrusted uploaded text files."""

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def decode_upload(payload: bytes) -> str:
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 10 MB upload limit.")
    if b"\x00" in payload[:4096]:
        raise ValueError("Binary files are not supported.")
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Unable to decode file safely as UTF-8, UTF-16, or Windows-1252 text.")
