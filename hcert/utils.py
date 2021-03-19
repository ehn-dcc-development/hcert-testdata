import base64
import json

import base45


def json_compact_dumps(data) -> int:
    """Return JSON compact dumps"""
    return json.dumps(data, indent=None, separators=(",", ":"))


def json_compact_len(data) -> int:
    """Return length of JSON compact encoding"""
    return len(json_compact_dumps(data))


def encode_data(data: bytes, encoding: str) -> bytes:
    if encoding == "binary":
        return data
    elif encoding == "base45":
        return base45.b45encode(data)
    elif encoding == "base64":
        return base64.b64encode(data)
    elif encoding == "base85":
        return base64.b85encode(data)
    else:
        raise RuntimeError("Invalid encoding")


def decode_data(data: bytes, encoding: str) -> bytes:
    if encoding == "binary":
        return data
    elif encoding == "base45":
        return base45.b45decode(data)
    elif encoding == "base64":
        return base64.b64decode(data)
    elif encoding == "base85":
        return base64.b85decode(data)
    else:
        raise RuntimeError("Invalid encoding")
