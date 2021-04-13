import json


def json_compact_dumps(data) -> int:
    """Return JSON compact dumps"""
    return json.dumps(data, indent=None, separators=(",", ":"))


def json_compact_len(data) -> int:
    """Return length of JSON compact encoding"""
    return len(json_compact_dumps(data))
