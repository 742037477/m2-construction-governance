"""Versioned deterministic bytes for the new construction domain.

This is deliberately not an import from C06. See docs/PROVENANCE.md.
"""
from hashlib import sha256 as _sha256
import json
import re


class Denied(ValueError):
    """A checked governance precondition failed."""


def require(condition, code):
    if not condition:
        raise Denied(code)


def _domain(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(0 <= value <= 9_007_199_254_740_991, "CANONICAL_INTEGER")
        return
    if type(value) is str:
        require("\x00" not in value and not any(0xD800 <= ord(c) <= 0xDFFF for c in value),
                "CANONICAL_STRING")
        return
    if type(value) is list:
        for item in value:
            _domain(item)
        return
    require(type(value) is dict and all(type(k) is str for k in value), "CANONICAL_TYPE")
    for key, item in value.items():
        _domain(key)
        _domain(item)


def canonical(value):
    _domain(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value):
    return _sha256(canonical(value)).hexdigest()


def bytes_hash(raw):
    require(type(raw) is bytes, "HASH_INPUT_BYTES")
    return _sha256(raw).hexdigest()


def strict_json(raw):
    require(type(raw) in (bytes, str), "JSON_INPUT")
    text = raw.decode("utf-8") if type(raw) is bytes else raw
    require(not text.startswith("\ufeff"), "JSON_BOM")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    value = json.loads(text, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Denied("JSON_NONFINITE")))
    _domain(value)
    return value


def exact_fields(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)


def hash_text(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None
