"""Canonical JSON for signatures (RFC 8785 JSON Canonicalization Scheme style).

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Why this exists
---------------
A signature covers bytes, not "meaning". If the sender and the receiver
serialise the same JSON object differently (key order, spaces, number format,
escapes), a valid message fails verification - or worse, two different byte
strings may claim to be the same object. Both sides therefore sign and verify
the *canonical* form produced here:

* object members sorted by the UTF-16 code units of their names (RFC 8785 3.2.3);
* no insignificant whitespace;
* strings emitted as UTF-8 with only the mandatory JSON escapes;
* numbers written in the ECMAScript shortest round-trip form; integers are
  limited to the IEEE-754 safe range (+/- 2**53 - 1) so every peer agrees;
* NaN, Infinity, lone surrogates and non-string keys are rejected.

The module also provides :func:`strict_loads`, the parser used at checkpoint C2.
It refuses duplicate member names, NaN/Infinity literals, invalid UTF-8 and
excessive nesting, because those are classic ways to make two parsers disagree
about what a signed document says.
"""
from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 16


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented canonically."""


class StrictJSONError(ValueError):
    """Raised by :func:`strict_loads`; ``code`` is a stable reason code."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise CanonicalizationError("lone surrogate code point in string")
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _number(value: float) -> str:
    """ECMAScript Number.prototype.toString() for a finite double (RFC 8785 3.2.2.3)."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits_tuple = Decimal(repr(abs(value))).as_tuple()
    digits = list(digits_tuple.digits)
    exponent = int(digits_tuple.exponent)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    s = "".join(map(str, digits))
    k = len(s)
    n = exponent + k
    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        exp = ("+" if e >= 0 else "-") + str(abs(e))
        body = (s if k == 1 else s[0] + "." + s[1:]) + "e" + exp
    return sign + body


def _encode(value: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH} levels")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside the IEEE-754 safe range")
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError("object member names must be strings")
        ordered = sorted(value, key=lambda name: name.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(key) + ":" + _encode(value[key], depth + 1) for key in ordered) + "}"
    raise CanonicalizationError(f"type {type(value).__name__} is not JSON-serialisable")


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 byte string of ``value``."""
    return _encode(value, 0).encode("utf-8")


def _reject_constant(name: str):
    raise StrictJSONError("JSON_MALFORMED", f"non-standard numeric literal {name} is not allowed")


def _finite_float(text: str) -> float:
    value = float(text)
    if math.isinf(value) or math.isnan(value):
        raise StrictJSONError("JSON_MALFORMED", "number overflows an IEEE-754 double")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("JSON_DUPLICATE_KEY", f"duplicate member name {key!r}")
        result[key] = value
    return result


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_DEPTH:
        return level
    if isinstance(value, dict):
        return max([_depth(v, level + 1) for v in value.values()] or [level + 1])
    if isinstance(value, list):
        return max([_depth(v, level + 1) for v in value] or [level + 1])
    return level


def strict_loads(raw: bytes) -> Any:
    """Parse untrusted bytes as strict JSON or raise :class:`StrictJSONError`."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("JSON_MALFORMED", f"frame is not valid UTF-8 (byte {exc.start})") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant,
                           parse_float=_finite_float)
    except StrictJSONError:
        raise
    except RecursionError:
        raise StrictJSONError("JSON_MALFORMED", "JSON nesting is too deep") from None
    except json.JSONDecodeError as exc:
        raise StrictJSONError("JSON_MALFORMED", f"invalid JSON at line {exc.lineno} column {exc.colno}") from None
    except ValueError:
        # e.g. an integer literal longer than Python's int/str conversion limit (4300 digits)
        raise StrictJSONError("JSON_MALFORMED", "numeric literal is too large") from None
    if _depth(value) > MAX_DEPTH:
        raise StrictJSONError("JSON_MALFORMED", f"JSON nesting deeper than {MAX_DEPTH} levels")
    return value
