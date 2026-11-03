"""Canonical JSON (RFC 8785 style) and strict parser tests.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import json

import pytest

from ciphermesh.trust.canonical import CanonicalizationError, StrictJSONError, canonicalize, strict_loads


def test_member_order_does_not_change_bytes():
    assert canonicalize({"b": 1, "a": 2}) == canonicalize({"a": 2, "b": 1}) == b'{"a":2,"b":1}'


def test_nested_objects_and_arrays_are_sorted_recursively_without_whitespace():
    value = {"z": [3, {"y": True, "x": None}], "a": {"d": "v", "c": False}}
    assert canonicalize(value) == b'{"a":{"c":false,"d":"v"},"z":[3,{"x":null,"y":true}]}'


def test_non_ascii_is_emitted_as_utf8_not_escaped():
    out = canonicalize({"name": "Kumar ✓ क"})
    assert "✓".encode("utf-8") in out and b"\\u" not in out


def test_control_characters_use_mandatory_escapes():
    assert canonicalize("a\nb\t\x01\"\\") == b'"a\\nb\\t\\u0001\\"\\\\"'


def test_keys_sorted_by_utf16_code_units_not_code_points():
    # U+1F600 is D83D DE00 in UTF-16, which sorts before U+FB01 even though its code point is larger.
    out = canonicalize({"ﬁ": 1, "\U0001F600": 2}).decode("utf-8")
    assert out.index("\U0001F600") < out.index("ﬁ")


@pytest.mark.parametrize("number,expected", [
    (1.0, "1"), (4.50, "4.5"), (0.002, "0.002"), (1e21, "1e+21"), (1e30, "1e+30"), (1e-7, "1e-7"),
    (0.000001, "0.000001"), (333333333.33333329, "333333333.3333333"), (-0.0, "0"), (5e-324, "5e-324"),
    (123456789012345680000.0, "123456789012345680000"), (-1.5, "-1.5"), (100, "100"), (-7, "-7"),
])
def test_numbers_follow_ecmascript_shortest_form(number, expected):
    assert canonicalize(number).decode() == expected


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 2**53, {1: "x"}, "\ud800", {"a": object()}])
def test_values_without_canonical_form_are_rejected(bad):
    with pytest.raises(CanonicalizationError):
        canonicalize(bad)


def test_canonical_form_is_stable_across_reserialisation():
    value = {"header": {"msg_id": "m", "nonce": "n", "issued_at": "2026-11-01T10:00:00.000Z"},
             "payload": {"patterns": ["PRJ-[0-9]{4}", "EMP-[0-9]{6}"], "n": 3}}
    first = canonicalize(value)
    for _ in range(50):
        assert canonicalize(json.loads(first)) == first
    pretty = json.dumps(value, indent=4, sort_keys=False)
    assert canonicalize(strict_loads(pretty.encode())) == first


def test_strict_loads_rejects_duplicate_member_names():
    with pytest.raises(StrictJSONError) as err:
        strict_loads(b'{"command":"A","command":"B"}')
    assert err.value.code == "JSON_DUPLICATE_KEY"


@pytest.mark.parametrize("raw", [b'{"a": NaN}', b'{"a": Infinity}', b'\xff\xfe{}', b'{"a": ', b"[" * 40 + b"]" * 40,
                                 b'{"a": 1' + b"0" * 5000 + b'}', b'{"a": 1e400}', b'{"a": -1e400}'])
def test_strict_loads_rejects_malformed_input(raw):
    with pytest.raises(StrictJSONError) as err:
        strict_loads(raw)
    assert err.value.code == "JSON_MALFORMED"
