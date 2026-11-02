"""Canonical JSON serialization, strict parsing, and argument hash tests.

Repository location: tests/unit/test_canonical_json.py
Run from the repository root with PYTHONPATH=src using pytest or unittest.
Tests run offline; no API key, Docker, database, or persistent key is required.
This tests the project JSON subset, which deliberately excludes floats.
"""

import copy
import json
import unittest
from datetime import datetime
from decimal import Decimal

from secure_agent.common.canonical_json import (
    CanonicalJSONError,
    MAX_JSON_DEPTH,
    MAX_SAFE_INTEGER,
    canonical_json_bytes,
    canonical_json_text,
    canonical_json_hash,
    canonical_json_loads,
    tool_arguments_hash,
)
from secure_agent.common.schemas import parse_tool_call
from pydantic import ValidationError


class TestCanonicalJSON(unittest.TestCase):
    def test_nested_key_order(self):
        a = {"z": [{"b": 2, "a": 1}], "a": False}
        b = {"a": False, "z": [{"a": 1, "b": 2}]}
        self.assertEqual(canonical_json_bytes(a), b'{"a":false,"z":[{"a":1,"b":2}]}')
        self.assertEqual(canonical_json_bytes(a), canonical_json_bytes(b))
        self.assertEqual(canonical_json_hash(a), canonical_json_hash(b))

    def test_utf16_order(self):
        # Supplementary characters sort before U+E000 in UTF-16, unlike Python.
        self.assertEqual(
            canonical_json_text({"\ue000": 1, "\U0001f600": 2}), '{"😀":2,"\ue000":1}'
        )

    def test_literals(self):
        self.assertEqual(
            canonical_json_bytes([None, True, False, 0, -1, ""]),
            b'[null,true,false,0,-1,""]',
        )
        self.assertNotEqual(canonical_json_hash([1, 2]), canonical_json_hash([2, 1]))

    def test_unicode_and_code_preserved(self):
        content = "  # Türkçe: ığüşöç\r\ndef topla(a, b):\n    return a+b\n"
        self.assertEqual(
            json.loads(canonical_json_text({"content": content}))["content"], content
        )
        self.assertNotEqual(
            canonical_json_hash({"s": "é"}), canonical_json_hash({"s": "e\u0301"})
        )
        self.assertNotEqual(
            canonical_json_hash({"s": "x\r\n"}), canonical_json_hash({"s": "x\n"})
        )

    def test_invalid_types(self):
        for value in [
            1.0,
            float("nan"),
            float("inf"),
            Decimal("1"),
            b"abc",
            (1,),
            {1},
            datetime.now(),
            {1: "v"},
            "\ud800",
            {"\ud800": 1},
        ]:
            with self.subTest(value=repr(value)):
                with self.assertRaises(CanonicalJSONError):
                    canonical_json_bytes(value)

    def test_safe_integer_bounds(self):
        for n in [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER]:
            self.assertEqual(canonical_json_text(n), str(n))
        for n in [MAX_SAFE_INTEGER + 1, -MAX_SAFE_INTEGER - 1]:
            with self.assertRaises(CanonicalJSONError):
                canonical_json_bytes(n)

    def test_duplicate_keys(self):
        for payload in ['{"a":1,"a":2}', '{"x":{"a":1,"a":2}}', '{"a":1,"\\u0061":2}']:
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalJSONError):
                    canonical_json_loads(payload)

    def test_float_tokens_rejected(self):
        for payload in ["1.0", "1e0", "NaN", "Infinity", "-Infinity", '{"a":1.2}']:
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalJSONError):
                    canonical_json_loads(payload)

    def test_invalid_raw_json(self):
        for payload in [
            "",
            "{}{}",
            '{"a":}',
            b"\xff",
            b"\xff\xfe{\x00}\x00",
            "[1,]",
            None,
            {},
            '"\\ud800"',
            "9007199254740992",
        ]:
            with self.subTest(payload=repr(payload)):
                with self.assertRaises(CanonicalJSONError):
                    canonical_json_loads(payload)

    def test_utf8_loading_and_escapes(self):
        self.assertEqual(
            canonical_json_loads(' {"s":"Türkçe"} '.encode()), {"s": "Türkçe"}
        )
        self.assertEqual(
            canonical_json_hash(canonical_json_loads('{"s":"\\u015f"}')),
            canonical_json_hash({"s": "ş"}),
        )

    def test_cycles_and_shared_objects(self):
        a = []
        a.append(a)
        b = {}
        b["b"] = b
        for value in [a, b]:
            with self.assertRaises(CanonicalJSONError):
                canonical_json_bytes(value)
        shared = {"x": 1}
        self.assertEqual(canonical_json_bytes([shared, shared]), b'[{"x":1},{"x":1}]')

    def test_depth_limit(self):
        value = 0
        for _ in range(MAX_JSON_DEPTH):
            value = [value]
        self.assertIsInstance(canonical_json_bytes(value), bytes)
        with self.assertRaises(CanonicalJSONError):
            canonical_json_bytes([value])
        with self.assertRaises(CanonicalJSONError):
            canonical_json_loads("[" * 2000 + "0" + "]" * 2000)

    def test_hash_known_vector(self):
        self.assertEqual(
            canonical_json_hash({}),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        )
        self.assertEqual(len(canonical_json_hash({"s": "ş"})), 64)

    def test_tool_arguments_only_and_no_mutation(self):
        call = {
            "request_id": "r",
            "task_id": "t",
            "tool": "secure_edit_file",
            "arguments": {"path": "main.py", "content": "# Türkçe\n"},
        }
        original = copy.deepcopy(call)
        expected = canonical_json_hash(call["arguments"])
        self.assertEqual(tool_arguments_hash(call), expected)
        self.assertEqual(tool_arguments_hash(parse_tool_call(call)), expected)
        self.assertEqual(call, original)
        call["request_id"] = "other-request"
        self.assertEqual(tool_arguments_hash(call), expected)
        call["task_id"] = "other-task"
        self.assertEqual(tool_arguments_hash(call), expected)
        for field, value in [("path", "other.py"), ("content", "# Türkçe\n ")]:
            changed = copy.deepcopy(original)
            changed["arguments"][field] = value
            self.assertNotEqual(tool_arguments_hash(changed), expected)
        self.assertEqual(original["arguments"], call["arguments"])

    def test_schema_validation(self):
        for call in [{}, {"tool": "shell"}]:
            with self.assertRaises(ValidationError):
                tool_arguments_hash(call)

    def test_text_and_raw_string_are_distinct(self):
        self.assertEqual(canonical_json_bytes("{}"), b'"{}"')
        self.assertEqual(canonical_json_bytes(canonical_json_loads("{}")), b"{}")
        self.assertEqual(
            canonical_json_bytes({"s": "ş"}),
            canonical_json_text({"s": "ş"}).encode("utf-8"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
