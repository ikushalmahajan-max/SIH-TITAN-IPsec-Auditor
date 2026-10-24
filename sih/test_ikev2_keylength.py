import struct
import unittest
from sih.analyzer.ike_dissector import parse_ike_payload


def make_packet(attrs=b"", transform_id=12):
    transform = struct.pack(
        "!BBHBBH", 0, 0, 8 + len(attrs), 1, 0, transform_id
    ) + attrs
    proposal = struct.pack(
        "!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1
    ) + transform
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    total_length = 28 + len(sa_payload)
    header = struct.pack(
        "!8s8sBBBBII",
        b"INITSP01", b"RESPSP01", 33, 0x20, 34, 0, 0, total_length
    )
    return header + sa_payload


class TestIKEv2KeyLengthParsing(unittest.TestCase):
    def test_key_length_first(self):
        attrs = struct.pack("!HH", 0x800E, 256)
        parsed = parse_ike_payload(make_packet(attrs))
        self.assertEqual(parsed["key_length"], 256)

    def test_key_length_after_another_attribute(self):
        attrs = struct.pack("!HH", 0x8001, 1) + struct.pack("!HH", 0x800E, 256)
        parsed = parse_ike_payload(make_packet(attrs))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["version"], "IKEv2.0")
        self.assertEqual(parsed["key_length"], 256)

    def test_missing_key_length_uses_default(self):
        attrs = struct.pack("!HH", 0x8001, 1)
        parsed = parse_ike_payload(make_packet(attrs))
        self.assertEqual(parsed["key_length"], 128)

    def test_unknown_attribute_before_key_length(self):
        attrs = struct.pack("!HH", 0x800F, 7) + struct.pack("!HH", 0x800E, 192)
        parsed = parse_ike_payload(make_packet(attrs))
        self.assertEqual(parsed["key_length"], 192)

    def test_truncated_attribute_does_not_crash(self):
        packet = make_packet()
        malformed = packet[:-1]
        try:
            parse_ike_payload(malformed)
        except (IndexError, struct.error):
            self.fail("Parser crashed on truncated IKEv2 input")


if __name__ == "__main__":
    unittest.main(verbosity=2)
