import struct
import unittest
from sih.analyzer.ike_dissector import (
    IKEV2_ENCR_TRANSFORMS,
    parse_ike_payload,
)

EXPECTED = {
    1: "ENCR_DES_IV64",
    3: "ENCR_3DES",
    5: "ENCR_IDEA",
    7: "ENCR_BLOWFISH",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    28: "ENCR_CHACHA20_POLY1305",
    29: "ENCR_AES_CCM_8_IIV",
}

def make_ikev2_sa_packet(encryption_id):
    transform = struct.pack("!BBHBBH", 0, 0, 8, 1, 0, encryption_id)
    proposal = struct.pack("!BBHBBBB", 0, 0, 16, 1, 1, 0, 1) + transform
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    total_length = 28 + len(sa_payload)
    header = struct.pack(
        "!8s8sBBBBII",
        b"INITSP01",
        b"RESPSP01",
        33, 0x20, 34, 0, 0, total_length
    )
    return header + sa_payload

class TestIKEv2RegistryMapping(unittest.TestCase):
    def test_registry_names(self):
        for transform_id, expected_name in EXPECTED.items():
            with self.subTest(transform_id=transform_id):
                self.assertEqual(
                    IKEV2_ENCR_TRANSFORMS[transform_id]["name"],
                    expected_name,
                )

    def test_parser_reports_registered_names(self):
        for transform_id, expected_name in EXPECTED.items():
            with self.subTest(transform_id=transform_id):
                parsed = parse_ike_payload(make_ikev2_sa_packet(transform_id))
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed["version"], "IKEv2.0")
                self.assertEqual(parsed["encryption_algorithm"], expected_name)

if __name__ == "__main__":
    unittest.main(verbosity=2)
