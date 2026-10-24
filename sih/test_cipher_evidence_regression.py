import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from analyzer.cipher_mode_infer import infer_ipsec_cipher_and_mode


class TestCipherEvidenceRegression(unittest.TestCase):
    def test_missing_crypto_fields_are_not_invented(self):
        features = [
            {
                "esp": True,
                "packet_length": 1200,
                "shannon_entropy": 7.5,
            }
        ]

        ike = {
            "has_real_proposals": True,
            "version": "IKEv2",
            "encryption_algorithm": None,
            "key_length": None,
            "dh_group": None,
            "dh_bits": None,
            "integrity_algorithm": None,
        }

        result = infer_ipsec_cipher_and_mode(features, ike)

        print("\nRegression result:", result["inferred_cipher"])
        print("Reported confidence:", result["cipher_confidence"])

        self.assertTrue(
            result["is_indeterminate"],
            "Missing cryptographic fields must not produce a definite cipher inference.",
        )
        self.assertNotIn(
            "AES-CBC-256",
            result["inferred_cipher"],
            "AES-CBC-256 must not be invented when encryption and key length are missing.",
        )
        self.assertLess(
            result["cipher_confidence"],
            100.0,
            "Incomplete evidence must not receive 100% cipher confidence.",
        )


    def test_complete_aes_gcm_proposal_is_preserved(self):
        features = [
            {"esp": True, "packet_length": 1200, "shannon_entropy": 7.5}
        ]
        ike = {
            "has_real_proposals": True,
            "version": "IKEv2",
            "encryption_algorithm": "ENCR_AES_GCM_16",
            "key_length": 256,
            "dh_group": "ECP-384",
            "dh_bits": 384,
            "integrity_algorithm": "AEAD",
        }

        result = infer_ipsec_cipher_and_mode(features, ike)

        self.assertIn("ENCR_AES_GCM_16-256 AEAD", result["inferred_cipher"])
        self.assertFalse(result["is_indeterminate"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
