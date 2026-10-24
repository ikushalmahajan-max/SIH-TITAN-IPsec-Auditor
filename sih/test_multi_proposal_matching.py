import unittest
from unittest.mock import patch

from sih.analyzer.tunnel_partitioner import partition_and_audit_tunnels


ENDPOINTS = ("10.0.0.1", "10.0.0.2")


def proposal(cipher, key_length, dh_group, dh_bits):
    return {
        "has_real_proposals": True,
        "encryption_algorithm": cipher,
        "key_length": key_length,
        "dh_group": dh_group,
        "dh_bits": dh_bits,
        "_endpoint_pair": ENDPOINTS,
    }


def run_audit(features, ike_map):
    def fake_cipher_inference(_features, matched):
        return {
            "operating_mode": "Test",
            "inferred_cipher": (
                matched["encryption_algorithm"] if matched else "Indeterminate"
            ),
            "integrity_algorithm": "Test",
        }

    with (
        patch(
            "sih.analyzer.tunnel_partitioner.infer_ipsec_cipher_and_mode",
            side_effect=fake_cipher_inference,
        ),
        patch(
            "sih.analyzer.tunnel_partitioner.perform_encrypted_traffic_analysis",
            return_value={
                "application_category": "Test",
                "eta_confidence": 1.0,
                "avg_packet_size_bytes": 100,
                "packet_size_std_dev": 0,
                "burstiness_index": 0,
                "traffic_pattern": "Test",
            },
        ),
    ):
        return partition_and_audit_tunnels(features, ike_map)


def sa(spi):
    # At least five frames avoids the existing probe-like classification
    # from masking the proposal-matching result.
    return [
        {
            "spi": spi, "esp": True,
            "ip_src": ENDPOINTS[0], "ip_dst": ENDPOINTS[1],
            "seq_num": seq,
        }
        for seq in range(1, 6)
    ]


class TestMultipleProposalMatching(unittest.TestCase):
    def test_conflicting_endpoint_proposals_remain_indeterminate(self):
        a = proposal("ENCR_AES_GCM_16", 256, "ECP-384", 384)
        b = proposal("ENCR_DES", 64, "MODP-768", 768)
        ike_map = {
            ENDPOINTS: b,
            ENDPOINTS[0]: b,
            ENDPOINTS[1]: b,
            "all_proposals": [a, b],
        }

        results = run_audit(sa("0x1111") + sa("0x2222"), ike_map)

        self.assertEqual(len(results), 2)
        self.assertEqual(
            [r["inferred_cipher"] for r in results],
            ["Indeterminate", "Indeterminate"],
        )

    def test_exact_spi_match_wins_over_endpoint_ambiguity(self):
        a = proposal("ENCR_AES_GCM_16", 256, "ECP-384", 384)
        b = proposal("ENCR_DES", 64, "MODP-768", 768)
        ike_map = {
            ENDPOINTS: b,
            ENDPOINTS[0]: b,
            ENDPOINTS[1]: b,
            "0x1111": a,
            "all_proposals": [a, b],
        }

        results = run_audit(sa("0x1111") + sa("0x2222"), ike_map)

        self.assertEqual(results[0]["inferred_cipher"], "ENCR_AES_GCM_16")
        self.assertEqual(results[1]["inferred_cipher"], "Indeterminate")

    def test_unique_endpoint_proposal_is_matched(self):
        a = proposal("ENCR_AES_GCM_16", 256, "ECP-384", 384)
        ike_map = {
            ENDPOINTS: a,
            ENDPOINTS[0]: a,
            ENDPOINTS[1]: a,
            "all_proposals": [a],
        }

        results = run_audit(sa("0x1111"), ike_map)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["inferred_cipher"], "ENCR_AES_GCM_16")


if __name__ == "__main__":
    unittest.main(verbosity=2)
