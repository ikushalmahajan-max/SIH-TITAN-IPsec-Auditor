import traceback
from analyzer.cipher_mode_infer import infer_ipsec_cipher_and_mode
from analyzer.eta_fingerprint import perform_encrypted_traffic_analysis

def partition_and_audit_tunnels(features, ike_map=None):
    """
    Partitions capture strictly per-SPI into independent Security Associations (SAs).
    Each unique SPI gets exactly ONE row with its own isolated IKE proposal,
    Cipher Inference, PQC Score, ETA profile, and Anti-Replay status.
    Features robust error isolation and granular Tier 1/2/3 matching logging.
    """
    if not features:
        return []

    ike_map = ike_map or {}
    all_proposals = ike_map.get("all_proposals", [])
    
    # 1. Bucket features strictly by unique SPI
    sa_buckets = {}
    for f in features:
        if f.get("esp") or f.get("ah") or f.get("spi"):
            spi_key = f.get("spi")
            if not spi_key:
                continue
            sa_buckets.setdefault(spi_key, []).append(f)

    if not sa_buckets:
        return []

    total_unique_sas = len(sa_buckets)
    sa_audits = []
    
    print(f"[TUNNEL_PARTITIONER] Beginning partition audit for {total_unique_sas} distinct Security Associations...")
    
    for sa_idx, (spi_key, sa_feats) in enumerate(sa_buckets.items()):
        try:
            # Discover all IPs associated with this specific SA (Normalized)
            src_ips = set(str(f.get("ip_src") or f.get("src_ip")).strip().lower() for f in sa_feats if (f.get("ip_src") or f.get("src_ip")))
            dst_ips = set(str(f.get("ip_dst") or f.get("dst_ip")).strip().lower() for f in sa_feats if (f.get("ip_dst") or f.get("dst_ip")))
            src_ips.discard("none")
            src_ips.discard("")
            dst_ips.discard("none")
            dst_ips.discard("")
            
            all_ips = sorted(list(src_ips.union(dst_ips)))
            
            if len(all_ips) >= 2:
                pair_key = (all_ips[0], all_ips[1])
                endpoints_str = f"{all_ips[0]} <-> {all_ips[1]}"
            elif len(all_ips) == 1:
                pair_key = (all_ips[0], all_ips[0])
                endpoints_str = all_ips[0]
            else:
                pair_key = ("0.0.0.0", "0.0.0.0")
                endpoints_str = "Gateway-to-Gateway"

            # Conservative SA-to-proposal association.
            # Exact Child-SA SPI evidence takes priority. Endpoint-only
            # evidence is accepted only when it identifies one unique proposal.
            sa_ike = None
            ambiguous_match = False
            tier_matched = (
                "Tier 0: No reliable IKE proposal association; "
                "parameters remain indeterminate"
            )

            spi_lookup_key = str(spi_key).lower() if spi_key else ""
            spi_candidate = ike_map.get(spi_lookup_key) if spi_lookup_key else None

            if isinstance(spi_candidate, dict) and spi_candidate.get("has_real_proposals"):
                sa_ike = spi_candidate
                tier_matched = f"Tier 1: Direct Child SPI Match ({spi_lookup_key})"
            else:
                # Prefer proposal records that explicitly preserve their
                # originating endpoint pair. Never pick the last of conflicts.
                pair_candidates = [
                    p for p in all_proposals
                    if isinstance(p, dict)
                    and p.get("has_real_proposals")
                    and tuple(p.get("_endpoint_pair", ())) == pair_key
                ]

                def proposal_signature(p):
                    fields = (
                        "encryption_algorithm", "key_length", "dh_group",
                        "dh_bits", "prf_algorithm", "integrity_algorithm"
                    )
                    return tuple(p.get(field) for field in fields)

                unique_candidates = {}
                for candidate in pair_candidates:
                    unique_candidates.setdefault(
                        proposal_signature(candidate), candidate
                    )

                if len(unique_candidates) == 1:
                    sa_ike = next(iter(unique_candidates.values()))
                    tier_matched = (
                        f"Tier 2: Unique endpoint-pair proposal "
                        f"({pair_key[0]} <-> {pair_key[1]})"
                    )
                elif len(unique_candidates) > 1:
                    ambiguous_match = True
                    tier_matched = (
                        f"Ambiguous endpoint-pair match: "
                        f"{len(unique_candidates)} distinct proposals; "
                        "no cipher assigned"
                    )
                elif all_proposals:
                    # Legacy maps without endpoint metadata cannot prove
                    # which of several proposals belongs to this SA.
                    if len(all_proposals) == 1:
                        only = all_proposals[0]
                        if isinstance(only, dict) and only.get("has_real_proposals"):
                            sa_ike = only
                            tier_matched = (
                                "Tier 3: Single proposal in capture "
                                "(association not independently confirmed)"
                            )
                    else:
                        ambiguous_match = True
                        tier_matched = (
                            "Ambiguous legacy proposal map: endpoint metadata "
                            "missing; no fallback assignment"
                        )
                else:
                    # Compatibility for callers that supply a single direct
                    # endpoint mapping but no proposal list at all.
                    pair_candidate = ike_map.get(pair_key)
                    if isinstance(pair_candidate, dict) and pair_candidate.get("has_real_proposals"):
                        sa_ike = pair_candidate
                        tier_matched = "Tier 2: Direct endpoint mapping (no proposal list)"

            encr_debug = (
                sa_ike.get("encryption_algorithm")
                if sa_ike else ("Ambiguous / Indeterminate" if ambiguous_match else "Pre-established / None")
            )
            dh_debug = sa_ike.get("dh_group") if sa_ike else "Indeterminate"
            print(
                f"[TUNNEL_PARTITIONER] [SA #{sa_idx+1}] SPI: {spi_key} "
                f"({endpoints_str}) -> Resolved via: [{tier_matched}] "
                f"=> Proposal: {encr_debug} / {dh_debug}"
            )

            # 1. Per-SA Cipher & Mode Inference
            try:
                c_infer = infer_ipsec_cipher_and_mode(sa_feats, sa_ike)
            except Exception as c_err:
                print(f"[TUNNEL_PARTITIONER] [ERROR] Cipher inference failed for SA {spi_key}: {c_err}")
                c_infer = {"operating_mode": "Tunnel Mode (IPsec)", "inferred_cipher": "Indeterminate", "integrity_algorithm": "Indeterminate"}

            # 2. Per-SA ETA Application Profiling
            try:
                eta_prof = perform_encrypted_traffic_analysis(sa_feats)
            except Exception as e_err:
                print(f"[TUNNEL_PARTITIONER] [ERROR] ETA profiling failed for SA {spi_key}: {e_err}")
                eta_prof = {"application_category": "Encapsulated Stream", "eta_confidence": None, "avg_packet_size_bytes": 0, "packet_size_std_dev": 0, "burstiness_index": 0, "traffic_pattern": "Standard Flow"}

            # 3. Per-SA Anti-Replay Audit
            seqs = [f["seq_num"] for f in sa_feats if f.get("seq_num") is not None]
            dup_count = len(seqs) - len(set(seqs))
            is_mono = (len(seqs) > 1 and all(seqs[i] < seqs[i+1] for i in range(len(seqs)-1)))
            
            if dup_count > 0:
                replay_status = f"VULNERABLE ({dup_count} duplicate sequences)"
            elif len(seqs) == 1:
                replay_status = f"Single Packet Observed (Seq #{seqs[0]})"
            elif is_mono and len(seqs) > 1:
                replay_status = f"SYNCHRONIZED (Strictly Monotonic 1..{len(seqs)})"
            elif len(seqs) > 1:
                replay_status = f"VALID ({len(seqs)} packets tracked)"
            else:
                replay_status = "N/A"

            # 4. Per-SA PQC Score & Status
            if sa_ike and sa_ike.get("has_real_proposals"):
                encr = sa_ike.get("encryption_algorithm") or ""
                dh = sa_ike.get("dh_group") or ""
                dh_bits_raw = sa_ike.get("dh_bits")
                key_bits_raw = sa_ike.get("key_length")
                prf_name = sa_ike.get("prf_algorithm") or ""

                # Proposal visibility does not prove negotiation or PQC protection.
                # Do not assign a numeric PQC score from classical parameters.
                pqc_score = None
                has_pqc_kem = ("ML-KEM" in dh or "Kyber" in dh)
                has_weak_cipher = (
                    "DES" in encr or "3DES" in encr or "IDEA" in encr
                    or (key_bits_raw is not None and key_bits_raw < 128)
                )
                has_weak_dh = (
                    dh_bits_raw is not None and dh_bits_raw < 2048
                    and not any(x in dh for x in ("Curve", "ECP-")) and not has_pqc_kem
                )

                if has_weak_cipher or has_weak_dh or "MD5" in prf_name or "SHA1" in prf_name:
                    pqc_status = (
                        f"Legacy/weak parameter observed ({encr or 'unknown cipher'}/"
                        f"{dh or 'unknown key exchange'}); PQC protection not established"
                    )
                elif has_pqc_kem:
                    pqc_status = (
                        "PQC-capable KEM name observed in proposal; "
                        "selection and successful hybrid negotiation unconfirmed"
                    )
                else:
                    pqc_status = (
                        "No post-quantum key exchange confirmed; "
                        "PQC status indeterminate from proposal-only evidence"
                    )
            else:
                pqc_score = None
                pqc_status = "Indeterminate (Handshake Not in Capture Window)"

            # An SPI is classified as unrecognized/suspicious probe traffic if:
            # 1. No matching IKE handshake (sa_ike is None), and very few frames (< 5 frames)
            # OR explicitly starts with known synthetic anomaly prefix (e.g. 0xdead)
            is_probe_spi = (sa_ike is None and len(sa_feats) < 5) or str(spi_key).lower().startswith("0xdead")
            sa_status = "Unrecognized ESP SPI / Probe-like Traffic" if is_probe_spi else "Active Established SA"

            sa_audits.append({
                "spi": spi_key,
                "endpoints": endpoints_str,
                "protocol": ("ESP-in-UDP / NAT-T (UDP 4500)" if any(f.get("is_natt") or f.get("src_port") == 4500 or f.get("dst_port") == 4500 for f in sa_feats) else ("Native ESP (Protocol 50)" if any(f.get("esp") for f in sa_feats) else "AH (Protocol 51)")),
                "packet_count": len(sa_feats),
                "traffic_share_pct": round(len(sa_feats) / len(features) * 100, 1),
                "operating_mode": c_infer.get("operating_mode"),
                "inferred_cipher": ("Unrecognized ESP SPI / Probe-like Traffic" if is_probe_spi else c_infer.get("inferred_cipher")),
                "integrity_algorithm": ("Indeterminate (No IKE Trace)" if is_probe_spi else c_infer.get("integrity_algorithm")),
                "pqc_score": None if is_probe_spi else pqc_score,
                "pqc_status": ("Unrecognized ESP SPI / Probe-like Traffic" if is_probe_spi else pqc_status),
                "is_suspicious": is_probe_spi,
                "sa_status": sa_status,
                "eta_profile": {
                    "application_category": eta_prof.get("application_category"),
                    "eta_confidence": eta_prof.get("eta_confidence"),
                    "mean_packet_length": eta_prof.get("avg_packet_size_bytes"),
                    "length_std_dev": eta_prof.get("packet_size_std_dev"),
                    "burstiness_index": eta_prof.get("burstiness_index"),
                    "traffic_pattern": eta_prof.get("traffic_pattern")
                },
                "anti_replay": {
                    "status": replay_status,
                    "duplicates": dup_count
                },
                "is_weak": (pqc_score == 0 or (pqc_score is not None and pqc_score <= 20))
            })

        except Exception as sa_general_err:
            print(f"[TUNNEL_PARTITIONER] [CRITICAL ERROR] Unexpected failure on SA #{sa_idx+1} (SPI {spi_key}): {sa_general_err}")
            traceback.print_exc()
            # Graceful fallback for this SA without crashing the partition loop
            sa_audits.append({
                "spi": spi_key,
                "endpoints": "Unknown",
                "protocol": "ESP (Protocol 50)",
                "packet_count": len(sa_feats),
                "traffic_share_pct": round(len(sa_feats) / len(features) * 100, 1),
                "operating_mode": "Indeterminate",
                "inferred_cipher": "Indeterminate",
                "integrity_algorithm": "Indeterminate",
                "pqc_score": None,
                "pqc_status": "Indeterminate (Error in SA processing)",
                "eta_profile": {"application_category": "Encapsulated Stream", "traffic_pattern": "Standard"},
                "anti_replay": {"status": "N/A", "duplicates": 0},
                "is_weak": False
            })

    return sa_audits

