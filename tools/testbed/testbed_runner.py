"""
Comprehensive Automated Testbed Runner for Sender-Receiver Correlation on Real Traffic.
Orchestrates:
- 100-300 node BEP 5 / BEP 44 isolated DHT cluster
- 25 pairs of PQChat clients (50 clients) with Ephemeral Key Hopping
- Polling, Decoy GETs, Delayed PUT, Decoy Slots, Poisson Cover Traffic
- Storing Node direct visibility and VPN variants
- Attackers: Timing correlation, 0-PUT filtering, Intersection (M=1..20), Sybil (fraction f)
- >= 100 runs with deterministic seeds (1000..1099), 95% Confidence Intervals
- Exports MEASURED telemetry CSV and generates publication-quality plots & comparison tables.
"""

import os
import sys
import time
import math
import random
import csv
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .dht_cluster import DhtCluster
from .client import HeadlessPqClient
from .attackers import AttackEvaluator, CorrelationEvaluationResult
from . import ed25519


@dataclass
class PostureConfig:
    name: str
    display_name: str
    polling_jitter_ratio: float = 0.0
    cover_get_ratio: float = 0.0
    put_delay_max_sec: float = 0.0
    decoy_put_slots: int = 0
    poisson_lambda: float = 0.0
    use_populated_decoys: bool = True
    adversary_filters_zero_put: bool = False
    adversary_uses_lookahead: bool = True
    vpn_enabled: bool = False
    sybil_fraction: float = 0.0


@dataclass
class StatMetric:
    mean: float
    ci95_half: float
    std: float
    min_val: float
    max_val: float

    def format_pct(self) -> str:
        return f"{self.mean * 100:5.1f}% ± {self.ci95_half * 100:4.1f}%"


def compute_metric_stats(values: List[float]) -> StatMetric:
    n = len(values)
    if n == 0:
        return StatMetric(0.0, 0.0, 0.0, 0.0, 0.0)
    mean_v = float(np.mean(values))
    std_v = float(np.std(values, ddof=1)) if n > 1 else 0.0
    half_ci = 1.96 * std_v / math.sqrt(n) if n > 1 else 0.0
    return StatMetric(
        mean=mean_v,
        ci95_half=half_ci,
        std=std_v,
        min_val=float(np.min(values)),
        max_val=float(np.max(values))
    )


class TestbedController:
    """Controls and executes end-to-end testbed trials."""

    def __init__(
        self,
        num_pairs: int = 25,
        num_cluster_nodes: int = 150,
        msgs_per_pair: int = 4,
        sim_duration_sec: float = 180.0,
        base_poll_sec: float = 10.0
    ):
        self.num_pairs = num_pairs
        self.num_cluster_nodes = num_cluster_nodes
        self.msgs_per_pair = msgs_per_pair
        self.sim_duration_sec = sim_duration_sec
        self.base_poll_sec = base_poll_sec
        self.baseline_guessing = 1.0 / num_pairs

    def run_single_trial(
        self,
        posture: PostureConfig,
        seed: int
    ) -> CorrelationEvaluationResult:
        """Executes a single testbed trial on real KRPC packets."""
        rng = random.Random(seed)

        # 1. Initialize isolated 100-300 node cluster
        cluster = DhtCluster(
            num_nodes=self.num_cluster_nodes,
            sybil_fraction=posture.sybil_fraction,
            base_port=30000,
            seed=seed
        )

        # 2. Setup Clients (Alice_0..24, Bob_0..24)
        pair_mappings = {}
        pair_identities = {}
        all_receiver_ips = []
        client_to_physical = {}

        alices: List[HeadlessPqClient] = []
        bobs: List[HeadlessPqClient] = []

        vpn_pool = [f"198.51.100.{10 + (i % 5)}" for i in range(self.num_pairs * 2)]

        for p in range(self.num_pairs):
            alice_ip = f"192.168.1.{100 + p}"
            bob_ip = f"192.168.2.{100 + p}"
            all_receiver_ips.append(bob_ip)

            pair_mappings[alice_ip] = bob_ip
            pair_identities[alice_ip] = p
            pair_identities[bob_ip] = p

            # Shared initial 64-byte KDF chain key per pair
            chain_seed = f"chain_pair_{p}_{seed}".encode("utf-8")
            init_chain_key = hashlib.sha512(chain_seed).digest()

            alice_vpn = vpn_pool[p] if posture.vpn_enabled else None
            bob_vpn = vpn_pool[self.num_pairs + p] if posture.vpn_enabled else None

            if posture.vpn_enabled:
                client_to_physical[alice_vpn] = alice_ip
                client_to_physical[bob_vpn] = bob_ip
                pair_identities[alice_vpn] = p
                pair_identities[bob_vpn] = p
                pair_mappings[alice_vpn] = bob_vpn

            alice = HeadlessPqClient(
                client_id=f"Alice_{p}",
                virtual_ip=alice_ip,
                cluster=cluster,
                init_chain_key=init_chain_key,
                rng=rng,
                vpn_gateway_ip=alice_vpn
            )
            bob = HeadlessPqClient(
                client_id=f"Bob_{p}",
                virtual_ip=bob_ip,
                cluster=cluster,
                init_chain_key=init_chain_key,
                rng=rng,
                vpn_gateway_ip=bob_vpn
            )
            alices.append(alice)
            bobs.append(bob)

        # 3. Simulate Traffic Events Over Time
        # Schedule message emission times per pair
        now_ms = 1_000_000  # Virtual clock starting offset

        # Generate message emission schedule
        all_events = []  # (timestamp_ms, type, client_obj, extra_args)

        for p in range(self.num_pairs):
            avg_interval = self.sim_duration_sec / self.msgs_per_pair
            t = 0.0
            while t < self.sim_duration_sec:
                t += rng.expovariate(1.0 / avg_interval)
                if t < self.sim_duration_sec:
                    all_events.append((int((t * 1000) + now_ms), "SEND_MSG", alices[p], p))

        # Schedule Polling events for Bobs
        t_poll = 0.0
        while t_poll < self.sim_duration_sec:
            for p in range(self.num_pairs):
                # Apply polling jitter if configured
                j_ratio = posture.polling_jitter_ratio
                eff_interval = self.base_poll_sec * (1.0 + rng.uniform(-j_ratio, j_ratio)) if j_ratio > 0 else self.base_poll_sec
                poll_t = t_poll + eff_interval
                if poll_t < self.sim_duration_sec:
                    all_events.append((int((poll_t * 1000) + now_ms), "POLL", bobs[p], p))
            t_poll += self.base_poll_sec

        # Schedule Poisson Cover Traffic PUTs
        if posture.poisson_lambda > 0:
            for client in alices + bobs:
                t_cov = 0.0
                while t_cov < self.sim_duration_sec:
                    t_cov += rng.expovariate(posture.poisson_lambda)
                    if t_cov < self.sim_duration_sec:
                        all_events.append((int((t_cov * 1000) + now_ms), "POISSON_PUT", client, None))

        # Sort all scheduled events by timestamp
        all_events.sort(key=lambda ev: ev[0])

        # 4. Execute Real KRPC Packets
        for ev_time, ev_type, client, pair_idx in all_events:
            if ev_type == "SEND_MSG":
                # Alice derives next ephemeral slot and publishes 900B BEP 44 record
                alice = client
                msg_k, pk, tgt, sk = alice.ratchet.derive_slot(alice.counter_out)
                alice.counter_out += 1

                # Delayed PUT hold
                put_delay_ms = int(rng.uniform(0, posture.put_delay_max_sec * 1000)) if posture.put_delay_max_sec > 0 else 0
                actual_put_time = ev_time + put_delay_ms

                # Exact 900-byte frame filled with CSPRNG noise per BinaryFrameCodec specification
                payload_900b = bytes(rng.getrandbits(8) for _ in range(900))

                alice.send_put(
                    target=tgt,
                    payload_900b=payload_900b,
                    pk=pk,
                    sk=sk,
                    seq=alice.counter_out,
                    timestamp_ms=actual_put_time
                )

                # Decoy PUT slots published alongside real message
                for _ in range(posture.decoy_put_slots):
                    d_seed = bytes(rng.getrandbits(8) for _ in range(32))
                    d_pk, d_sk = ed25519.generate_keypair(d_seed)
                    d_tgt = ed25519.compute_target(d_pk)
                    d_payload = bytes(rng.getrandbits(8) for _ in range(900))
                    alice.send_put(
                        target=d_tgt,
                        payload_900b=d_payload,
                        pk=d_pk,
                        sk=d_sk,
                        seq=0,
                        timestamp_ms=actual_put_time
                    )

            elif ev_type == "POLL":
                bob = client
                # Bob executes lookahead polling (W=5 slots: n..n+4)
                bob.execute_lookahead_poll(timestamp_ms=ev_time, window_size=4)

                # Decoy GETs
                if posture.cover_get_ratio > 0:
                    decoy_count = int(posture.cover_get_ratio)
                    bob.execute_decoy_gets(
                        count=decoy_count,
                        timestamp_ms=ev_time,
                        use_populated_pool=posture.use_populated_decoys
                    )

            elif ev_type == "POISSON_PUT":
                client.execute_poisson_cover_put(timestamp_ms=ev_time)

        # 5. Evaluate Logged Telemetry with Adversary Suite
        evaluator = AttackEvaluator(
            num_pairs=self.num_pairs,
            baseline_guessing=self.baseline_guessing
        )
        log_entries = cluster.logger.get_entries()

        result = evaluator.evaluate_trace(
            log_entries=log_entries,
            pair_mappings=pair_mappings,
            pair_identities=pair_identities,
            all_receiver_ips=all_receiver_ips,
            window_sec=30.0,
            filter_zero_put=posture.adversary_filters_zero_put,
            use_lookahead=posture.adversary_uses_lookahead,
            vpn_active=posture.vpn_enabled,
            client_to_physical=client_to_physical if posture.vpn_enabled else None
        )
        return result


def run_full_testbed_suite(
    num_runs: int = 100,
    num_nodes: int = 150,
    sim_duration_sec: float = 180.0,
    msgs_per_pair: int = 4
) -> Dict:
    """
    Executes the full testbed evaluation across:
    1. Defense Postures (Baseline, Jitter, Decoys, Delayed PUT, Full Defense)
    2. Storing Node Direct Observer vs Network Observer
    3. VPN Variant
    4. 0-PUT Stateful Filtering
    5. Multi-Message Intersection Attack (M=1..20)
    6. Sybil Fraction Sweeps (f=0..0.5)
    """
    print("=" * 80)
    print("PQChat.DHT - Sender-Receiver Correlation Testbed on REAL Traffic (BEP 5 / BEP 44)")
    print(f"Cluster: {num_nodes} Nodes | Communicating Pairs: 25 (50 clients) | Baseline: 4.0%")
    print(f"Repetitions: {num_runs} Monte Carlo Runs (Seeds 1000..{1000 + num_runs - 1})")
    print("=" * 80)

    controller = TestbedController(
        num_pairs=25,
        num_cluster_nodes=num_nodes,
        msgs_per_pair=msgs_per_pair,
        sim_duration_sec=sim_duration_sec,
        base_poll_sec=10.0
    )

    # Define Defense Postures
    postures = [
        PostureConfig(
            name="BASELINE",
            display_name="Baseline (No Defense)",
            polling_jitter_ratio=0.0,
            cover_get_ratio=0.0,
            put_delay_max_sec=0.0,
            decoy_put_slots=0,
            poisson_lambda=0.0
        ),
        PostureConfig(
            name="JITTER",
            display_name="+ Polling Jitter (±30%)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=0.0,
            put_delay_max_sec=0.0,
            decoy_put_slots=0,
            poisson_lambda=0.0
        ),
        PostureConfig(
            name="DECOYS",
            display_name="+ Decoy GETs (Ratio 1.5)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=0.0,
            decoy_put_slots=0,
            poisson_lambda=0.0,
            use_populated_decoys=True
        ),
        PostureConfig(
            name="DELAYED_PUT",
            display_name="+ Delayed PUT & Decoy Slots",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=0.0,
            use_populated_decoys=True
        ),
        PostureConfig(
            name="FULL_DEFENSE",
            display_name="Full Defense (+ Poisson 1/480s)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=1.0 / 480.0,
            use_populated_decoys=True
        ),
        # Storing Node direct visibility analysis
        PostureConfig(
            name="STORING_NODE_NO_DEFENSE",
            display_name="Storing Node (No Defense)",
            polling_jitter_ratio=0.0,
            cover_get_ratio=0.0,
            put_delay_max_sec=0.0,
            decoy_put_slots=0,
            poisson_lambda=0.0,
            sybil_fraction=0.0  # Storage node observed
        ),
        PostureConfig(
            name="STORING_NODE_FULL_DEFENSE",
            display_name="Storing Node (Full Defense)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=1.0 / 480.0,
            use_populated_decoys=True
        ),
        # VPN variant
        PostureConfig(
            name="VPN_FULL_DEFENSE",
            display_name="Full Defense + VPN/Tor",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=1.0 / 480.0,
            use_populated_decoys=True,
            vpn_enabled=True
        ),
        # 0-PUT filtering on synthetic decoys vs populated decoys
        PostureConfig(
            name="0PUT_SYNTHETIC",
            display_name="Synthetic Decoys (0-PUT Filtered)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=0.0,
            decoy_put_slots=0,
            poisson_lambda=0.0,
            use_populated_decoys=False,
            adversary_filters_zero_put=True
        ),
        PostureConfig(
            name="0PUT_POPULATED",
            display_name="Populated + Poisson (0-PUT Resilient)",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=1.0 / 480.0,
            use_populated_decoys=True,
            adversary_filters_zero_put=True
        ),
    ]

    all_results = {}
    csv_rows = []

    for posture in postures:
        print(f"\nEvaluating: {posture.display_name} ...", flush=True)
        top1_list = []
        entropy_list = []
        candidates_list = []
        multi_msg_runs = {M: [] for M in [1, 2, 5, 10, 20]}
        delta_t_accum: Dict[float, List[float]] = {}

        t_start = time.time()
        for i in range(num_runs):
            seed = 1000 + i
            res = controller.run_single_trial(posture, seed)
            top1_list.append(res.top1_accuracy)
            entropy_list.append(res.shannon_entropy_ratio)
            candidates_list.append(res.candidate_set_size)

            for M, val in res.multi_msg_accuracy.items():
                multi_msg_runs[M].append(val)

            for dt, val in res.delta_t_accuracy.items():
                delta_t_accum.setdefault(dt, []).append(val)

            # Record telemetry CSV row (MEASURED)
            csv_rows.append({
                "trial_id": i + 1,
                "seed": seed,
                "data_source": "MEASURED",
                "posture": posture.name,
                "display_name": posture.display_name,
                "top1_accuracy": res.top1_accuracy,
                "entropy_ratio": res.shannon_entropy_ratio,
                "candidates": res.candidate_set_size,
                "m1": res.multi_msg_accuracy.get(1, 0.0),
                "m2": res.multi_msg_accuracy.get(2, 0.0),
                "m5": res.multi_msg_accuracy.get(5, 0.0),
                "m10": res.multi_msg_accuracy.get(10, 0.0),
                "m20": res.multi_msg_accuracy.get(20, 0.0),
                "vpn_enabled": posture.vpn_enabled
            })

        t_elapsed = time.time() - t_start
        stat_top1 = compute_metric_stats(top1_list)
        stat_entropy = compute_metric_stats(entropy_list)
        stat_candidates = compute_metric_stats(candidates_list)
        stat_multi = {M: compute_metric_stats(multi_msg_runs[M]) for M in [1, 2, 5, 10, 20]}
        delta_t_mean = {dt: float(np.mean(vals)) for dt, vals in delta_t_accum.items()}

        all_results[posture.name] = {
            "posture": posture,
            "top1": stat_top1,
            "entropy": stat_entropy,
            "candidates": stat_candidates,
            "multi_msg": stat_multi,
            "delta_t": delta_t_mean,
            "time_sec": t_elapsed
        }

        print(f"  -> Top-1 Accuracy: {stat_top1.format_pct()} (Advantage: +{(stat_top1.mean - controller.baseline_guessing)*100:4.1f}%)")
        print(f"  -> Entropy Ratio: {stat_entropy.format_pct()} | Avg Candidates: {stat_candidates.mean:4.1f}")
        print(f"  -> Elapsed: {t_elapsed:.2f}s")

    # Sybil Fraction Sweep Evaluation
    print("\n--- Evaluating Sybil Neighborhood Sweep (f = 0.0 .. 0.5) ---")
    sybil_fractions = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]
    sybil_results = {}

    for f_val in sybil_fractions:
        p_sybil = PostureConfig(
            name=f"SYBIL_{int(f_val*100)}",
            display_name=f"Sybil f={f_val*100:4.1f}%",
            polling_jitter_ratio=0.3,
            cover_get_ratio=1.5,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            poisson_lambda=1.0 / 480.0,
            use_populated_decoys=True,
            sybil_fraction=f_val
        )
        syb_acc = []
        for i in range(num_runs):
            res = controller.run_single_trial(p_sybil, seed=1000 + i)
            syb_acc.append(res.top1_accuracy)
        stat_syb = compute_metric_stats(syb_acc)
        sybil_results[f_val] = stat_syb
        p_compromise_theory = (1.0 - (1.0 - f_val) ** 8) * 100 if f_val > 0 else 0.0
        print(f"  f = {f_val*100:4.1f}% (Theory P_comp = {p_compromise_theory:4.1f}%) -> Top-1: {stat_syb.format_pct()}")

    # 6. Save Telemetry CSV
    output_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(output_dir, "metrics_testbed_correlation.csv")
    docs_csv_path = os.path.abspath(os.path.join(output_dir, "..", "..", "docs", "metrics_testbed_correlation.csv"))

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "trial_id", "seed", "data_source", "posture", "display_name",
            "top1_accuracy", "entropy_ratio", "candidates",
            "m1", "m2", "m5", "m10", "m20", "vpn_enabled"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    try:
        with open(docs_csv_path, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "trial_id", "seed", "data_source", "posture", "display_name",
                "top1_accuracy", "entropy_ratio", "candidates",
                "m1", "m2", "m5", "m10", "m20", "vpn_enabled"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
    except Exception:
        pass

    print(f"\n[Exported MEASURED Telemetry CSV]")
    print(f" -> {csv_path}")

    # 7. Generate Visualizations
    generate_testbed_plots(all_results, sybil_results, controller.baseline_guessing)

    return {
        "postures": all_results,
        "sybil": sybil_results,
        "baseline": controller.baseline_guessing
    }


def generate_testbed_plots(all_results: Dict, sybil_results: Dict, baseline_guessing: float):
    """Generates 4-panel publication-quality visualization comparing MEASURED results."""
    output_dir = os.path.dirname(os.path.abspath(__file__))
    docs_dir = os.path.abspath(os.path.join(output_dir, "..", "..", "docs"))
    os.makedirs(docs_dir, exist_ok=True)

    fig_path_tools = os.path.join(output_dir, "testbed_correlation_measured.png")
    fig_path_docs = os.path.join(docs_dir, "testbed_correlation_measured.png")

    fig, axs = plt.subplots(2, 2, figsize=(16, 12), dpi=300)
    ((ax_post, ax_dt), (ax_inter, ax_syb)) = axs

    baseline_pct = baseline_guessing * 100

    # Panel A (Top-Left): Defense Posture Comparison (MEASURED with 95% CI)
    primary_keys = ["BASELINE", "JITTER", "DECOYS", "DELAYED_PUT", "FULL_DEFENSE", "VPN_FULL_DEFENSE"]
    labels = [
        "Baseline\n(No Defense)",
        "+ Jitter\n(±30%)",
        "+ Decoys\n(Ratio 1.5)",
        "+ Delayed PUT\n& Decoy Slots",
        "Full Defense\n(+ Poisson)",
        "Full Defense\n+ VPN/Tor"
    ]
    means = [all_results[k]["top1"].mean * 100 for k in primary_keys]
    errs = [all_results[k]["top1"].ci95_half * 100 for k in primary_keys]
    entropies = [all_results[k]["entropy"].mean * 100 for k in primary_keys]

    x = np.arange(len(labels))
    width = 0.35

    ax_post.bar(x - width/2, means, width, yerr=errs, capsize=4, label="Adversary Top-1 Accuracy (%) [MEASURED]", color="#e53935", alpha=0.88)
    ax_post.bar(x + width/2, entropies, width, label="Degree of Anonymity (Entropy %) [MEASURED]", color="#1e88e5", alpha=0.88)
    ax_post.axhline(y=baseline_pct, color="#333333", linestyle="--", linewidth=1.5, label=f"Random Baseline 1/N ({baseline_pct:.1f}%)")

    ax_post.set_xticks(x)
    ax_post.set_xticklabels(labels, fontsize=8.5)
    ax_post.set_ylabel("Metric Score (%)", fontsize=9.5, fontweight="bold")
    ax_post.set_title("A. Defense Postures on Real Traffic (MEASURED, 95% CI)", fontsize=11, fontweight="bold")
    ax_post.set_ylim(0, 115)
    ax_post.legend(loc="upper right", fontsize=8.2, framealpha=0.92)
    ax_post.grid(True, linestyle="--", alpha=0.5)

    # Panel B (Top-Right): Timing Correlation Success vs Delta_t (with Lookahead)
    colors = {"BASELINE": "#e53935", "DECOYS": "#fb8c00", "DELAYED_PUT": "#8e24aa", "FULL_DEFENSE": "#2e7d32"}
    for k in ["BASELINE", "DECOYS", "DELAYED_PUT", "FULL_DEFENSE"]:
        dt_dict = all_results[k]["delta_t"]
        if dt_dict:
            dts = sorted(dt_dict.keys())
            probs = [dt_dict[t] * 100 for t in dts]
            ax_dt.plot(dts, probs, marker="o", markersize=4.5, linewidth=2.0, color=colors[k], label=all_results[k]["posture"].display_name)

    ax_dt.axvline(x=0.0, color="#333333", linestyle=":", alpha=0.8, label="PUT Emission (t_PUT)")
    ax_dt.axhline(y=baseline_pct, color="#555555", linestyle="--", label=f"Random Baseline 1/N ({baseline_pct:.1f}%)")
    ax_dt.set_xlabel(r"Arrival Time Gap $\Delta t = t_{\mathrm{GET}} - t_{\mathrm{PUT}}$ (sec) [Lookahead: $\Delta t < 0$ | Post-PUT: $\Delta t > 0$]", fontsize=9.5, fontweight="bold")
    ax_dt.set_ylabel("Correlation Success (%)", fontsize=9.5, fontweight="bold")
    ax_dt.set_title(r"B. Timing Correlation vs $\Delta t$ on Real Packets [MEASURED]", fontsize=11, fontweight="bold")
    ax_dt.set_ylim(-5, 105)
    ax_dt.legend(loc="upper right", fontsize=8.0, framealpha=0.92)
    ax_dt.grid(True, linestyle="--", alpha=0.5)

    # Panel C (Bottom-Left): Multi-Message Statistical Disclosure (Intersection Attack M = 1..20)
    m_ticks = [1, 2, 5, 10, 20]
    base_m = [all_results["BASELINE"]["multi_msg"][M].mean * 100 for M in m_ticks]
    decoy_m = [all_results["DECOYS"]["multi_msg"][M].mean * 100 for M in m_ticks]
    full_m = [all_results["FULL_DEFENSE"]["multi_msg"][M].mean * 100 for M in m_ticks]

    ax_inter.plot(m_ticks, base_m, marker="s", linewidth=2.4, color="#e53935", label="Baseline (Immediate Disclosure) [MEASURED]")
    ax_inter.plot(m_ticks, decoy_m, marker="^", linewidth=2.2, color="#fb8c00", label="Decoys Only (Slow Intersection) [MEASURED]")
    ax_inter.plot(m_ticks, full_m, marker="o", linewidth=2.5, color="#2e7d32", label="Full Defense (+ Poisson Cover) [MEASURED]")
    ax_inter.axhline(y=baseline_pct, color="#555555", linestyle="--", label=f"Random Baseline 1/N ({baseline_pct:.1f}%)")

    ax_inter.set_xticks(m_ticks)
    ax_inter.set_xlabel(r"Number of Consecutive Messages Observed ($M$)", fontsize=9.5, fontweight="bold")
    ax_inter.set_ylabel("Adversary Cumulative Top-1 Accuracy (%)", fontsize=9.5, fontweight="bold")
    ax_inter.set_title(r"C. Statistical Disclosure / Intersection Attack vs $M$ [MEASURED]", fontsize=11, fontweight="bold")
    ax_inter.set_ylim(-5, 105)
    ax_inter.legend(loc="center right", fontsize=8.2, framealpha=0.92)
    ax_inter.grid(True, linestyle="--", alpha=0.5)

    # Panel D (Bottom-Right): Sybil Compromise vs Theoretical K=8
    f_vals = sorted(sybil_results.keys())
    syb_measured = [sybil_results[f].mean * 100 for f in f_vals]
    syb_err = [sybil_results[f].ci95_half * 100 for f in f_vals]
    syb_theory = [(1.0 - (1.0 - f) ** 8) * 100 for f in f_vals]

    ax_syb.plot([f * 100 for f in f_vals], syb_theory, marker="x", linestyle=":", color="#333333", linewidth=1.8, label="Theory P(Compromise) = 1-(1-f)^K")
    ax_syb.errorbar([f * 100 for f in f_vals], syb_measured, yerr=syb_err, marker="D", linewidth=2.2, color="#d32f2f", capsize=4, label="Adversary Top-1 Accuracy [MEASURED]")
    ax_syb.axhline(y=baseline_pct, color="#555555", linestyle="--", label=f"Random Baseline 1/N ({baseline_pct:.1f}%)")

    ax_syb.set_xlabel(r"Adversary Sybil Fraction in DHT $f$ (%)", fontsize=9.5, fontweight="bold")
    ax_syb.set_ylabel("Metric Score (%)", fontsize=9.5, fontweight="bold")
    ax_syb.set_title("D. Sybil Resistance in 150-Node DHT Swarm (K=8) [MEASURED]", fontsize=11, fontweight="bold")
    ax_syb.set_ylim(-5, 105)
    ax_syb.legend(loc="upper left", fontsize=8.2, framealpha=0.92)
    ax_syb.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(fig_path_tools, dpi=300)
    plt.savefig(fig_path_docs, dpi=300)
    plt.close()

    print(f"\n[Generated Publication-Quality Visualizations]")
    print(f" -> {fig_path_tools}")
    print(f" -> {fig_path_docs}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PQChat.DHT Real Traffic Correlation Testbed")
    parser.add_argument("--runs", type=int, default=100, help="Number of Monte Carlo repetitions (default: 100)")
    parser.add_argument("--nodes", type=int, default=150, help="Number of DHT nodes in cluster (default: 150)")
    parser.add_argument("--duration", type=float, default=180.0, help="Simulation duration in seconds (default: 180)")
    parser.add_argument("--msgs", type=int, default=4, help="Messages per pair (default: 4)")
    parser.add_argument("--quick", action="store_true", help="Quick run mode for smoke test (3 runs, 50 nodes)")
    args = parser.parse_args()

    if args.quick:
        r = 3
        n = 50
        d = 60.0
        m = 2
    else:
        r = args.runs
        n = args.nodes
        d = args.duration
        m = args.msgs

    run_full_testbed_suite(num_runs=r, num_nodes=n, sim_duration_sec=d, msgs_per_pair=m)
