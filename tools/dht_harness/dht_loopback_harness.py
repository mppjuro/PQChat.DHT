#!/usr/bin/env python3
"""
Automated Measurement Harness for BitTorrent DHT Loopback & Retention Telemetry.

Evaluates:
1. PUT -> GET latency percentiles (p50, p90, p99) and Delivery Success Rate.
2. Data retention across 5min, 1h, 2h, 6h, 12h, and 24h horizons (comparing with vs without republish, N >= 300).
3. Network environment profiles:
   - Stable Wi-Fi
   - Mobile LTE
   - Restrictive NAT / CGNAT
4. Strict separation between MEASURED (live BitTorrent Mainline DHT) and SIMULATED (calibrated model) telemetry.
5. Removal of hardcoded artificial floors (e.g. max(0.85)).
6. Safe CSV export: Zero message content, zero cryptographic keys/seeds.
7. Visualizations & summary report generation comparing MEASURED vs SIMULATED data.
"""

import os
import sys
import csv
import time
import math
import random
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


# Payload size strictly matches BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES (900 bytes)
MAX_FRAME_PAYLOAD_BYTES = 900
BEP44_MAX_BENCODE_VALUE_BYTES = 1000


@dataclass
class NetworkProfile:
    name: str
    display_name: str
    base_rtt_ms: float
    jitter_ms: float
    packet_loss_rate: float
    nat_timeout_sec: int
    retransmit_prob: float
    rrc_tail_promotion_prob: float


PROFILES = {
    "WIFI": NetworkProfile(
        name="WIFI",
        display_name="Stable Wi-Fi",
        base_rtt_ms=28.0,
        jitter_ms=12.0,
        packet_loss_rate=0.008,
        nat_timeout_sec=300,
        retransmit_prob=0.02,
        rrc_tail_promotion_prob=0.0
    ),
    "LTE": NetworkProfile(
        name="LTE",
        display_name="Mobile LTE",
        base_rtt_ms=68.0,
        jitter_ms=35.0,
        packet_loss_rate=0.032,
        nat_timeout_sec=90,
        retransmit_prob=0.07,
        rrc_tail_promotion_prob=0.14
    ),
    "RESTRICTIVE_NAT": NetworkProfile(
        name="RESTRICTIVE_NAT",
        display_name="Restrictive NAT/CGNAT",
        base_rtt_ms=115.0,
        jitter_ms=65.0,
        packet_loss_rate=0.095,
        nat_timeout_sec=30,
        retransmit_prob=0.18,
        rrc_tail_promotion_prob=0.0
    ),
}


@dataclass
class TelemetryRecord:
    measurement_id: int
    timestamp_epoch_ms: int
    data_source: str  # "MEASURED" or "SIMULATED"
    network_environment: str
    operation: str
    rtt_put_ms: float
    rtt_get_ms: float
    rtt_total_ms: float
    delivery_success: bool
    retransmissions: int
    retention_hours: float
    republish_enabled: bool
    nodes_queried: int
    nodes_responded: int
    error_code: str


def simulate_network_hop(profile: NetworkProfile, is_put: bool) -> Tuple[float, bool, int, int, int]:
    """
    Simulates a KRPC UDP hop (PUT or GET) under the given network profile.
    Returns: (rtt_ms, success, retransmissions, nodes_contacted, nodes_responded)
    """
    retransmissions = 0
    success = True

    # Base RTT + Jitter
    jitter = random.uniform(-profile.jitter_ms, profile.jitter_ms)
    total_latency = max(5.0, profile.base_rtt_ms + jitter)

    # Restrictive NAT binding expiry or CGNAT state stall
    if profile.name == "RESTRICTIVE_NAT" and random.random() < 0.22:
        total_latency += random.uniform(150.0, 450.0)

    # LTE RRC channel promotion penalty
    if profile.name == "LTE" and random.random() < profile.rrc_tail_promotion_prob:
        total_latency += random.uniform(110.0, 280.0)

    # Packet loss and retransmission check
    if random.random() < profile.packet_loss_rate:
        retransmissions += 1
        total_latency += max(400.0, profile.base_rtt_ms * 4.0)  # KRPC timeout and retransmit
        if random.random() < (profile.packet_loss_rate * 1.5):
            success = False

    nodes_contacted = 16 if is_put else 8
    if success:
        nodes_responded = random.randint(3, 8) if is_put else random.randint(1, 4)
    else:
        nodes_responded = 0

    return total_latency, success, retransmissions, nodes_contacted, nodes_responded


def run_loopback_trial(measurement_id: int, profile: NetworkProfile, data_source: str = "SIMULATED") -> TelemetryRecord:
    """Executes a single loopback trial measuring PUT -> GET latency and delivery success."""
    t_now = int(time.time() * 1000)

    put_rtt, put_ok, put_retrans, nodes_q, nodes_r = simulate_network_hop(profile, is_put=True)
    retransmissions = put_retrans
    err_code = "NONE"

    if put_ok:
        get_rtt, get_ok, get_retrans, _, get_nodes_r = simulate_network_hop(profile, is_put=False)
        retransmissions += get_retrans
        nodes_r = max(nodes_r, get_nodes_r)
        if not get_ok:
            err_code = "GET_TIMEOUT"
        delivery_success = get_ok
    else:
        get_rtt = 0.0
        delivery_success = False
        err_code = "PUT_TIMEOUT"

    total_rtt = (put_rtt + get_rtt)

    return TelemetryRecord(
        measurement_id=measurement_id,
        timestamp_epoch_ms=t_now,
        data_source=data_source,
        network_environment=profile.name,
        operation="LOOPBACK_PUT_GET",
        rtt_put_ms=round(put_rtt, 2),
        rtt_get_ms=round(get_rtt, 2),
        rtt_total_ms=round(total_rtt, 2),
        delivery_success=delivery_success,
        retransmissions=retransmissions,
        retention_hours=0.0,
        republish_enabled=False,
        nodes_queried=nodes_q,
        nodes_responded=nodes_r,
        error_code=err_code
    )


def simulate_retention_probe(
    measurement_id: int,
    profile: NetworkProfile,
    hours: float,
    republish_enabled: bool,
    data_source: str = "SIMULATED"
) -> TelemetryRecord:
    """
    Simulates checking record retention in DHT after `hours` from initial publication.
    Models Kademlia node churn (half-life ~ 50 min) and cache eviction without artificial floor clamping.
    """
    t_now = int(time.time() * 1000)
    k_replication = 8
    churn_half_life_hours = 0.833  # 50 minutes
    lambda_churn = math.log(2.0) / churn_half_life_hours

    if not republish_enabled:
        # Without republish: exponential node survival decay
        p_node_survives = math.exp(-lambda_churn * hours)
        if hours <= (5.0 / 60.0):
            cache_eviction = 0.99
        elif hours <= 1.0:
            cache_eviction = 0.96
        elif hours <= 2.0:
            cache_eviction = 0.88
        elif hours <= 6.0:
            cache_eviction = 0.55
        elif hours <= 12.0:
            cache_eviction = 0.28
        else:
            cache_eviction = 0.12
        p_item_survives = 1.0 - math.pow(1.0 - (p_node_survives * cache_eviction), k_replication)
        retrieval_discount = 1.0 - (profile.packet_loss_rate * 1.5)
        survival_prob = min(1.0, max(0.0, p_item_survives * retrieval_discount))
    else:
        # With active republish: refreshed every 1.5 hours to current closest nodes
        republish_interval = 1.5
        cycles = int(hours / republish_interval)
        p_cycle_ok = 1.0 - (profile.packet_loss_rate * 2.0)
        base_survival = math.pow(p_cycle_ok, max(1, cycles) * 0.15)
        # REMOVED max(0.85): True calculated survival probability
        survival_prob = min(1.0, max(0.0, base_survival * (1.0 - (profile.packet_loss_rate * 0.5))))

    survived = (random.random() < survival_prob)
    get_rtt, _, _, _, nodes_r = simulate_network_hop(profile, is_put=False)

    return TelemetryRecord(
        measurement_id=measurement_id,
        timestamp_epoch_ms=t_now,
        data_source=data_source,
        network_environment=profile.name,
        operation="RETENTION_PROBE",
        rtt_put_ms=0.0,
        rtt_get_ms=round(get_rtt, 2) if survived else 0.0,
        rtt_total_ms=round(get_rtt, 2) if survived else 0.0,
        delivery_success=survived,
        retransmissions=0 if survived else 1,
        retention_hours=hours,
        republish_enabled=republish_enabled,
        nodes_queried=16,
        nodes_responded=nodes_r if survived else 0,
        error_code="NONE" if survived else "RETENTION_EXPIRED"
    )


def export_csv(records: List[TelemetryRecord], file_path: str):
    """Exports records to RFC 4180 CSV without any keys, hashes, or payload contents."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "measurement_id",
            "timestamp_epoch_ms",
            "data_source",
            "network_environment",
            "operation",
            "rtt_put_ms",
            "rtt_get_ms",
            "rtt_total_ms",
            "delivery_success",
            "retransmissions",
            "retention_hours",
            "republish_enabled",
            "nodes_queried",
            "nodes_responded",
            "error_code"
        ])
        for r in records:
            writer.writerow([
                r.measurement_id,
                r.timestamp_epoch_ms,
                r.data_source,
                r.network_environment,
                r.operation,
                f"{r.rtt_put_ms:.2f}",
                f"{r.rtt_get_ms:.2f}",
                f"{r.rtt_total_ms:.2f}",
                str(r.delivery_success),
                r.retransmissions,
                f"{r.retention_hours:.3f}",
                str(r.republish_enabled),
                r.nodes_queried,
                r.nodes_responded,
                r.error_code
            ])


def load_measured_records(
    measured_csv_path: str
) -> List[TelemetryRecord]:
    """
    Loads empirical records strictly from docs/metrics_dht_loopback_measured.csv.
    Does not synthetically generate or fabricate records. Missing file or empty data returns an empty list.
    """
    records: List[TelemetryRecord] = []
    if os.path.exists(measured_csv_path) and os.path.getsize(measured_csv_path) > 100:
        with open(measured_csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("data_source") == "MEASURED" and row.get("operation") == "LOOPBACK_PUT_GET":
                    records.append(TelemetryRecord(
                        measurement_id=int(row["measurement_id"]),
                        timestamp_epoch_ms=int(row["timestamp_epoch_ms"]),
                        data_source=row["data_source"],
                        network_environment=row["network_environment"],
                        operation=row["operation"],
                        rtt_put_ms=float(row["rtt_put_ms"]),
                        rtt_get_ms=float(row["rtt_get_ms"]),
                        rtt_total_ms=float(row["rtt_total_ms"]),
                        delivery_success=(row["delivery_success"].strip().lower() == "true"),
                        retransmissions=int(row["retransmissions"]),
                        retention_hours=float(row["retention_hours"]),
                        republish_enabled=(row["republish_enabled"].strip().lower() == "true"),
                        nodes_queried=int(row["nodes_queried"]),
                        nodes_responded=int(row["nodes_responded"]),
                        error_code=row.get("error_code", "NONE")
                    ))
        if records:
            print(f"[Measured Data] Loaded {len(records)} existing MEASURED records from {measured_csv_path}")
            return records

    print(f"[Measured Data] No valid MEASURED records found in {measured_csv_path}. Returning empty list.")
    return []


def compute_env_stats(records_env: List[TelemetryRecord], profile: NetworkProfile, data_source: str) -> Dict:
    successful = [r for r in records_env if r.delivery_success]
    success_rate = (len(successful) / len(records_env)) * 100.0 if records_env else 0.0

    put_rtts = [r.rtt_put_ms for r in records_env] if records_env else [0.0]
    get_rtts = [r.rtt_get_ms for r in successful] if successful else [0.0]
    tot_rtts = [r.rtt_total_ms for r in successful] if successful else [0.0]
    avg_retrans = np.mean([r.retransmissions for r in records_env]) if records_env else 0.0

    return {
        "profile": profile,
        "data_source": data_source,
        "trials": len(records_env),
        "success_rate": success_rate,
        "put_p50": np.percentile(put_rtts, 50),
        "put_p90": np.percentile(put_rtts, 90),
        "put_p99": np.percentile(put_rtts, 99),
        "get_p50": np.percentile(get_rtts, 50),
        "get_p90": np.percentile(get_rtts, 90),
        "get_p99": np.percentile(get_rtts, 99),
        "tot_p50": np.percentile(tot_rtts, 50),
        "tot_p90": np.percentile(tot_rtts, 90),
        "tot_p99": np.percentile(tot_rtts, 99),
        "avg_retrans": avg_retrans,
        "tot_rtts": tot_rtts
    }


def run_full_harness():
    print("=" * 86)
    print("PQChat.DHT - Automated Loopback & Retention Telemetry: MEASURED vs SIMULATED")
    print("=" * 86)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    tools_sim_csv = os.path.join(base_dir, "metrics_dht_loopback.csv")
    docs_sim_csv = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "metrics_dht_loopback.csv"))
    docs_meas_csv = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "metrics_dht_loopback_measured.csv"))
    tools_meas_csv = os.path.join(base_dir, "metrics_dht_loopback_measured.csv")

    all_sim_records: List[TelemetryRecord] = []
    measurement_id = 1

    # 1. SIMULATED Phase: Latency & Delivery Success Rate Trials (1000 trials per profile)
    sim_trials_per_env = 1000
    sim_results: Dict[str, Dict] = {}

    print(f"\n[Phase 1] Executing {sim_trials_per_env} SIMULATED Loopback Iterations per Network Environment...")
    for env_key, profile in PROFILES.items():
        records_env = []
        for _ in range(sim_trials_per_env):
            rec = run_loopback_trial(measurement_id, profile, data_source="SIMULATED")
            measurement_id += 1
            records_env.append(rec)
            all_sim_records.append(rec)

        stats = compute_env_stats(records_env, profile, "SIMULATED")
        sim_results[env_key] = stats
        print(f" -> [SIMULATED] {profile.display_name:22s} | Success: {stats['success_rate']:5.1f}% | "
              f"RTT Total: p50={stats['tot_p50']:5.1f}ms, p90={stats['tot_p90']:5.1f}ms, p99={stats['tot_p99']:5.1f}ms | "
              f"Retrans: {stats['avg_retrans']:4.2f}")

    # 2. MEASURED Phase: Read exclusively from real measurements CSV
    print(f"\n[Phase 2] Loading MEASURED empirical telemetry from {docs_meas_csv}...")
    meas_records = load_measured_records(docs_meas_csv)
    if meas_records:
        export_csv(meas_records, tools_meas_csv)

    meas_results: Dict[str, Dict] = {}
    for env_key, profile in PROFILES.items():
        records_env = [r for r in meas_records if r.network_environment == env_key]
        if records_env:
            stats = compute_env_stats(records_env, profile, "MEASURED")
            meas_results[env_key] = stats
            print(f" -> [MEASURED]  {profile.display_name:22s} | Success: {stats['success_rate']:5.1f}% | "
                  f"RTT Total: p50={stats['tot_p50']:5.1f}ms, p90={stats['tot_p90']:5.1f}ms, p99={stats['tot_p99']:5.1f}ms | "
                  f"Retrans: {stats['avg_retrans']:4.2f}")
        else:
            print(f" -> [MEASURED]  {profile.display_name:22s} | Brak danych (MEASURED pending)")

    # 3. Print Side-by-Side Comparison
    print("\n" + "=" * 86)
    print("EMPIRICAL COMPARISON TABLE: SIMULATED (UDP Hops) vs MEASURED (Live BitTorrent Mainline DHT)")
    print("=" * 86)
    print(f"{'Environment':<22s} | {'Source':<10s} | {'Trials':<6s} | {'Success':<8s} | {'Total p50':<10s} | {'Total p90':<10s} | {'Total p99':<10s} | {'Retrans':<7s}")
    print("-" * 86)
    for env_key, profile in PROFILES.items():
        s = sim_results[env_key]
        m = meas_results[env_key]
        print(f"{profile.display_name:<22s} | {'SIMULATED':<10s} | {s['trials']:<6d} | {s['success_rate']:6.1f}%  | {s['tot_p50']:7.1f} ms | {s['tot_p90']:7.1f} ms | {s['tot_p99']:7.1f} ms | {s['avg_retrans']:5.2f}")
        print(f"{'':<22s} | {'MEASURED':<10s} | {m['trials']:<6d} | {m['success_rate']:6.1f}%  | {m['tot_p50']:7.1f} ms | {m['tot_p90']:7.1f} ms | {m['tot_p99']:7.1f} ms | {m['avg_retrans']:5.2f}")
        print("-" * 86)

    # 4. Retention Evaluation across horizons (5m, 1h, 2h, 6h, 12h, 24h)
    horizons = [5.0 / 60.0, 1.0, 2.0, 6.0, 12.0, 24.0]
    retention_samples = 600
    retention_results = []

    print(f"\n[Phase 3] Evaluating Data Retention across horizons {horizons} hours (N={retention_samples})...")
    for hours in horizons:
        for republish in [False, True]:
            survived_count = 0
            for env_key, profile in PROFILES.items():
                env_samples = retention_samples // len(PROFILES)
                for _ in range(env_samples):
                    rec = simulate_retention_probe(measurement_id, profile, hours, republish, data_source="SIMULATED")
                    measurement_id += 1
                    all_sim_records.append(rec)
                    if rec.delivery_success:
                        survived_count += 1

            survival_rate = (survived_count / (retention_samples // len(PROFILES) * len(PROFILES))) * 100.0
            retention_results.append({
                "hours": hours,
                "republish": republish,
                "survival_rate": survival_rate
            })

            mode_str = "WITH Republish" if republish else "NO Republish  "
            h_str = f"{hours*60:.0f}m" if hours < 1.0 else f"{hours:.0f}h"
            print(f" -> Horizon: {h_str:>4s} | Mode: {mode_str} | Survival Rate: {survival_rate:5.1f}%")

    # Export simulated records
    export_csv(all_sim_records, tools_sim_csv)
    export_csv(all_sim_records, docs_sim_csv)
    print(f"\n[Export] CSV metrics successfully saved to:")
    print(f" -> SIMULATED: {docs_sim_csv}")
    print(f" -> MEASURED:  {docs_meas_csv}")

    # 5. Generate Updated 4-Panel Visualization (MEASURED vs SIMULATED)
    fig_path_tools = os.path.join(base_dir, "dht_retention_latency_chart.png")
    fig_path_docs = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "dht_retention_latency_chart.png"))

    fig, axs = plt.subplots(2, 2, figsize=(16, 12), dpi=300)
    ((ax_lat, ax_succ), (ax_ret, ax_cdf)) = axs

    env_keys = ["WIFI", "LTE", "RESTRICTIVE_NAT"]
    labels = [PROFILES[k].display_name for k in env_keys]
    x = np.arange(len(env_keys))

    # =========================================================================
    # Panel A: Total PUT->GET Latency Percentiles (MEASURED vs SIMULATED)
    # =========================================================================
    bar_w = 0.11
    # SIMULATED bars (hatched, lighter colors)
    sim_p50 = [sim_results[k]["tot_p50"] for k in env_keys]
    sim_p90 = [sim_results[k]["tot_p90"] for k in env_keys]
    sim_p99 = [sim_results[k]["tot_p99"] for k in env_keys]

    # MEASURED bars (solid, darker colors)
    meas_p50 = [meas_results[k]["tot_p50"] for k in env_keys]
    meas_p90 = [meas_results[k]["tot_p90"] for k in env_keys]
    meas_p99 = [meas_results[k]["tot_p99"] for k in env_keys]

    ax_lat.bar(x - 2.5 * bar_w, sim_p50, bar_w, label='SIM Median p50', color='#42a5f5', hatch='//', alpha=0.9)
    ax_lat.bar(x - 1.5 * bar_w, sim_p90, bar_w, label='SIM Tail p90', color='#ffa726', hatch='//', alpha=0.9)
    ax_lat.bar(x - 0.5 * bar_w, sim_p99, bar_w, label='SIM Worst 1% p99', color='#ef5350', hatch='//', alpha=0.9)

    ax_lat.bar(x + 0.5 * bar_w, meas_p50, bar_w, label='MEAS Median p50', color='#1565c0', alpha=0.95)
    ax_lat.bar(x + 1.5 * bar_w, meas_p90, bar_w, label='MEAS Tail p90', color='#e65100', alpha=0.95)
    ax_lat.bar(x + 2.5 * bar_w, meas_p99, bar_w, label='MEAS Worst 1% p99', color='#c62828', alpha=0.95)

    ax_lat.set_yscale('log')
    ax_lat.set_ylim(10, 30000)
    ax_lat.set_xticks(x)
    ax_lat.set_xticklabels(
        [f"{l}\n[SIM | MEASURED]" for l in labels],
        fontsize=9.5, fontweight='bold'
    )
    ax_lat.set_ylabel('Loopback Total RTT (ms, log scale)', fontsize=10, fontweight='bold')
    ax_lat.set_title('A. Total PUT->GET Latency Percentiles [MEASURED vs SIMULATED]', fontsize=11, fontweight='bold')
    ax_lat.legend(loc='upper left', fontsize=8, framealpha=0.95, ncol=2)
    ax_lat.grid(True, which="both", linestyle='--', alpha=0.4)

    # Vertical separators between profile clusters
    for sep in [0.5, 1.5]:
        ax_lat.axvline(sep, color='gray', linestyle=':', alpha=0.5)

    # =========================================================================
    # Panel B: Delivery Success Rate & Retransmissions (MEASURED vs SIMULATED)
    # =========================================================================
    bar_w_b = 0.28
    sim_succ = [sim_results[k]["success_rate"] for k in env_keys]
    meas_succ = [meas_results[k]["success_rate"] for k in env_keys]
    sim_retrans = [sim_results[k]["avg_retrans"] for k in env_keys]
    meas_retrans = [meas_results[k]["avg_retrans"] for k in env_keys]

    b_sim = ax_succ.bar(x - bar_w_b / 2, sim_succ, bar_w_b, label='Success Rate [SIMULATED]', color='#81c784', hatch='//', alpha=0.9)
    b_meas = ax_succ.bar(x + bar_w_b / 2, meas_succ, bar_w_b, label='Success Rate [MEASURED]', color='#2e7d32', alpha=0.95)

    ax_succ_twin = ax_succ.twinx()
    l1 = ax_succ_twin.plot(x - bar_w_b / 2, sim_retrans, marker='s', markersize=8, linewidth=2.2, linestyle='--', color='#ec407a', label='Retransmissions [SIMULATED]')
    l2 = ax_succ_twin.plot(x + bar_w_b / 2, meas_retrans, marker='D', markersize=8, linewidth=2.5, color='#880e4f', label='Retransmissions [MEASURED]')

    ax_succ.set_xticks(x)
    ax_succ.set_xticklabels(labels, fontsize=9.5, fontweight='bold')
    ax_succ.set_ylabel('Delivery Success Rate (%)', fontsize=10, fontweight='bold', color='#2e7d32')
    ax_succ_twin.set_ylabel('Avg Retransmissions per Hop', fontsize=10, fontweight='bold', color='#880e4f')
    ax_succ.set_ylim(0, 115)
    ax_succ_twin.set_ylim(-0.02, 0.45)
    ax_succ.set_title('B. Delivery Success Rate & Retransmissions [MEASURED vs SIMULATED]', fontsize=11, fontweight='bold')
    ax_succ.grid(True, linestyle='--', alpha=0.4)

    # Combine legends for Panel B
    handles_b = [b_sim, b_meas, l1[0], l2[0]]
    labels_b = [h.get_label() for h in handles_b]
    ax_succ.legend(handles_b, labels_b, loc='upper right', fontsize=8, framealpha=0.95)

    # =========================================================================
    # Panel C: Data Retention Curves (MEASURED vs SIMULATED)
    # =========================================================================
    h_vals = horizons
    sim_no_rep = [r["survival_rate"] for r in retention_results if not r["republish"]]
    sim_with_rep = [r["survival_rate"] for r in retention_results if r["republish"]]

    # Read retention strictly from docs/metrics_dht_retention_measured.csv
    docs_retention_csv = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "metrics_dht_retention_measured.csv"))
    meas_retention_points: Dict[Tuple[float, bool], List[float]] = {}
    if os.path.exists(docs_retention_csv):
        with open(docs_retention_csv, mode="r", encoding="utf-8") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                if row.get("data_source") == "MEASURED" and row.get("network_environment") != "MOCK_CLUSTER":
                    h = float(row.get("retention_hours", 0.0))
                    repub = (row.get("republish_enabled", "").strip().lower() == "true")
                    succ = (row.get("delivery_success", "").strip().lower() == "true")
                    meas_retention_points.setdefault((round(h, 2), repub), []).append(1.0 if succ else 0.0)

    # Plot SIMULATED reference curves
    ax_ret.plot(h_vals, sim_with_rep, marker='s', markersize=6, linewidth=2.0, linestyle='--', color='#00acc1', label='With refresh (~1.5h refresh) [SIMULATED]')
    ax_ret.plot(h_vals, sim_no_rep, marker='o', markersize=6, linewidth=2.0, linestyle='--', color='#f57c00', label='Without refresh (Single Put) [SIMULATED]')

    if meas_retention_points:
        meas_h_rep = []
        meas_rate_rep = []
        meas_h_norep = []
        meas_rate_norep = []
        for (h, repub), vals in sorted(meas_retention_points.items()):
            rate = float(np.mean(vals)) * 100.0
            if repub:
                meas_h_rep.append(h)
                meas_rate_rep.append(rate)
            else:
                meas_h_norep.append(h)
                meas_rate_norep.append(rate)
        if meas_h_rep:
            ax_ret.plot(meas_h_rep, meas_rate_rep, marker='s', markersize=7, linewidth=2.8, color='#1565c0', label='With refresh [MEASURED]')
        if meas_h_norep:
            ax_ret.plot(meas_h_norep, meas_rate_norep, marker='o', markersize=7, linewidth=2.8, color='#c62828', label='Without refresh [MEASURED]')
    else:
        # Empty panel with annotation for missing empirical measurements
        ax_ret.text(
            0.5, 0.5,
            "Brak zmierzonych danych retencji (MEASURED)\nOczekiwanie na rzeczywiste pomiary publicznego DHT (1–24h)\n(.github/workflows/dht_retention_24h.yml)",
            ha='center', va='center', transform=ax_ret.transAxes,
            fontsize=9.5, fontweight='bold', color='#b71c1c',
            bbox=dict(boxstyle='round,pad=0.8', facecolor='#ffebee', edgecolor='#c62828', alpha=0.92)
        )

    ax_ret.set_xticks(h_vals)
    tick_labels = ["5m" if h < 1.0 else f"{int(h)}h" for h in h_vals]
    ax_ret.set_xticklabels(tick_labels, fontsize=9.5, fontweight='bold')
    ax_ret.set_xlabel('Time Elapsed Since Initial Publication (hours)', fontsize=10, fontweight='bold')
    ax_ret.set_ylabel('Record Retention Survival Rate (%)', fontsize=10, fontweight='bold')
    ax_ret.set_title('C. DHT Data Retention Decay (BEP 44 Store-and-Forward) [MEASURED vs SIMULATED]', fontsize=11, fontweight='bold')
    ax_ret.set_ylim(-5, 108)
    ax_ret.legend(loc='lower left', fontsize=8.5, framealpha=0.95)
    ax_ret.grid(True, linestyle='--', alpha=0.5)

    # =========================================================================
    # Panel D: Total RTT CDF (MEASURED vs SIMULATED)
    # =========================================================================
    ax_cdf.set_xscale('log')
    meas_colors = {'WIFI': '#1565c0', 'LTE': '#e65100', 'RESTRICTIVE_NAT': '#c62828'}
    sim_colors = {'WIFI': '#64b5f6', 'LTE': '#ffb74d', 'RESTRICTIVE_NAT': '#e57373'}

    # Plot MEASURED CDF curves (solid lines)
    for env_key in env_keys:
        if env_key in meas_results and len(meas_results[env_key]["tot_rtts"]) > 0:
            sorted_m = np.sort(meas_results[env_key]["tot_rtts"])
            yvals_m = np.arange(len(sorted_m)) / float(len(sorted_m) - 1)
            ax_cdf.plot(sorted_m, yvals_m * 100, linewidth=2.6, color=meas_colors[env_key], label=f'{PROFILES[env_key].display_name} [MEASURED]')

    # Plot SIMULATED CDF curves (dashed lines)
    for env_key in env_keys:
        sorted_s = np.sort(sim_results[env_key]["tot_rtts"])
        yvals_s = np.arange(len(sorted_s)) / float(len(sorted_s) - 1)
        ax_cdf.plot(sorted_s, yvals_s * 100, linewidth=1.8, linestyle='--', color=sim_colors[env_key], label=f'{PROFILES[env_key].display_name} [SIMULATED]')

    ax_cdf.set_xlabel('Total Latency (ms, log scale)', fontsize=10, fontweight='bold')
    ax_cdf.set_ylabel('Cumulative Probability (%)', fontsize=10, fontweight='bold')
    ax_cdf.set_title('D. Cumulative Distribution Function (CDF) of Total RTT [MEASURED vs SIMULATED]', fontsize=11, fontweight='bold')
    ax_cdf.set_xlim(20, 16000)
    ax_cdf.set_ylim(-2, 105)
    ax_cdf.legend(loc='lower right', fontsize=8, framealpha=0.95)
    ax_cdf.grid(True, which="both", linestyle='--', alpha=0.4)

    plt.tight_layout()
    plt.savefig(fig_path_tools, dpi=300)
    plt.savefig(fig_path_docs, dpi=300)
    plt.close()

    print(f"\n[Visualization] Generated updated 4-panel chart distinguishing MEASURED vs SIMULATED:")
    print(f" -> {fig_path_tools}")
    print(f" -> {fig_path_docs}")
    print("\nHarness execution finished successfully.")


if __name__ == "__main__":
    run_full_harness()
