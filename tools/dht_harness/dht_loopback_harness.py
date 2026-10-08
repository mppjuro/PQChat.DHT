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
4. Strict separation between MEASURED and SIMULATED telemetry.
5. Removal of hardcoded artificial floors (e.g. max(0.85)).
6. Safe CSV export: Zero message content, zero cryptographic keys/seeds.
7. Visualizations & summary report generation.
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


def run_full_harness():
    print("=" * 78)
    print("PQChat.DHT - Automated Loopback & Retention Measurement Harness")
    print("=" * 78)

    all_records: List[TelemetryRecord] = []
    measurement_id = 1

    # 1. Latency & Delivery Success Rate Trials (1000 trials per environment)
    trials_per_env = 1000
    env_results = {}

    print(f"\n[Phase 1] Executing {trials_per_env} Loopback Iterations per Network Environment...")
    for env_key, profile in PROFILES.items():
        records_env = []
        for _ in range(trials_per_env):
            rec = run_loopback_trial(measurement_id, profile, data_source="SIMULATED")
            measurement_id += 1
            records_env.append(rec)
            all_records.append(rec)

        successful = [r for r in records_env if r.delivery_success]
        success_rate = (len(successful) / len(records_env)) * 100.0

        put_rtts = [r.rtt_put_ms for r in records_env]
        get_rtts = [r.rtt_get_ms for r in successful]
        tot_rtts = [r.rtt_total_ms for r in successful]
        avg_retrans = np.mean([r.retransmissions for r in records_env])

        stats = {
            "profile": profile,
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
        env_results[env_key] = stats

        print(f" -> {profile.display_name:24s} | Success: {success_rate:5.1f}% | "
              f"RTT Total: p50={stats['tot_p50']:5.1f}ms, p90={stats['tot_p90']:5.1f}ms, p99={stats['tot_p99']:5.1f}ms | "
              f"Retrans: {avg_retrans:4.2f}")

    # 2. Data Retention Evaluation (5 min, 1h, 2h, 6h, 12h, 24h, N=600 >= 300)
    horizons = [5.0 / 60.0, 1.0, 2.0, 6.0, 12.0, 24.0]
    retention_samples = 600
    retention_results = []

    print(f"\n[Phase 2] Evaluating Data Retention across horizons {horizons} hours (N={retention_samples})...")
    for hours in horizons:
        for republish in [False, True]:
            survived_count = 0
            for env_key, profile in PROFILES.items():
                env_samples = retention_samples // len(PROFILES)
                for _ in range(env_samples):
                    rec = simulate_retention_probe(measurement_id, profile, hours, republish, data_source="SIMULATED")
                    measurement_id += 1
                    all_records.append(rec)
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

    # 3. CSV Export
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tools_csv = os.path.join(base_dir, "metrics_dht_loopback.csv")
    docs_csv = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "metrics_dht_loopback.csv"))

    export_csv(all_records, tools_csv)
    export_csv(all_records, docs_csv)
    print(f"\n[Export] CSV metrics successfully saved to:")
    print(f" -> {tools_csv}")
    print(f" -> {docs_csv}")

    # 4. Generate 4-Panel Visualization
    fig_path_tools = os.path.join(base_dir, "dht_retention_latency_chart.png")
    fig_path_docs = os.path.abspath(os.path.join(base_dir, "..", "..", "docs", "dht_retention_latency_chart.png"))

    fig, axs = plt.subplots(2, 2, figsize=(15, 11), dpi=300)
    ((ax_lat, ax_succ), (ax_ret, ax_cdf)) = axs

    # Panel A: Latency Percentiles (p50, p90, p99) by Network Profile
    profiles_list = list(env_results.values())
    labels = [p["profile"].display_name for p in profiles_list]
    x = np.arange(len(labels))
    width = 0.25

    p50_vals = [p["tot_p50"] for p in profiles_list]
    p90_vals = [p["tot_p90"] for p in profiles_list]
    p99_vals = [p["tot_p99"] for p in profiles_list]

    ax_lat.bar(x - width, p50_vals, width, label='Median p50', color='#1e88e5', alpha=0.9)
    ax_lat.bar(x, p90_vals, width, label='Tail p90', color='#fb8c00', alpha=0.9)
    ax_lat.bar(x + width, p99_vals, width, label='Worst 1% p99', color='#e53935', alpha=0.9)

    ax_lat.set_xticks(x)
    ax_lat.set_xticklabels(labels, fontsize=9.5, fontweight='bold')
    ax_lat.set_ylabel('Loopback Total RTT (ms)', fontsize=10, fontweight='bold')
    ax_lat.set_title('A. Total PUT->GET Latency Percentiles [SIMULATED Calibrated Network Profiles]', fontsize=10.5, fontweight='bold')
    ax_lat.legend(loc='upper left', fontsize=8.5, framealpha=0.9)
    ax_lat.grid(True, linestyle='--', alpha=0.5)

    # Panel B: Delivery Success Rate & Retransmissions
    succ_vals = [p["success_rate"] for p in profiles_list]
    retrans_vals = [p["avg_retrans"] for p in profiles_list]

    ax_succ_twin = ax_succ.twinx()
    ax_succ.bar(x - 0.18, succ_vals, 0.36, label='Delivery Success Rate (%)', color='#2e7d32', alpha=0.85)
    ax_succ_twin.plot(x + 0.18, retrans_vals, marker='o', linewidth=2.5, color='#d81b60', label='Avg Retransmissions')

    ax_succ.set_xticks(x)
    ax_succ.set_xticklabels(labels, fontsize=9.5, fontweight='bold')
    ax_succ.set_ylabel('Delivery Success Rate (%)', fontsize=10, fontweight='bold', color='#2e7d32')
    ax_succ_twin.set_ylabel('Avg Retransmissions per Hop', fontsize=10, fontweight='bold', color='#d81b60')
    ax_succ.set_ylim(0, 105)
    ax_succ.set_title('B. Delivery Success Rate & Retransmissions [SIMULATED]', fontsize=10.5, fontweight='bold')
    ax_succ.grid(True, linestyle='--', alpha=0.5)

    # Panel C: Data Retention Curves (5m, 1h, 2h, 6h, 12h, 24h)
    h_vals = horizons
    no_rep = [r["survival_rate"] for r in retention_results if not r["republish"]]
    with_rep = [r["survival_rate"] for r in retention_results if r["republish"]]

    ax_ret.plot(h_vals, with_rep, marker='s', linewidth=2.6, color='#1e88e5', label='With Active Republish (~1.5h refresh) [SIMULATED]')
    ax_ret.plot(h_vals, no_rep, marker='o', linewidth=2.6, linestyle='--', color='#e53935', label='Without Republish (Single Publish) [SIMULATED]')

    ax_ret.set_xticks(h_vals)
    tick_labels = ["5m" if h < 1.0 else f"{int(h)}h" for h in h_vals]
    ax_ret.set_xticklabels(tick_labels, fontsize=9.5, fontweight='bold')
    ax_ret.set_xlabel('Time Elapsed Since Initial Publication (hours)', fontsize=10, fontweight='bold')
    ax_ret.set_ylabel('Record Retention Survival Rate (%)', fontsize=10, fontweight='bold')
    ax_ret.set_title('C. DHT Data Retention Decay (BEP 44 Store-and-Forward) [SIMULATED Decay, No Floor]', fontsize=10.5, fontweight='bold')
    ax_ret.set_ylim(-5, 105)
    ax_ret.legend(loc='lower left', fontsize=9, framealpha=0.9)
    ax_ret.grid(True, linestyle='--', alpha=0.5)

    # Panel D: Total RTT CDF (Empirical Distribution)
    colors_cdf = {'WIFI': '#1e88e5', 'LTE': '#fb8c00', 'RESTRICTIVE_NAT': '#e53935'}
    for env_key, res in env_results.items():
        sorted_data = np.sort(res["tot_rtts"])
        yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
        ax_cdf.plot(sorted_data, yvals * 100, linewidth=2.2, color=colors_cdf[env_key], label=res["profile"].display_name)

    ax_cdf.set_xlabel('Total Latency (ms)', fontsize=10, fontweight='bold')
    ax_cdf.set_ylabel('Cumulative Probability (%)', fontsize=10, fontweight='bold')
    ax_cdf.set_title('D. Cumulative Distribution Function (CDF) of Total RTT [SIMULATED]', fontsize=10.5, fontweight='bold')
    ax_cdf.set_xlim(0, 1000)
    ax_cdf.set_ylim(0, 105)
    ax_cdf.legend(loc='lower right', fontsize=8.5, framealpha=0.9)
    ax_cdf.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(fig_path_tools, dpi=300)
    plt.savefig(fig_path_docs, dpi=300)
    plt.close()

    print(f"\n[Visualization] Generated 4-panel chart with SIMULATED labeling:")
    print(f" -> {fig_path_tools}")
    print(f" -> {fig_path_docs}")
    print("\nHarness execution finished successfully.")


if __name__ == "__main__":
    run_full_harness()
