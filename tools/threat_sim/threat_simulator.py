#!/usr/bin/env python3
"""
PQChat.DHT - Adversary Traffic Correlation & Anonymity Simulator
================================================================
Models passive and active DHT storage node observers attempting to correlate
sender (PUT) and receiver (GET) IP addresses over time under Ephemeral Key Hopping.

In PQChat.DHT (AGENTS.md Sec. 5.B):
  - Every message uses an ephemeral single-use target: Target_i = SHA-1(pk_i).
  - Storage nodes observe PUT and subsequent GET(s) per target slot.
  - Cover traffic, decoy GETs, delayed PUTs, and polling jitter introduce ambiguity
    at each ephemeral target, preventing the storage node from linking sender and receiver.

Outputs:
  - Quantitative correlation probability P(corr) vs delta_t arrival time difference
  - Degree of Anonymity (Normalized Shannon Entropy) across defense configurations
  - Resource trade-off: Anonymity vs UDP bandwidth (KB/h) and battery power (mWh)
  - 4-panel publication-quality visualization charts
"""

import os
import sys
import math
import numpy as np
import matplotlib.pyplot as plt
from dataclasses import dataclass
from typing import List, Tuple, Dict

# Set plot styling
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans', 'Arial', 'Helvetica'
plt.rcParams['axes.edgecolor'] = '#cccccc'
plt.rcParams['axes.linewidth'] = 0.8


@dataclass
class SimulationConfig:
    num_client_pairs: int = 25          # 50 clients (25 communicating pairs)
    num_storage_nodes: int = 16         # DHT nodes in observed neighborhood
    sim_duration_sec: float = 3600.0    # 1 hour simulation run
    msg_rate_per_pair_hour: float = 20  # Average 20 messages per pair per hour
    poll_interval_sec: float = 10.0     # Active foreground chat poll interval (10s)
    bep44_value_bytes: int = 1000       # Exact BEP 44 value payload size (1000 B)
    krpc_put_overhead_bytes: int = 70   # KRPC UDP/Bencode put header overhead (~1070 B total)
    krpc_get_overhead_bytes: int = 150  # KRPC UDP/Bencode get query+response (~150 B)
    rrc_tail_time_sec: float = 8.0      # Cellular modem RRC inactivity timer (8s)
    power_active_mw: float = 1200.0     # Modem active/tail power draw (mW)
    power_idle_mw: float = 10.0         # Modem deep sleep idle power draw (mW)


@dataclass
class DefenseParameters:
    name: str
    poisson_lambda: float = 0.0         # Events/sec (1/480 = once per 8 min)
    cover_get_ratio: float = 0.0        # Ratio of decoy GETs per real GET (0.0 = none)
    polling_jitter_ratio: float = 0.0   # Jitter as fraction of poll interval (e.g. 0.3 = +-30%)
    put_delay_max_sec: float = 0.0      # Random hold delay for PUT emissions (0.0 = immediate)
    decoy_put_slots: int = 0            # Dummy PUT targets published per message


class PoissonTrafficModel:
    """Exact replica of Kotlin PoissonTrafficGenerator mathematical formulation."""
    def __init__(self, lambda_rate: float):
        self.lambda_rate = lambda_rate

    def next_interval(self) -> float:
        if self.lambda_rate <= 0:
            return float('inf')
        u = np.random.uniform(1e-10, 1.0 - 1e-10)
        return -math.log(u) / self.lambda_rate


class TrafficSimulator:
    """Simulates ephemeral DHT message exchange, storage observations, and adversary inference."""

    def __init__(self, sim_cfg: SimulationConfig, defense: DefenseParameters, seed: int = 42):
        self.cfg = sim_cfg
        self.defense = defense
        np.random.seed(seed)

    def run_simulation(self) -> Dict:
        pairs = self.cfg.num_client_pairs
        total_time = self.cfg.sim_duration_sec
        nodes_count = self.cfg.num_storage_nodes

        # Generate message events for each pair
        msg_events = []
        for p in range(pairs):
            t = 0.0
            avg_interval = 3600.0 / self.cfg.msg_rate_per_pair_hour
            while t < total_time:
                t += np.random.exponential(avg_interval)
                if t < total_time:
                    msg_events.append((t, p))
        msg_events.sort(key=lambda x: x[0])

        dht_events = []
        bytes_uploaded = 0
        bytes_downloaded = 0
        all_clients = [f"Alice_{p}" for p in range(pairs)] + [f"Bob_{p}" for p in range(pairs)]
        client_bytes = {c: 0 for c in all_clients}
        client_wakes = {c: [] for c in all_clients}

        ephemeral_slots = {}
        target_counter = 0
        receiver_current_target = {p: None for p in range(pairs)}

        # 1. Real PUTs (Alice -> Ephemeral Target in DHT)
        for t_create, p in msg_events:
            sender_id = f"Alice_{p}"
            receiver_id = f"Bob_{p}"

            put_delay = np.random.uniform(0, self.defense.put_delay_max_sec) if self.defense.put_delay_max_sec > 0 else 0.0
            t_put = t_create + put_delay
            slot_id = f"hop_target_{p}_{target_counter}"
            node_idx = target_counter % nodes_count
            target_counter += 1

            ephemeral_slots[slot_id] = {
                "t_put": t_put,
                "sender": sender_id,
                "receiver": receiver_id,
                "node": node_idx,
                "is_dummy": False
            }
            receiver_current_target[p] = slot_id

            dht_events.append((t_put, 'PUT', sender_id, slot_id, node_idx, False))
            pkg_size = self.cfg.bep44_value_bytes + self.cfg.krpc_put_overhead_bytes
            bytes_uploaded += pkg_size
            client_bytes[sender_id] += pkg_size
            client_wakes[sender_id].append(t_put)

            # Decoy PUT slots
            for d in range(self.defense.decoy_put_slots):
                t_decoy = t_put + np.random.uniform(0.1, 3.0)
                decoy_slot = f"decoy_slot_{p}_{d}_{target_counter}"
                decoy_node = (node_idx + d + 1) % nodes_count
                ephemeral_slots[decoy_slot] = {
                    "t_put": t_decoy,
                    "sender": sender_id,
                    "receiver": None,
                    "node": decoy_node,
                    "is_dummy": True
                }
                dht_events.append((t_decoy, 'PUT', sender_id, decoy_slot, decoy_node, True))
                bytes_uploaded += pkg_size
                client_bytes[sender_id] += pkg_size
                client_wakes[sender_id].append(t_decoy)

        # 2. Poisson Cover Traffic PUTs (Dummy slots)
        if self.defense.poisson_lambda > 0:
            poisson = PoissonTrafficModel(self.defense.poisson_lambda)
            for p in range(pairs):
                for client in [f"Alice_{p}", f"Bob_{p}"]:
                    t_cov = poisson.next_interval()
                    while t_cov < total_time:
                        dummy_slot = f"poisson_dummy_{client}_{target_counter}"
                        dummy_node = target_counter % nodes_count
                        target_counter += 1

                        ephemeral_slots[dummy_slot] = {
                            "t_put": t_cov,
                            "sender": client,
                            "receiver": None,
                            "node": dummy_node,
                            "is_dummy": True
                        }
                        dht_events.append((t_cov, 'PUT', client, dummy_slot, dummy_node, True))
                        pkg_size = self.cfg.bep44_value_bytes + self.cfg.krpc_put_overhead_bytes
                        bytes_uploaded += pkg_size
                        client_bytes[client] += pkg_size
                        client_wakes[client].append(t_cov)
                        t_cov += poisson.next_interval()

        # 3. GET Polling by Receivers (Bob_0 .. Bob_N-1)
        active_slot_keys = list(ephemeral_slots.keys())

        for p in range(pairs):
            receiver_id = f"Bob_{p}"
            t_poll = np.random.uniform(0, self.cfg.poll_interval_sec)

            while t_poll < total_time:
                if self.defense.polling_jitter_ratio > 0:
                    jitter = np.random.uniform(
                        -self.defense.polling_jitter_ratio * self.cfg.poll_interval_sec,
                        self.defense.polling_jitter_ratio * self.cfg.poll_interval_sec
                    )
                    actual_interval = max(1.0, self.cfg.poll_interval_sec + jitter)
                else:
                    actual_interval = self.cfg.poll_interval_sec

                polled_slot = receiver_current_target[p]
                if polled_slot and polled_slot in ephemeral_slots:
                    slot_info = ephemeral_slots[polled_slot]
                    node_idx = slot_info["node"]
                else:
                    polled_slot = f"idle_{p}"
                    node_idx = p % nodes_count

                dht_events.append((t_poll, 'GET', receiver_id, polled_slot, node_idx, False))
                bytes_downloaded += self.cfg.krpc_get_overhead_bytes
                client_bytes[receiver_id] += self.cfg.krpc_get_overhead_bytes
                client_wakes[receiver_id].append(t_poll)

                # Decoy GET Queries
                if self.defense.cover_get_ratio > 0:
                    num_decoys = np.random.poisson(self.defense.cover_get_ratio)
                    for _ in range(num_decoys):
                        if active_slot_keys and np.random.random() < 0.55:
                            decoy_target = active_slot_keys[np.random.randint(len(active_slot_keys))]
                            decoy_node = ephemeral_slots[decoy_target]["node"]
                        else:
                            decoy_target = f"synth_{np.random.randint(1_000_000)}"
                            decoy_node = np.random.randint(nodes_count)

                        t_decoy_get = t_poll + np.random.uniform(0.05, 1.5)
                        dht_events.append((t_decoy_get, 'GET', receiver_id, decoy_target, decoy_node, True))
                        bytes_downloaded += self.cfg.krpc_get_overhead_bytes
                        client_bytes[receiver_id] += self.cfg.krpc_get_overhead_bytes
                        client_wakes[receiver_id].append(t_decoy_get)

                t_poll += actual_interval

        dht_events.sort(key=lambda x: x[0])

        adversary_results = self._evaluate_ephemeral_adversary(dht_events, ephemeral_slots, pairs)

        per_client_bandwidth_kb_h = float(np.mean([client_bytes[c] / 1024.0 for c in all_clients]))
        client_energies = [self._calculate_battery_energy(client_wakes[c], total_time) for c in all_clients]
        per_client_energy_mwh = float(np.mean(client_energies))

        return {
            "top1_accuracy": adversary_results["top1_accuracy"],
            "anonymity_degree": adversary_results["anonymity_degree"],
            "delta_t_distribution": adversary_results["delta_ts"],
            "corr_by_delta_t": adversary_results["corr_by_delta_t"],
            "bandwidth_kb_h": per_client_bandwidth_kb_h,
            "battery_energy_mwh": per_client_energy_mwh,
            "total_packets": len(dht_events)
        }

    def _evaluate_ephemeral_adversary(self, dht_events: List, ephemeral_slots: Dict, num_pairs: int) -> Dict:
        """
        Adversary controls storage nodes observing ephemeral slots.
        Evaluates timing correlation P(corr | delta_t) and calculates top-1 accuracy and Shannon entropy.
        """
        slot_gets = {}
        for t, ev_type, client, target, node_idx, is_cover in dht_events:
            if ev_type == 'GET':
                slot_gets.setdefault(target, []).append((t, client))

        correct_attributions = 0
        total_evaluations = 0
        slot_entropies = []
        observed_delta_ts = []
        delta_t_accuracy_pairs = []

        window = 30.0

        # Pairwise association matrix across the entire hour session
        pair_confusion_matrix = np.zeros((num_pairs, num_pairs))

        for slot_id, slot_info in ephemeral_slots.items():
            t_put = slot_info["t_put"]
            sender = slot_info["sender"]
            true_receiver = slot_info["receiver"]
            is_dummy = slot_info["is_dummy"]

            gets = slot_gets.get(slot_id, [])
            candidates = [(t_g - t_put, r_id) for t_g, r_id in gets if 0 <= (t_g - t_put) <= window]

            if not candidates:
                continue

            total_evaluations += 1

            candidate_weights = {}
            for dt, r_id in candidates:
                observed_delta_ts.append(dt)
                w = math.exp(-dt / max(1.0, self.cfg.poll_interval_sec))
                candidate_weights[r_id] = candidate_weights.get(r_id, 0.0) + w

            total_weight = sum(candidate_weights.values())
            probs = {r: w / total_weight for r, w in candidate_weights.items()}

            # Track global pair confusion matrix
            if sender.startswith("Alice_"):
                s_idx = int(sender.split("_")[1])
                for r, p_val in probs.items():
                    if r.startswith("Bob_"):
                        r_idx = int(r.split("_")[1])
                        pair_confusion_matrix[s_idx, r_idx] += p_val

            predicted_receiver = max(probs.keys(), key=lambda k: probs[k])

            if not is_dummy and true_receiver is not None:
                is_correct = (predicted_receiver == true_receiver)
                sorted_p = sorted(probs.values(), reverse=True)
                if len(sorted_p) > 1 and (sorted_p[0] - sorted_p[1]) < 0.15:
                    is_correct = False
                if is_correct:
                    correct_attributions += 1

                for dt, r_id in candidates:
                    if r_id == true_receiver:
                        delta_t_accuracy_pairs.append((dt, is_correct))
            else:
                delta_t_accuracy_pairs.append((candidates[0][0], False))

        top1_accuracy = correct_attributions / max(1, total_evaluations)

        # Global Session Anonymity Degree (Normalized Shannon entropy of pair confusion matrix)
        global_entropies = []
        max_h = math.log2(num_pairs) if num_pairs > 1 else 1.0
        for s_idx in range(num_pairs):
            row = pair_confusion_matrix[s_idx, :]
            row_sum = np.sum(row)
            if row_sum > 0:
                p_dist = row / row_sum
                h = -np.sum([p * math.log2(p) for p in p_dist if p > 0])
                global_entropies.append(h / max_h)
            else:
                global_entropies.append(1.0)

        anonymity_degree = float(np.mean(global_entropies))

        # Binned P(corr) vs delta_t
        corr_by_delta_t = {}
        bins = np.linspace(0, window, 8)
        for i in range(len(bins) - 1):
            b_min, b_max = bins[i], bins[i+1]
            in_bin = [corr for dt, corr in delta_t_accuracy_pairs if b_min <= dt < b_max]
            b_mid = (b_min + b_max) / 2.0
            corr_by_delta_t[b_mid] = float(np.mean(in_bin)) if in_bin else 0.0

        return {
            "top1_accuracy": top1_accuracy,
            "anonymity_degree": anonymity_degree,
            "delta_ts": observed_delta_ts,
            "corr_by_delta_t": corr_by_delta_t
        }

    def _calculate_battery_energy(self, wake_events: List[float], total_time: float) -> float:
        """Calculates cellular modem power consumption with RRC tail time (mWh)."""
        if not wake_events:
            return (self.cfg.power_idle_mw * total_time / 3600.0)

        wake_events.sort()
        active_intervals = []
        cur_start = wake_events[0]
        cur_end = cur_start + self.cfg.rrc_tail_time_sec

        for t in wake_events[1:]:
            if t <= cur_end:
                cur_end = max(cur_end, t + self.cfg.rrc_tail_time_sec)
            else:
                active_intervals.append((cur_start, min(total_time, cur_end)))
                cur_start = t
                cur_end = cur_start + self.cfg.rrc_tail_time_sec
        active_intervals.append((cur_start, min(total_time, cur_end)))

        total_active_sec = sum(end - start for start, end in active_intervals)
        total_idle_sec = max(0.0, total_time - total_active_sec)

        energy_mj = (total_active_sec * self.cfg.power_active_mw) + (total_idle_sec * self.cfg.power_idle_mw)
        return energy_mj / 3600.0


def run_comprehensive_simulation():
    """Runs simulations and produces publication-quality 4-panel trade-off visualizations."""
    print("=" * 76)
    print("PQChat.DHT - Adversary Traffic Correlation & Anonymity Simulator")
    print("=" * 76)

    cfg = SimulationConfig()

    defenses = [
        DefenseParameters(
            name="Baseline (No Defenses)",
            poisson_lambda=0.0,
            cover_get_ratio=0.0,
            polling_jitter_ratio=0.0,
            put_delay_max_sec=0.0,
            decoy_put_slots=0
        ),
        DefenseParameters(
            name="+ Polling Jitter (+-30%)",
            poisson_lambda=0.0,
            cover_get_ratio=0.0,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=0.0,
            decoy_put_slots=0
        ),
        DefenseParameters(
            name="+ Decoy GETs (Ratio 1.5)",
            poisson_lambda=0.0,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=0.0,
            decoy_put_slots=0
        ),
        DefenseParameters(
            name="+ Delayed PUTs (5s) & Decoy Slots",
            poisson_lambda=0.0,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1
        ),
        DefenseParameters(
            name="Full Defense (All + Poisson 1/480s)",
            poisson_lambda=1.0 / 480.0,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1
        )
    ]

    print("\n--- 1. Evaluating Defense Postures (1-Hour Traces) ---")
    posture_results = []
    for d in defenses:
        sim = TrafficSimulator(cfg, d, seed=42)
        res = sim.run_simulation()
        posture_results.append((d, res))
        print(f"[{d.name:36s}] Top-1 Corr: {res['top1_accuracy']*100:5.1f}% | "
              f"Anonymity: {res['anonymity_degree']*100:5.1f}% | "
              f"Bandwidth: {res['bandwidth_kb_h']:7.1f} KB/h | "
              f"Energy: {res['battery_energy_mwh']:6.1f} mWh")

    print("\n--- 2. Sweeping Poisson Cover Traffic Rate (Lambda) ---")
    lambda_values = [
        0.0,            # Off
        1.0 / 1800.0,   # Every 30 min
        1.0 / 900.0,    # Every 15 min
        1.0 / 600.0,    # Every 10 min
        1.0 / 480.0,    # Every 8 min (Current app default)
        1.0 / 240.0,    # Every 4 min
        1.0 / 120.0,    # Every 2 min
        1.0 / 60.0,     # Every 1 min
        1.0 / 30.0,     # Every 30 sec
        1.0 / 15.0      # Every 15 sec
    ]

    lambda_labels = [
        "Off", "30m", "15m", "10m", "8m (Default)", "4m", "2m", "1m", "30s", "15s"
    ]

    sweep_anonymity = []
    sweep_accuracy = []
    sweep_bandwidth = []
    sweep_energy = []

    for l_val in lambda_values:
        d = DefenseParameters(
            name=f"Lambda {l_val:.5f}",
            poisson_lambda=l_val,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1
        )
        accs, anons, bws, engs = [], [], [], []
        for seed in [42, 101, 2024]:
            sim = TrafficSimulator(cfg, d, seed=seed)
            res = sim.run_simulation()
            accs.append(res['top1_accuracy'])
            anons.append(res['anonymity_degree'])
            bws.append(res['bandwidth_kb_h'])
            engs.append(res['battery_energy_mwh'])

        mean_acc = np.mean(accs)
        mean_anon = np.mean(anons)
        mean_bw = np.mean(bws)
        mean_eng = np.mean(engs)

        sweep_accuracy.append(mean_acc)
        sweep_anonymity.append(mean_anon)
        sweep_bandwidth.append(mean_bw)
        sweep_energy.append(mean_eng)

        print(f"Lambda = {l_val:8.5f} ({lambda_labels[len(sweep_anonymity)-1]:12s}) -> "
              f"Top-1: {mean_acc*100:5.1f}% | Anonymity: {mean_anon*100:5.1f}% | "
              f"Bandwidth: {mean_bw:7.1f} KB/h | Energy: {mean_eng:6.1f} mWh")

    # 3. Generate 4-Panel Visualization Figure
    output_dir_tools = os.path.dirname(os.path.abspath(__file__))
    output_dir_docs = os.path.abspath(os.path.join(output_dir_tools, "..", "..", "docs"))
    os.makedirs(output_dir_docs, exist_ok=True)

    fig_path_tools = os.path.join(output_dir_tools, "tradeoff_anonymity_bandwidth_battery.png")
    fig_path_docs = os.path.join(output_dir_docs, "tradeoff_anonymity_bandwidth_battery.png")

    fig, axs = plt.subplots(2, 2, figsize=(15, 11), dpi=300)
    ((ax_dt, ax_bar), (ax_sec, ax_res)) = axs

    # Panel 1 (Top-Left): P(Correlation) vs Delta_t arrival time
    colors_dt = ['#e53935', '#fb8c00', '#1e88e5', '#8e24aa', '#2e7d32']
    for idx, (def_param, res_item) in enumerate(posture_results):
        cdict = res_item["corr_by_delta_t"]
        if cdict:
            dts = sorted(cdict.keys())
            probs = [cdict[t] * 100 for t in dts]
            ax_dt.plot(dts, probs, marker='o', linewidth=2.0, color=colors_dt[idx],
                       label=def_param.name.split('(')[0].strip())
        else:
            # Baseline theoretical curve
            dts = np.linspace(0, 30, 15)
            probs = [100.0 * math.exp(-t / 10.0) for t in dts]
            ax_dt.plot(dts, probs, linestyle='--', color='#e53935', label='Baseline Model')

    ax_dt.set_xlabel(r'Arrival Time Gap $\Delta t = t_{\mathrm{GET}} - t_{\mathrm{PUT}}$ (seconds)', fontsize=10, fontweight='bold')
    ax_dt.set_ylabel(r'Correlation Probability $P(\mathrm{corr} \mid \Delta t)$ (%)', fontsize=10, fontweight='bold')
    ax_dt.set_title(r'A. Timing Correlation Success vs $\Delta t$', fontsize=11, fontweight='bold')
    ax_dt.set_ylim(-5, 105)
    ax_dt.legend(loc='upper right', fontsize=8.5, framealpha=0.9)
    ax_dt.grid(True, linestyle='--', alpha=0.5)

    # Panel 2 (Top-Right): Defense Posture Comparison (Bar chart)
    posture_names = [
        d[0].name.replace(" (No Defenses)", "\n(Baseline)")
                .replace(" (Ratio 1.5)", "")
                .replace(" (5s) & Decoy Slots", "")
                .replace(" (All + Poisson 1/480s)", "\n(Full Def.)")
        for d in posture_results
    ]
    posture_top1 = [d[1]['top1_accuracy'] * 100 for d in posture_results]
    posture_anon = [d[1]['anonymity_degree'] * 100 for d in posture_results]

    x = np.arange(len(posture_names))
    width = 0.35

    ax_bar.bar(x - width/2, posture_top1, width, label='Adversary Accuracy P(corr) %', color='#e53935', alpha=0.9)
    ax_bar.bar(x + width/2, posture_anon, width, label='Degree of Anonymity (Entropy) %', color='#1e88e5', alpha=0.9)

    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(posture_names, rotation=20, ha='right', fontsize=8.5)
    ax_bar.set_ylabel('Metric Score (%)', fontsize=10, fontweight='bold')
    ax_bar.set_title('B. Defense Mechanisms Impact on Linkability', fontsize=11, fontweight='bold')
    ax_bar.set_ylim(0, 115)
    ax_bar.legend(loc='upper right', fontsize=8.5, framealpha=0.9)
    ax_bar.grid(True, linestyle='--', alpha=0.5)

    # Panel 3 (Bottom-Left): Security vs Poisson Cover Rate Lambda
    x_indices = np.arange(len(lambda_values))

    ax_sec.plot(x_indices, np.array(sweep_anonymity) * 100, marker='o', linewidth=2.5, color='#1e88e5', label='Degree of Anonymity (Entropy %)')
    ax_sec.plot(x_indices, (1.0 - np.array(sweep_accuracy)) * 100, marker='s', linewidth=2.2, linestyle='--', color='#2e7d32', label='Adversary Error Rate (1 - P(corr)) %')
    ax_sec.plot(x_indices, np.array(sweep_accuracy) * 100, marker='^', linewidth=2.0, linestyle=':', color='#e53935', label='Adversary Success P(corr) %')

    ax_sec.set_xticks(x_indices)
    ax_sec.set_xticklabels(lambda_labels, rotation=35, ha='right', fontsize=8.5)
    ax_sec.set_xlabel(r'Cover Traffic Rate $\lambda$ (Mean Interval)', fontsize=10, fontweight='bold')
    ax_sec.set_ylabel('Security Metric (%)', fontsize=10, fontweight='bold')
    ax_sec.set_title(r'C. Anonymity vs Poisson Rate $\lambda$', fontsize=11, fontweight='bold')
    ax_sec.set_ylim(-5, 105)
    ax_sec.axvline(x=4, color='#666666', linestyle='-.', alpha=0.8, label=r'Default ($\lambda=1/480$)')
    ax_sec.legend(loc='center left', fontsize=8.5, framealpha=0.9)
    ax_sec.grid(True, linestyle='--', alpha=0.5)

    # Panel 4 (Bottom-Right): Resource Overhead: UDP Bandwidth vs Battery Consumption
    ax_res_twin = ax_res.twinx()

    p1 = ax_res.plot(x_indices, sweep_bandwidth, marker='D', linewidth=2.4, color='#3949ab', label='UDP Bandwidth (KB/h)')
    p2 = ax_res_twin.plot(x_indices, sweep_energy, marker='v', linewidth=2.4, color='#ef6c00', label='Modem Power (mWh/h)')

    ax_res.set_xticks(x_indices)
    ax_res.set_xticklabels(lambda_labels, rotation=35, ha='right', fontsize=8.5)
    ax_res.set_xlabel(r'Cover Traffic Rate $\lambda$ (Mean Interval)', fontsize=10, fontweight='bold')
    ax_res.set_ylabel('UDP Bandwidth (KB / hour)', fontsize=10, fontweight='bold', color='#3949ab')
    ax_res_twin.set_ylabel('Modem Energy (mWh / hour)', fontsize=10, fontweight='bold', color='#ef6c00')
    ax_res.tick_params(axis='y', labelcolor='#3949ab')
    ax_res_twin.tick_params(axis='y', labelcolor='#ef6c00')

    ax_res.set_title('D. Bandwidth & Battery Cost Trade-off', fontsize=11, fontweight='bold')
    ax_res.grid(True, linestyle='--', alpha=0.5)

    lines = p1 + p2
    labels = [l.get_label() for l in lines]
    ax_res.legend(lines, labels, loc='upper left', fontsize=8.5, framealpha=0.9)

    plt.tight_layout()
    plt.savefig(fig_path_tools, dpi=300)
    plt.savefig(fig_path_docs, dpi=300)
    plt.close()

    print(f"\n[Generated 4-Panel Visualization]")
    print(f" -> {fig_path_tools}")
    print(f" -> {fig_path_docs}")
    print("\nSimulation completed successfully.")


if __name__ == "__main__":
    run_comprehensive_simulation()
