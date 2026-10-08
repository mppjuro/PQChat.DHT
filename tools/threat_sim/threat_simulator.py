#!/usr/bin/env python3
"""
PQChat.DHT - Adversary Traffic Correlation & Anonymity Simulator (Enhanced)
===========================================================================
Models passive and active DHT storage node observers attempting to correlate
sender (PUT) and receiver (GET) IP addresses over time under Ephemeral Key Hopping.

Incorporates:
  (a) Lookahead polling: Receiver polls W future slots (RatchetChain.computeLookaheadSlots)
      prior to sender PUT emission. An adversary observing pre-PUT GET queries correlates
      receiver intent before message publication.
  (b) Decoy GET distinguishability: Stateful adversary filtering targets with 0 PUTs vs
      populated/cover-traffic-backed targets. Demonstrates why synthetic unpopulated decoys
      are filterable and how Poisson cover traffic dummy PUTs restore indistinguishability.
  (c) Multi-message statistical disclosure & intersection attack over M messages.
      Quantifies convergence of candidate receiver intersections as M increases from 1 to 20.
  (d) Sybil / Eclipse attack neighborhood compromise model in Kademlia DHT (K=8 closest replicas).
  (e) Real operational lifecycle intervals (10s active chat, 1m app open, 5m background,
      15m Doze mode; cover traffic active strictly when process is alive / paused in Doze).
  (f) >=100 Monte Carlo repetitions with random seeds, 95% confidence intervals,
      multi-parameter sensitivity analysis, and explicit 1/N random baseline comparison.
  (g) Rigorous terminology avoiding colloquial 'random noise' in favor of CSPRNG padding,
      uncoordinated dummy records, and anonymity set entropy.

Outputs:
  - Quantitative statistical summary with 95% CI and random guessing baseline comparison
  - Sensitivity analysis across lookahead window, decoy ratios, Sybil fractions, and rates
  - 4-panel publication-quality visualization figure saved to tools/threat_sim/ and docs/
"""

import os
import sys
import math
import numpy as np
import matplotlib.pyplot as plt
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple, Dict, Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Set plot styling
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans', 'Arial', 'Helvetica'
plt.rcParams['axes.edgecolor'] = '#cccccc'
plt.rcParams['axes.linewidth'] = 0.8


class LifecycleState(Enum):
    FOREGROUND_CHAT = "FOREGROUND_CHAT"   # 10s interval, process alive, cover traffic active
    APP_ACTIVE_OTHER = "APP_ACTIVE_OTHER" # 60s interval (1m), process alive, cover traffic active
    BACKGROUND_IDLE = "BACKGROUND_IDLE"   # 300s interval (5m), process alive, cover traffic active
    DOZE_SLEEP = "DOZE_SLEEP"             # 900s interval (15m), process suspended, cover traffic OFF


@dataclass
class SimulationConfig:
    num_client_pairs: int = 25          # 50 clients (25 communicating pairs), baseline 1/N = 4.0%
    num_storage_nodes: int = 16         # DHT nodes in observed neighborhood
    sim_duration_sec: float = 3600.0    # 1 hour simulation run
    msg_rate_per_pair_hour: float = 20  # Average 20 messages per pair per hour
    poll_interval_sec: float = 10.0     # Default active foreground chat poll interval (10s)
    bep44_value_bytes: int = 1000       # Exact BEP 44 value payload size (1000 B)
    krpc_put_overhead_bytes: int = 70   # KRPC UDP/Bencode put header overhead (~1070 B total)
    krpc_get_overhead_bytes: int = 150  # KRPC UDP/Bencode get query+response (~150 B)
    rrc_tail_time_sec: float = 8.0      # Cellular modem RRC inactivity timer (8s)
    power_active_mw: float = 1200.0     # Modem active/tail power draw (mW)
    power_idle_mw: float = 10.0         # Modem deep sleep idle power draw (mW)
    dht_replication_k: int = 8          # BEP 44 / Kademlia closest-node replication factor
    lookahead_window_size: int = 4      # W = 5 slots (indices 0..4) as in RatchetChain.kt


@dataclass
class DefenseParameters:
    name: str
    poisson_lambda: float = 0.0         # Events/sec (1/480 = once per 8 min)
    cover_get_ratio: float = 0.0        # Ratio of decoy GETs per real GET (0.0 = none)
    polling_jitter_ratio: float = 0.0   # Jitter as fraction of poll interval (e.g. 0.3 = +-30%)
    put_delay_max_sec: float = 0.0      # Random hold delay for PUT emissions (0.0 = immediate)
    decoy_put_slots: int = 0            # Dummy PUT targets published per message
    lookahead_window_size: int = 4      # Default W = 5 slots (0..4)
    sybil_fraction: float = 0.0         # Fraction of adversary-controlled nodes in DHT
    is_sybil_sweep: bool = False        # Flag indicating explicit Sybil sweep where 0% means 0% compromise
    adversary_uses_lookahead: bool = True # Whether adversary cross-correlates pre-PUT GETs
    filter_zero_put_decoys: bool = False # Adversary filters targets with 0 PUTs
    decoy_target_populated_ratio: float = 0.6 # Fraction of decoys directed to populated/cover slots
    lifecycle_state: LifecycleState = LifecycleState.FOREGROUND_CHAT
    cover_active_in_doze: bool = False  # Suspended during Android Doze mode


@dataclass
class TrialResult:
    top1_accuracy: float
    multi_msg_accuracy: Dict[int, float]
    anonymity_degree: float
    bandwidth_kb_h: float
    battery_energy_mwh: float
    adversary_advantage: float
    delta_ts: List[float]
    corr_by_delta_t: Dict[float, float]


@dataclass
class AggregatedMetrics:
    mean: float
    ci95_lower: float
    ci95_upper: float
    ci95_half: float
    std: float

    def __str__(self):
        return f"{self.mean*100:5.1f}% ± {self.ci95_half*100:4.1f}%"


def compute_ci95(values: List[float]) -> AggregatedMetrics:
    n = len(values)
    mean_val = float(np.mean(values))
    std_val = float(np.std(values, ddof=1)) if n > 1 else 0.0
    half_width = 1.96 * std_val / math.sqrt(n) if n > 1 else 0.0
    return AggregatedMetrics(
        mean=mean_val,
        ci95_lower=max(0.0, mean_val - half_width),
        ci95_upper=mean_val + half_width,
        ci95_half=half_width,
        std=std_val
    )


class EnhancedTrafficSimulator:
    """
    Advanced simulator modeling:
    - Lookahead window polling before sender PUT (pre-PUT correlation)
    - Decoy GET distinguishability & 0-PUT target filtering
    - Multi-message Bayesian statistical disclosure / intersection attack
    - Sybil neighborhood penetration in Kademlia (K=8)
    - Tiered Android lifecycle polling and power profiles
    """

    def __init__(self, cfg: SimulationConfig, defense: DefenseParameters, seed: int = 42):
        self.cfg = cfg
        self.defense = defense
        self.seed = seed
        np.random.seed(seed)

    def run_single_trial(self) -> TrialResult:
        pairs = self.cfg.num_client_pairs
        total_time = self.cfg.sim_duration_sec
        W = self.defense.lookahead_window_size + 1 # windowSize=4 -> 5 slots: 0..4

        # 1. Determine effective poll interval and cover traffic liveness based on lifecycle
        if self.defense.lifecycle_state == LifecycleState.FOREGROUND_CHAT:
            poll_interval = 10.0
            cover_allowed = True
        elif self.defense.lifecycle_state == LifecycleState.APP_ACTIVE_OTHER:
            poll_interval = 60.0
            cover_allowed = True
        elif self.defense.lifecycle_state == LifecycleState.BACKGROUND_IDLE:
            poll_interval = 300.0
            cover_allowed = True
        elif self.defense.lifecycle_state == LifecycleState.DOZE_SLEEP:
            poll_interval = 900.0
            cover_allowed = self.defense.cover_active_in_doze
        else:
            poll_interval = self.cfg.poll_interval_sec
            cover_allowed = True

        all_clients = [f"Alice_{p}" for p in range(pairs)] + [f"Bob_{p}" for p in range(pairs)]
        client_bytes = {c: 0 for c in all_clients}
        client_wakes = {c: [] for c in all_clients}

        # 2. Generate Messages per Pair
        msg_counts = {}
        for p in range(pairs):
            avg_interval = 3600.0 / self.cfg.msg_rate_per_pair_hour
            t = 0.0
            count = 0
            while t < total_time:
                t += np.random.exponential(avg_interval)
                if t < total_time:
                    count += 1
            msg_counts[p] = max(1, count)

        # Calculate network bandwidth and wakeup traces
        pkg_put = self.cfg.bep44_value_bytes + self.cfg.krpc_put_overhead_bytes
        pkg_get = self.cfg.krpc_get_overhead_bytes

        # Bandwidth from real PUTs & decoy PUT slots
        for p in range(pairs):
            s_id = f"Alice_{p}"
            n_msgs = msg_counts[p]
            # Real PUTs
            client_bytes[s_id] += n_msgs * pkg_put
            # Decoy PUT slots
            client_bytes[s_id] += n_msgs * self.defense.decoy_put_slots * pkg_put

        # Bandwidth from Poisson Cover PUTs
        if self.defense.poisson_lambda > 0 and cover_allowed:
            mean_cov_puts = self.defense.poisson_lambda * total_time
            for c in all_clients:
                actual_cov = np.random.poisson(mean_cov_puts)
                client_bytes[c] += actual_cov * pkg_put
                # Sample wakeups for Poisson
                for _ in range(actual_cov):
                    client_wakes[c].append(np.random.uniform(0, total_time))

        # Bandwidth from Polling GETs & Lookahead GETs
        polls_per_receiver = int(total_time / poll_interval)
        for p in range(pairs):
            r_id = f"Bob_{p}"
            # Receiver polls W lookahead slots per poll tick
            client_bytes[r_id] += polls_per_receiver * W * pkg_get
            # Decoy GETs
            if self.defense.cover_get_ratio > 0:
                n_decoy_gets = int(polls_per_receiver * self.defense.cover_get_ratio)
                client_bytes[r_id] += n_decoy_gets * pkg_get

            # Wakeup timestamps
            t_w = np.random.uniform(0, poll_interval)
            while t_w < total_time:
                client_wakes[r_id].append(t_w)
                t_w += poll_interval

        # Bandwidth for Alice wakeups
        for p in range(pairs):
            s_id = f"Alice_{p}"
            for _ in range(msg_counts[p]):
                client_wakes[s_id].append(np.random.uniform(0, total_time))

        # 3. Adversary Inference & Correlation Evaluation
        adversary_stats = self._evaluate_adversary_stochastic(
            pairs=pairs,
            msg_counts=msg_counts,
            poll_interval=poll_interval,
            W=W,
            cover_allowed=cover_allowed
        )

        per_client_bandwidth_kb_h = float(np.mean([client_bytes[c] / 1024.0 for c in all_clients]))
        client_energies = [self._calculate_battery_energy(client_wakes[c], total_time) for c in all_clients]
        per_client_energy_mwh = float(np.mean(client_energies))

        baseline_acc = 1.0 / pairs
        adv_advantage = max(0.0, adversary_stats["top1_accuracy"] - baseline_acc)

        return TrialResult(
            top1_accuracy=adversary_stats["top1_accuracy"],
            multi_msg_accuracy=adversary_stats["multi_msg_accuracy"],
            anonymity_degree=adversary_stats["anonymity_degree"],
            bandwidth_kb_h=per_client_bandwidth_kb_h,
            battery_energy_mwh=per_client_energy_mwh,
            adversary_advantage=adv_advantage,
            delta_ts=adversary_stats["delta_ts"],
            corr_by_delta_t=adversary_stats["corr_by_delta_t"]
        )

    def _evaluate_adversary_stochastic(self, pairs: int, msg_counts: Dict[int, int],
                                       poll_interval: float, W: int, cover_allowed: bool) -> Dict:
        """
        Stochastic evaluation of adversary correlation with lookahead awareness,
        decoy distinguishability, Sybil penetration, and multi-message Bayesian updating.
        """
        window_sec = 30.0
        sybil_f = self.defense.sybil_fraction
        K = self.cfg.dht_replication_k

        # Sybil compromise probability:
        # If is_sybil_sweep is True: p_intercept = 1 - (1 - sybil_f)^K (at 0%, p_intercept = 0.0)
        # Otherwise if sybil_f > 0: p_intercept = 1 - (1 - sybil_f)^K
        # Default (sybil_f == 0, not sweep): p_intercept = 1.0 (designated passive storage node observer)
        if self.defense.is_sybil_sweep:
            p_intercept = 1.0 - (1.0 - sybil_f) ** K
        elif sybil_f > 0.0:
            p_intercept = 1.0 - (1.0 - sybil_f) ** K
        else:
            p_intercept = 1.0

        # Effective active target pool size in DHT
        # S_active = Active conversation slots (pairs * 2) + Poisson dummy slots active
        n_poisson_slots = (self.defense.poisson_lambda * 120.0 * pairs * 2) if (cover_allowed and self.defense.poisson_lambda > 0) else 0.0
        s_active = max(10.0, (pairs * 2.0) + n_poisson_slots)

        # Decoy hit rate on active targets
        # Decoy GETs targeting populated slots survive 0-PUT filtering.
        # Decoys targeting unpopulated synthetic targets have 0 PUTs; filtered if filter_zero_put_decoys is True.
        if self.defense.filter_zero_put_decoys:
            eff_alpha_pop = self.defense.decoy_target_populated_ratio
        else:
            eff_alpha_pop = 1.0 # Naive adversary considers all decoys

        tau_total = window_sec + (W * poll_interval)
        lambda_decoy_hit = ((pairs - 1) * (self.defense.cover_get_ratio * eff_alpha_pop) / poll_interval) * (tau_total / s_active)

        # Decoy PUT slots blur sender emission
        decoy_put_blur = (1.0 / (1.0 + self.defense.decoy_put_slots))

        observed_delta_ts = []
        delta_t_accuracy_pairs = []

        # Candidate likelihoods per message for multi-message evaluation
        pair_message_likelihoods = {p: [] for p in range(pairs)}

        total_msgs = 0
        single_msg_correct = 0
        single_entropies = []
        max_h = math.log2(pairs) if pairs > 1 else 1.0

        for p in range(pairs):
            n_msgs = msg_counts[p]
            for m in range(n_msgs):
                total_msgs += 1

                # Check if target is intercepted by adversary
                is_intercepted = (np.random.random() < p_intercept)
                if not is_intercepted:
                    # Honest storage nodes -> uniform prior (baseline 1/N)
                    uniform_p = np.full(pairs, 1.0 / pairs)
                    pair_message_likelihoods[p].append(uniform_p)
                    # Random guessing on unintercepted slot
                    pred_rand = np.random.randint(pairs)
                    if pred_rand == p:
                        single_msg_correct += 1
                    single_entropies.append(1.0) # Maximum entropy
                    continue

                weights = np.full(pairs, 1e-4)

                # 1. True Receiver Bob_p
                # Jitter impact
                j_ratio = self.defense.polling_jitter_ratio
                if j_ratio > 0:
                    j_val = np.random.uniform(-j_ratio, j_ratio)
                    eff_interval = max(1.0, poll_interval * (1.0 + j_val))
                else:
                    eff_interval = poll_interval

                # Delayed PUT impact
                t_put_delay = np.random.uniform(0, self.defense.put_delay_max_sec) if self.defense.put_delay_max_sec > 0 else 0.0

                dt_post = np.random.uniform(0.0, eff_interval)
                dt_pre = -np.random.uniform(0.0, W * eff_interval)

                w_post = math.exp(-dt_post / poll_interval) * decoy_put_blur
                observed_delta_ts.append(dt_post)

                if self.defense.adversary_uses_lookahead:
                    # Pre-PUT lookahead correlation weight
                    w_pre = 0.85 * math.exp(dt_pre / (W * poll_interval)) * decoy_put_blur
                    observed_delta_ts.append(dt_pre)
                    weights[p] = w_post + w_pre
                else:
                    weights[p] = w_post

                # 2. Decoy GET queries hitting this target from other receivers
                if self.defense.cover_get_ratio > 0:
                    n_hits = np.random.poisson(lambda_decoy_hit)
                    for _ in range(n_hits):
                        decoy_r = np.random.choice([i for i in range(pairs) if i != p])
                        dt_decoy = np.random.uniform(-W * poll_interval, window_sec)
                        if dt_decoy >= 0:
                            w_d = math.exp(-dt_decoy / poll_interval)
                        else:
                            if self.defense.adversary_uses_lookahead:
                                w_d = 0.85 * math.exp(dt_decoy / (W * poll_interval))
                            else:
                                w_d = 0.0
                        weights[decoy_r] += w_d
                        observed_delta_ts.append(dt_decoy)

                # Normalize to probability distribution
                probs = weights / np.sum(weights)
                pair_message_likelihoods[p].append(probs)

                pred_idx = int(np.argmax(probs))
                sorted_p = np.sort(probs)[::-1]
                is_correct = (pred_idx == p)
                if len(sorted_p) > 1 and (sorted_p[0] - sorted_p[1]) < 0.10:
                    is_correct = False

                if is_correct:
                    single_msg_correct += 1

                # Normalized Shannon entropy
                h = -np.sum([pr * math.log2(pr) for pr in probs if pr > 0])
                single_entropies.append(h / max_h)

                delta_t_accuracy_pairs.append((dt_post, is_correct))
                if self.defense.adversary_uses_lookahead:
                    delta_t_accuracy_pairs.append((dt_pre, is_correct))

        top1_accuracy = single_msg_correct / max(1, total_msgs)
        anonymity_degree = float(np.mean(single_entropies)) if single_entropies else 0.0

        # Multi-Message Bayesian Statistical Disclosure (Intersection Attack)
        multi_msg_accuracy = {}
        for M in [1, 2, 5, 10, 20]:
            correct_m = 0
            evaluated_pairs = 0
            for p in range(pairs):
                p_likelihoods = pair_message_likelihoods[p]
                if len(p_likelihoods) < M:
                    continue
                evaluated_pairs += 1
                accum_log = np.zeros(pairs)
                for m_idx in range(M):
                    accum_log += np.log(p_likelihoods[m_idx] + 1e-9)

                max_l = np.max(accum_log)
                exp_p = np.exp(accum_log - max_l)
                post_p = exp_p / np.sum(exp_p)

                pred_m = int(np.argmax(post_p))
                sorted_post = np.sort(post_p)[::-1]
                if pred_m == p and (len(sorted_post) <= 1 or (sorted_post[0] - sorted_post[1]) >= 0.08):
                    correct_m += 1

            multi_msg_accuracy[M] = correct_m / max(1, evaluated_pairs)

        # Binned P(corr) vs delta_t
        corr_by_delta_t = {}
        bins = np.linspace(-30.0, 30.0, 13)
        for i in range(len(bins) - 1):
            b_min, b_max = bins[i], bins[i+1]
            in_bin = [corr for dt, corr in delta_t_accuracy_pairs if b_min <= dt < b_max]
            b_mid = (b_min + b_max) / 2.0
            corr_by_delta_t[b_mid] = float(np.mean(in_bin)) if in_bin else 0.0

        return {
            "top1_accuracy": top1_accuracy,
            "multi_msg_accuracy": multi_msg_accuracy,
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


def run_monte_carlo(cfg: SimulationConfig, defense: DefenseParameters,
                     num_runs: int = 100, base_seed: int = 1000) -> Dict:
    """Runs >=100 Monte Carlo simulation runs with distinct deterministic seeds."""
    top1_list = []
    anon_list = []
    bw_list = []
    energy_list = []
    adv_list = []
    multi_m_lists = {1: [], 2: [], 5: [], 10: [], 20: []}
    corr_by_dt_samples = {}

    for i in range(num_runs):
        sim = EnhancedTrafficSimulator(cfg, defense, seed=base_seed + i)
        res = sim.run_single_trial()

        top1_list.append(res.top1_accuracy)
        anon_list.append(res.anonymity_degree)
        bw_list.append(res.bandwidth_kb_h)
        energy_list.append(res.battery_energy_mwh)
        adv_list.append(res.adversary_advantage)

        for m_key in multi_m_lists.keys():
            if m_key in res.multi_msg_accuracy:
                multi_m_lists[m_key].append(res.multi_msg_accuracy[m_key])

        for dt_val, corr_p in res.corr_by_delta_t.items():
            corr_by_dt_samples.setdefault(dt_val, []).append(corr_p)

    corr_by_dt_agg = {}
    for dt_val, p_list in corr_by_dt_samples.items():
        corr_by_dt_agg[dt_val] = float(np.mean(p_list))

    multi_m_agg = {m: compute_ci95(v_list) for m, v_list in multi_m_lists.items()}

    return {
        "top1": compute_ci95(top1_list),
        "anonymity": compute_ci95(anon_list),
        "bandwidth": compute_ci95(bw_list),
        "energy": compute_ci95(energy_list),
        "advantage": compute_ci95(adv_list),
        "multi_m": multi_m_agg,
        "corr_by_delta_t": corr_by_dt_agg
    }


def execute_full_threat_evaluation(num_runs: int = 100):
    """
    Main execution routine for enhanced threat evaluation:
    1. Evaluates 5 Defense Postures with 100 runs & 95% CIs.
    2. Evaluates Lookahead Threat (pre-PUT correlation).
    3. Evaluates Decoy GET 0-PUT filterability.
    4. Evaluates Multi-Message Intersection Attack convergence.
    5. Sweeps Sybil / Eclipse penetration fractions.
    6. Sweeps Lifecycle states (10s, 60s, 300s, 900s with cover traffic paused in Doze).
    7. Sweeps Poisson Cover Rate lambda.
    8. Generates publication-quality 4-panel figure.
    """
    print("=" * 84)
    print(" PQChat.DHT - Enhanced Threat Model & Adversary Correlation Simulator")
    print(f" Monte Carlo Repetitions: N = {num_runs} with Random Seeds (1000..{1000 + num_runs - 1})")
    print("=" * 84)

    cfg = SimulationConfig(num_client_pairs=25)
    random_baseline_pct = (1.0 / cfg.num_client_pairs) * 100.0

    print(f"\n[Theoretical Baseline] Random Guessing across N = {cfg.num_client_pairs} Pairs: "
          f"1/N = {random_baseline_pct:.1f}%\n")

    # 1. Standard Defense Postures Evaluation
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

    print("--- 1. Evaluating Defense Postures (N=100 Runs with 95% Confidence Intervals) ---")
    posture_results = []
    for d in defenses:
        agg = run_monte_carlo(cfg, d, num_runs=num_runs)
        posture_results.append((d, agg))
        print(f"[{d.name:36s}] "
              f"Top-1: {agg['top1'].mean*100:5.1f}% ± {agg['top1'].ci95_half*100:4.1f}% | "
              f"Adv vs 1/N: +{agg['advantage'].mean*100:4.1f}% | "
              f"Anonymity: {agg['anonymity'].mean*100:5.1f}% ± {agg['anonymity'].ci95_half*100:4.1f}% | "
              f"BW: {agg['bandwidth'].mean:5.1f} KB/h | "
              f"Energy: {agg['energy'].mean:5.1f} mWh")

    # 2. Lookahead Pre-PUT Correlation Threat Analysis
    print("\n--- 2. Lookahead Pre-Polling Threat Analysis (RatchetChain W=5 Future Slots) ---")
    d_post_only = DefenseParameters(
        name="Decoys (Post-PUT Observer Only)",
        cover_get_ratio=1.5,
        polling_jitter_ratio=0.3,
        adversary_uses_lookahead=False
    )
    d_lookahead_aware = DefenseParameters(
        name="Decoys (Lookahead-Aware Observer)",
        cover_get_ratio=1.5,
        polling_jitter_ratio=0.3,
        adversary_uses_lookahead=True
    )
    for d_look in [d_post_only, d_lookahead_aware]:
        agg = run_monte_carlo(cfg, d_look, num_runs=min(num_runs, 50))
        print(f"[{d_look.name:38s}] "
              f"Top-1: {agg['top1'].mean*100:5.1f}% ± {agg['top1'].ci95_half*100:4.1f}% | "
              f"Advantage: +{agg['advantage'].mean*100:4.1f}% | "
              f"Anonymity: {agg['anonymity'].mean*100:5.1f}%")

    # 3. Decoy GET Distinguishability Analysis (Stateful 0-PUT Target Filter)
    print("\n--- 3. Decoy GET Distinguishability Analysis (Stateful 0-PUT Target Filter) ---")
    d_nofilter = DefenseParameters(
        name="Decoys (Naive Observer, No Filter)",
        cover_get_ratio=1.5,
        polling_jitter_ratio=0.3,
        filter_zero_put_decoys=False,
        decoy_target_populated_ratio=0.0 # pure synthetic
    )
    d_filter_pure = DefenseParameters(
        name="Decoys (0-PUT Filter, Pure Synth)",
        cover_get_ratio=1.5,
        polling_jitter_ratio=0.3,
        filter_zero_put_decoys=True,
        decoy_target_populated_ratio=0.0 # pure synthetic -> 100% filtered out!
    )
    d_filter_cover = DefenseParameters(
        name="Decoys + Poisson Cover (0-PUT Filter)",
        poisson_lambda=1.0 / 480.0,
        cover_get_ratio=1.5,
        polling_jitter_ratio=0.3,
        filter_zero_put_decoys=True,
        decoy_target_populated_ratio=0.6 # populated & cover dummy targets
    )
    for test_d in [d_nofilter, d_filter_pure, d_filter_cover]:
        agg = run_monte_carlo(cfg, test_d, num_runs=min(num_runs, 50))
        print(f"[{test_d.name:42s}] "
              f"Top-1: {agg['top1'].mean*100:5.1f}% ± {agg['top1'].ci95_half*100:4.1f}% | "
              f"Advantage: +{agg['advantage'].mean*100:4.1f}% | "
              f"Anonymity: {agg['anonymity'].mean*100:5.1f}%")

    # 4. Multi-Message Statistical Disclosure / Intersection Attack Convergence
    print("\n--- 4. Multi-Message Statistical Disclosure (Intersection Attack Convergence) ---")
    m_eval_sizes = [1, 2, 5, 10, 20]
    multi_msg_summary = {}
    for d, agg in [posture_results[0], posture_results[2], posture_results[4]]:
        row_str = f"[{d.name:36s}] "
        multi_msg_summary[d.name] = []
        for m in m_eval_sizes:
            m_res = agg["multi_m"][m]
            multi_msg_summary[d.name].append(m_res.mean * 100.0)
            row_str += f"M={m:2d}: {m_res.mean*100:5.1f}% | "
        print(row_str)

    # 5. Sybil / Eclipse Neighborhood Penetration Sweep
    print("\n--- 5. Sybil / Eclipse Neighborhood Penetration Sweep (K=8 Closest Replicas) ---")
    sybil_fractions = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]
    sybil_results = []
    for sf in sybil_fractions:
        d_sybil = DefenseParameters(
            name=f"Sybil {sf*100:.0f}%",
            poisson_lambda=1.0 / 480.0,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            sybil_fraction=sf,
            is_sybil_sweep=True
        )
        agg = run_monte_carlo(cfg, d_sybil, num_runs=min(num_runs, 50))
        p_comp = (1.0 - (1.0 - sf) ** cfg.dht_replication_k) * 100.0 if sf > 0 else 0.0
        sybil_results.append((sf, p_comp, agg))
        print(f"Sybil fraction: {sf*100:4.1f}% -> P(target compromised): {p_comp:5.1f}% | "
              f"Top-1: {agg['top1'].mean*100:5.1f}% ± {agg['top1'].ci95_half*100:4.1f}% | "
              f"Advantage: +{agg['advantage'].mean*100:4.1f}%")

    # 6. Lifecycle States & Process Liveness
    print("\n--- 6. Lifecycle Tiering & Process Liveness (Doze Mode Cover Inactive) ---")
    lifecycle_states = [
        LifecycleState.FOREGROUND_CHAT,
        LifecycleState.APP_ACTIVE_OTHER,
        LifecycleState.BACKGROUND_IDLE,
        LifecycleState.DOZE_SLEEP
    ]
    lifecycle_labels = ["10s Foreground Chat", "1m App Active", "5m Background Idle", "15m Doze Sleep (Cover OFF)"]
    lifecycle_metrics = []
    for l_state, l_label in zip(lifecycle_states, lifecycle_labels):
        d_life = DefenseParameters(
            name=l_label,
            poisson_lambda=1.0 / 480.0,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1,
            lifecycle_state=l_state,
            cover_active_in_doze=False
        )
        agg = run_monte_carlo(cfg, d_life, num_runs=min(num_runs, 50))
        lifecycle_metrics.append((l_label, agg))
        print(f"[{l_label:32s}] "
              f"Top-1: {agg['top1'].mean*100:5.1f}% | "
              f"Bandwidth: {agg['bandwidth'].mean:6.1f} KB/h | "
              f"Energy: {agg['energy'].mean:5.1f} mWh")

    # 7. Sweeping Poisson Cover Traffic Rate (Lambda)
    print("\n--- 7. Sweeping Poisson Cover Traffic Rate (Lambda) ---")
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
    lambda_labels = ["Off", "30m", "15m", "10m", "8m (Default)", "4m", "2m", "1m", "30s", "15s"]

    sweep_accuracy = []
    sweep_anonymity = []
    sweep_bandwidth = []
    sweep_energy = []
    sweep_ci_acc = []

    for l_val, l_label in zip(lambda_values, lambda_labels):
        d_sw = DefenseParameters(
            name=f"Lambda {l_label}",
            poisson_lambda=l_val,
            cover_get_ratio=1.5,
            polling_jitter_ratio=0.3,
            put_delay_max_sec=5.0,
            decoy_put_slots=1
        )
        agg = run_monte_carlo(cfg, d_sw, num_runs=min(num_runs, 50))
        sweep_accuracy.append(agg['top1'].mean)
        sweep_ci_acc.append(agg['top1'].ci95_half)
        sweep_anonymity.append(agg['anonymity'].mean)
        sweep_bandwidth.append(agg['bandwidth'].mean)
        sweep_energy.append(agg['energy'].mean)

        print(f"Lambda = {l_val:8.5f} ({l_label:12s}) -> "
              f"Top-1: {agg['top1'].mean*100:5.1f}% ± {agg['top1'].ci95_half*100:4.1f}% | "
              f"Anonymity: {agg['anonymity'].mean*100:5.1f}% | "
              f"Bandwidth: {agg['bandwidth'].mean:6.1f} KB/h | Energy: {agg['energy'].mean:5.1f} mWh")

    # 8. Generate 4-Panel Visualization Figure
    output_dir_tools = os.path.dirname(os.path.abspath(__file__))
    output_dir_docs = os.path.abspath(os.path.join(output_dir_tools, "..", "..", "docs"))
    os.makedirs(output_dir_docs, exist_ok=True)

    fig_path_tools = os.path.join(output_dir_tools, "tradeoff_anonymity_bandwidth_battery.png")
    fig_path_docs = os.path.join(output_dir_docs, "tradeoff_anonymity_bandwidth_battery.png")

    fig, axs = plt.subplots(2, 2, figsize=(16, 12), dpi=300)
    ((ax_dt, ax_bar), (ax_inter, ax_res)) = axs

    # Panel 1 (Top-Left): P(Correlation) vs Delta_t (incorporating Lookahead: Delta_t < 0 and Delta_t > 0)
    colors_dt = ['#e53935', '#fb8c00', '#1e88e5', '#8e24aa', '#2e7d32']
    for idx, (def_param, agg_res) in enumerate(posture_results):
        cdict = agg_res["corr_by_delta_t"]
        if cdict:
            dts = sorted(cdict.keys())
            probs = [cdict[t] * 100 for t in dts]
            ax_dt.plot(dts, probs, marker='o', markersize=4.5, linewidth=2.0, color=colors_dt[idx],
                       label=def_param.name.split('(')[0].strip())

    ax_dt.axvline(x=0.0, color='#333333', linestyle=':', alpha=0.8, label=r'PUT Emission ($t_{\mathrm{PUT}}$)')
    ax_dt.axhline(y=random_baseline_pct, color='#555555', linestyle='--', alpha=0.7,
                  label=f'Random Baseline 1/N ({random_baseline_pct:.1f}%)')
    ax_dt.set_xlabel(r'Arrival Time Gap $\Delta t = t_{\mathrm{GET}} - t_{\mathrm{PUT}}$ (seconds)' + '\n' +
                     r'[Lookahead Pre-Polling: $\Delta t < 0$ | Post-PUT Fetch: $\Delta t > 0$]',
                     fontsize=9.5, fontweight='bold')
    ax_dt.set_ylabel(r'Correlation Success $P(\mathrm{corr} \mid \Delta t)$ (%)', fontsize=9.5, fontweight='bold')
    ax_dt.set_title(r'A. Timing Correlation Success vs $\Delta t$ (with Lookahead)', fontsize=11, fontweight='bold')
    ax_dt.set_ylim(-5, 105)
    ax_dt.legend(loc='upper right', fontsize=8.0, framealpha=0.92)
    ax_dt.grid(True, linestyle='--', alpha=0.5)

    # Panel 2 (Top-Right): Defense Posture Comparison with 95% Confidence Interval Error Bars
    posture_names = [
        "Baseline\n(No Defense)",
        "+ Polling\nJitter (±30%)",
        "+ Decoy GETs\n(Ratio 1.5)",
        "+ Delayed PUT\n& Decoy Slots",
        "Full Defense\n(+ Poisson)"
    ]
    posture_top1 = [d[1]['top1'].mean * 100 for d in posture_results]
    posture_top1_err = [d[1]['top1'].ci95_half * 100 for d in posture_results]
    posture_anon = [d[1]['anonymity'].mean * 100 for d in posture_results]
    posture_anon_err = [d[1]['anonymity'].ci95_half * 100 for d in posture_results]

    x = np.arange(len(posture_names))
    width = 0.35

    ax_bar.bar(x - width/2, posture_top1, width, yerr=posture_top1_err, capsize=4,
               label='Adversary Top-1 Accuracy (%)', color='#e53935', alpha=0.88)
    ax_bar.bar(x + width/2, posture_anon, width, yerr=posture_anon_err, capsize=4,
               label='Degree of Anonymity (Entropy %)', color='#1e88e5', alpha=0.88)
    ax_bar.axhline(y=random_baseline_pct, color='#333333', linestyle='--', linewidth=1.5,
                   label=f'Random Baseline 1/N ({random_baseline_pct:.1f}%)')

    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(posture_names, fontsize=8.5)
    ax_bar.set_ylabel('Metric Score (%)', fontsize=9.5, fontweight='bold')
    ax_bar.set_title(r'B. Defense Mechanisms Impact (with 95% CI & $1/N$ Baseline)', fontsize=11, fontweight='bold')
    ax_bar.set_ylim(0, 115)
    ax_bar.legend(loc='upper right', fontsize=8.0, framealpha=0.92)
    ax_bar.grid(True, linestyle='--', alpha=0.5)

    # Panel 3 (Bottom-Left): Multi-Message Statistical Disclosure (Intersection Attack Convergence)
    m_ticks = np.array(m_eval_sizes)
    ax_inter.plot(m_ticks, multi_msg_summary["Baseline (No Defenses)"],
                  marker='s', linewidth=2.4, color='#e53935', label='Baseline (Immediate Disclosure)')
    ax_inter.plot(m_ticks, multi_msg_summary["+ Decoy GETs (Ratio 1.5)"],
                  marker='^', linewidth=2.2, color='#fb8c00', label='Decoys Only (Slow Intersection)')
    ax_inter.plot(m_ticks, multi_msg_summary["Full Defense (All + Poisson 1/480s)"],
                  marker='o', linewidth=2.5, color='#2e7d32', label='Full Defense (+ Poisson Cover Traffic)')
    ax_inter.axhline(y=random_baseline_pct, color='#555555', linestyle='--',
                     label=f'Random Baseline 1/N ({random_baseline_pct:.1f}%)')

    ax_inter.set_xticks(m_ticks)
    ax_inter.set_xlabel(r'Number of Consecutive Messages Observed ($M$)', fontsize=9.5, fontweight='bold')
    ax_inter.set_ylabel(r'Adversary Cumulative Top-1 Accuracy (%)', fontsize=9.5, fontweight='bold')
    ax_inter.set_title(r'C. Statistical Disclosure / Intersection Attack vs $M$', fontsize=11, fontweight='bold')
    ax_inter.set_ylim(-5, 105)
    ax_inter.legend(loc='center right', fontsize=8.2, framealpha=0.92)
    ax_inter.grid(True, linestyle='--', alpha=0.5)

    # Panel 4 (Bottom-Right): Resource Trade-off across Poisson Rates
    ax_res_twin = ax_res.twinx()
    x_indices = np.arange(len(lambda_values))

    p1 = ax_res.plot(x_indices, sweep_bandwidth, marker='D', linewidth=2.2, color='#3949ab',
                     label='UDP Bandwidth (KB/h)')
    p2 = ax_res_twin.plot(x_indices, sweep_energy, marker='v', linewidth=2.2, color='#ef6c00',
                          label='Modem Power (mWh/h)')

    ax_res.set_xticks(x_indices)
    ax_res.set_xticklabels(lambda_labels, rotation=35, ha='right', fontsize=8.0)
    ax_res.set_xlabel(r'Poisson Cover Traffic Rate $\lambda$ (Mean Interval)', fontsize=9.5, fontweight='bold')
    ax_res.set_ylabel('UDP Bandwidth (KB / hour)', fontsize=9.5, fontweight='bold', color='#3949ab')
    ax_res_twin.set_ylabel('Modem Energy (mWh / hour)', fontsize=9.5, fontweight='bold', color='#ef6c00')
    ax_res.tick_params(axis='y', labelcolor='#3949ab')
    ax_res_twin.tick_params(axis='y', labelcolor='#ef6c00')

    ax_res.set_title('D. Bandwidth & Battery Cost across Poisson Rates', fontsize=11, fontweight='bold')
    ax_res.grid(True, linestyle='--', alpha=0.5)

    lines = p1 + p2
    labels = [l.get_label() for l in lines]
    ax_res.legend(lines, labels, loc='upper left', fontsize=8.0, framealpha=0.92)

    plt.tight_layout()
    plt.savefig(fig_path_tools, dpi=300)
    plt.savefig(fig_path_docs, dpi=300)
    plt.close()

    print(f"\n[Generated Publication-Quality Visualizations]")
    print(f" -> {fig_path_tools}")
    print(f" -> {fig_path_docs}")
    print("\nSimulation completed successfully.")


if __name__ == "__main__":
    runs = 100
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        runs = int(sys.argv[1])
    execute_full_threat_evaluation(num_runs=runs)
