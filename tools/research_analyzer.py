#!/usr/bin/env python3
"""
tools/research_analyzer.py — Academic Research Telemetry Analyzer for Master's Thesis.

Reads research telemetry CSV and JSON bundles exported from PQChat DHT devices or Firebase,
calculates mathematical, statistical, and empirical metrics, and generates publication-ready
LaTeX tables and visualization charts.

Metrics evaluated:
1. Traffic Shaping & Anonymity Efficacy:
   - Empirical inter-packet time intervals (mean, variance, CV, Kolmogorov-Smirnov D statistic vs Poisson Exp(lambda))
   - Traffic mix percentage (REAL_MSG, COVER_DUMMY, BLIND_REPUBLISH, DECOY_GET, TOMBSTONE_900B)
   - Shannon entropy of Target ID prefix distribution H(X) and normalized uniformity (%)
2. BEP 44 Retention & Survival Curves:
   - Survival rate in function of elapsed time (5m, 1h, 2h, 6h, 12h, 24h, 48h) comparing with vs without republish
   - Responding node counts and Ed25519 valid signature response ratios
3. Network Transport RTT Percentiles:
   - RTT distributions (p50, p90, p99, min, max, avg) partitioned by network environment (WIFI, LTE, CGNAT, TOR_SOCKS5)
   - Chunk transfer resumption success rates
4. Group Chat Scalability:
   - Delivery latency vs group size M
   - Fan-out delivery skew (Delta t_skew)
   - Group key rotation convergence time (GROUP_SUBTYPE_REKEY)
"""

import argparse
import csv
import json
import math
import os
import sys
import zipfile
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

# Optional matplotlib for publication charts
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def compute_ks_exponential(samples: List[float]) -> Tuple[float, float, float, float]:
    """
    Computes empirical mean, variance, CV, and Kolmogorov-Smirnov D statistic
    against an exponential distribution F(x) = 1 - exp(-lambda * x) where lambda = 1 / mean.
    Samples should be non-negative intervals.
    """
    n = len(samples)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    mean_val = sum(samples) / n
    if n < 2 or mean_val <= 0.0:
        return mean_val, 0.0, 0.0, 0.0

    var_val = sum((x - mean_val) ** 2 for x in samples) / (n - 1)
    std_val = math.sqrt(var_val)
    cv = std_val / mean_val if mean_val > 0.0 else 0.0

    # Rate parameter lambda_hat
    rate_hat = 1.0 / mean_val
    sorted_samples = sorted(samples)

    max_d = 0.0
    for i, x in enumerate(sorted_samples):
        # Theoretical CDF
        f_theo = 1.0 - math.exp(-rate_hat * x)
        fn_upper = (i + 1) / n
        fn_lower = i / n
        d_plus = abs(fn_upper - f_theo)
        d_minus = abs(f_theo - fn_lower)
        max_d = max(max_d, d_plus, d_minus)

    return mean_val, var_val, cv, max_d


def compute_shannon_entropy(target_prefixes: List[str]) -> Tuple[float, float]:
    """
    Computes Shannon entropy of target ID prefix distribution over the first byte (0..255).
    Max theoretical entropy is log2(256) = 8.0 bits.
    Returns (entropy_bits, normalized_uniformity_percent).
    """
    counts = defaultdict(int)
    total = 0
    for p in target_prefixes:
        if len(p) >= 2:
            try:
                byte_val = int(p[:2], 16)
                counts[byte_val] += 1
                total += 1
            except ValueError:
                pass
    if total == 0:
        return 0.0, 0.0

    entropy = 0.0
    for byte_val, c in counts.items():
        if c > 0:
            prob = c / total
            entropy -= prob * math.log2(prob)

    normalized_pct = (entropy / 8.0) * 100.0
    return entropy, normalized_pct


def compute_percentiles(values: List[float]) -> Dict[str, float]:
    """
    Computes min, max, avg, p50, p90, p99 for a list of numeric samples.
    """
    if not values:
        return {"count": 0, "min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}
    sorted_v = sorted(values)
    n = len(sorted_v)
    return {
        "count": n,
        "min": sorted_v[0],
        "max": sorted_v[-1],
        "avg": sum(sorted_v) / n,
        "p50": sorted_v[min(int(n * 0.50), n - 1)],
        "p90": sorted_v[min(int(n * 0.90), n - 1)],
        "p99": sorted_v[min(int(n * 0.99), n - 1)],
    }


class ResearchDataset:
    def __init__(self):
        self.packet_events: List[Dict[str, Any]] = []
        self.ttl_samples: List[Dict[str, Any]] = []
        self.group_events: List[Dict[str, Any]] = []
        self.republish_summaries: List[Dict[str, Any]] = []
        self.resource_samples: List[Dict[str, Any]] = []
        self.manifest: Optional[Dict[str, Any]] = None

    def load_from_directory_or_zip(self, path: str):
        if os.path.isfile(path) and path.endswith(".zip"):
            self._load_from_zip(path)
        elif os.path.isdir(path):
            self._load_from_dir(path)
        else:
            raise ValueError(f"Invalid input path: {path} (must be directory or .zip file)")

    def _load_from_zip(self, zip_path: str):
        with zipfile.ZipFile(zip_path, "r") as z:
            for name in z.namelist():
                content = z.read(name).decode("utf-8", errors="replace")
                self._parse_file_content(name, content)

    def _load_from_dir(self, dir_path: str):
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    self._parse_file_content(file, content)
                except Exception as e:
                    print(f"Warning: could not read {file_path}: {e}", file=sys.stderr)

    def _parse_file_content(self, filename: str, content: str):
        if filename == "session_manifest.json":
            try:
                self.manifest = json.loads(content)
            except Exception:
                pass
            return

        lines = content.strip().splitlines()
        if not lines:
            return
        reader = csv.DictReader(lines)

        if "packet_events" in filename:
            for row in reader:
                self.packet_events.append(row)
        elif "ttl_samples" in filename:
            for row in reader:
                self.ttl_samples.append(row)
        elif "group_events" in filename:
            for row in reader:
                self.group_events.append(row)
        elif "republish_analysis" in filename:
            for row in reader:
                self.republish_summaries.append(row)
        elif "resource_profile" in filename:
            for row in reader:
                self.resource_samples.append(row)
        elif "master" in filename:
            # Fallback parsing from master CSV if individual CSVs were absent
            for row in reader:
                rec_type = row.get("record_type", "")
                if rec_type == "PACKET_EVENT":
                    self.packet_events.append(row)
                elif rec_type == "TTL_SAMPLE":
                    self.ttl_samples.append(row)
                elif rec_type == "GROUP_EVENT":
                    self.group_events.append(row)


class ResearchAnalyzer:
    def __init__(self, dataset: ResearchDataset, output_dir: str):
        self.dataset = dataset
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def analyze_traffic_shaping(self) -> Dict[str, Any]:
        """
        Analyzes traffic shaping intervals, mix percentages, and Shannon entropy.
        """
        outbound_roles = {
            "FIRST_SEND", "OWN_REPUBLISH", "CROWD_REPUBLISH",
            "TOMBSTONE_SENT", "COVER_ACK_SENT", "COVER_DUMMY_SENT", "DECOY_GET"
        }

        # Filter outbound packet events sorted by timestamp
        outbound = []
        for p in self.dataset.packet_events:
            role = p.get("role") or p.get("packet_role") or ""
            if role in outbound_roles:
                try:
                    ts = int(p.get("timestampEpochMs") or p.get("timestamp_epoch_ms") or 0)
                    outbound.append((ts, role, p.get("targetPrefix") or p.get("target_prefix") or ""))
                except ValueError:
                    pass

        outbound.sort(key=lambda x: x[0])

        intervals_ms = []
        for i in range(1, len(outbound)):
            dt = outbound[i][0] - outbound[i - 1][0]
            if dt >= 0:
                intervals_ms.append(float(dt))

        intervals_sec = [x / 1000.0 for x in intervals_ms]
        mean_sec, var_sec, cv, ks_d = compute_ks_exponential(intervals_sec)

        # Traffic mix
        total_out = len(outbound)
        role_counts = defaultdict(int)
        for _, role, _ in outbound:
            role_counts[role] += 1

        real_count = role_counts["FIRST_SEND"]
        dummy_count = role_counts["COVER_DUMMY_SENT"]
        blind_count = role_counts["CROWD_REPUBLISH"]
        decoy_count = role_counts["DECOY_GET"]
        tomb_count = role_counts["TOMBSTONE_SENT"]
        ack_count = role_counts["COVER_ACK_SENT"]

        mix_pct = {
            "REAL_MSG": (real_count / total_out * 100.0) if total_out > 0 else 0.0,
            "COVER_DUMMY": (dummy_count / total_out * 100.0) if total_out > 0 else 0.0,
            "BLIND_REPUBLISH": (blind_count / total_out * 100.0) if total_out > 0 else 0.0,
            "DECOY_GET": (decoy_count / total_out * 100.0) if total_out > 0 else 0.0,
            "TOMBSTONE_900B": (tomb_count / total_out * 100.0) if total_out > 0 else 0.0,
            "COVER_ACK": (ack_count / total_out * 100.0) if total_out > 0 else 0.0,
        }

        # Shannon entropy
        prefixes = [x[2] for x in outbound if x[2]]
        entropy_bits, entropy_norm = compute_shannon_entropy(prefixes)

        return {
            "total_outbound": total_out,
            "sample_intervals_count": len(intervals_ms),
            "mean_interval_sec": mean_sec,
            "variance_interval_sec": var_sec,
            "cv": cv,
            "kolmogorov_smirnov_d": ks_d,
            "role_counts": dict(role_counts),
            "mix_percentage": mix_pct,
            "entropy_bits": entropy_bits,
            "entropy_normalized_pct": entropy_norm,
            "intervals_sec": intervals_sec,
        }

    def analyze_network_rtt(self) -> Dict[str, Dict[str, float]]:
        """
        Analyzes RTT percentiles partitioned by network environment.
        """
        by_network = defaultdict(list)
        for p in self.dataset.packet_events:
            net = p.get("networkType") or p.get("network_type") or "UNKNOWN"
            try:
                rtt = float(p.get("rttMs") or p.get("rtt_ms") or 0.0)
                if rtt > 0.0:
                    by_network[net].append(rtt)
            except ValueError:
                pass

        results = {}
        for net, rtts in by_network.items():
            results[net] = compute_percentiles(rtts)
        return results

    def analyze_retention_survival(self) -> List[Dict[str, Any]]:
        """
        Analyzes BEP 44 survival curves across time horizons.
        """
        horizons = [
            ("5m", 5.0 / 60.0),
            ("1h", 1.0),
            ("2h", 2.0),
            ("6h", 6.0),
            ("12h", 12.0),
            ("24h", 24.0),
            ("48h", 48.0),
        ]

        parsed_samples = []
        for s in self.dataset.ttl_samples:
            try:
                hours = float(s.get("elapsedHours") or s.get("elapsed_hours") or 0.0)
                alive_str = str(s.get("isAlive") or s.get("is_alive") or "false").lower()
                is_alive = alive_str in ("true", "1", "yes")
                repub_str = str(s.get("republishActive") or s.get("republish_active") or "false").lower()
                repub = repub_str in ("true", "1", "yes")
                q_nodes = int(s.get("nodesQueried") or s.get("nodes_queried") or 0)
                r_nodes = int(s.get("nodesResponded") or s.get("nodes_responded") or 0)
                parsed_samples.append((hours, is_alive, repub, q_nodes, r_nodes))
            except ValueError:
                pass

        results = []
        for label, h in horizons:
            for repub in [False, True]:
                # Tolerance window around horizon
                matching = [
                    s for s in parsed_samples
                    if s[2] == repub and abs(s[0] - h) <= max(0.05, h * 0.40)
                ]
                total = len(matching)
                alive = sum(1 for s in matching if s[1])
                rate = (alive / total * 100.0) if total > 0 else 0.0
                avg_q = (sum(s[3] for s in matching) / total) if total > 0 else 0.0
                avg_r = (sum(s[4] for s in matching) / total) if total > 0 else 0.0

                results.append({
                    "horizon_label": label,
                    "horizon_hours": h,
                    "republish_active": repub,
                    "total_samples": total,
                    "alive_samples": alive,
                    "survival_rate_pct": rate,
                    "avg_nodes_queried": avg_q,
                    "avg_nodes_responded": avg_r,
                })
        return results

    def analyze_group_chat(self) -> Dict[str, Any]:
        """
        Analyzes group chat latency, fan-out skew, and key rotation convergence.
        """
        latencies_by_size = defaultdict(list)
        skews = []
        rekeys = []

        for g in self.dataset.group_events:
            try:
                size = int(g.get("groupSizeM") or g.get("group_size_m") or 0)
                lat = float(g.get("latencyMs") or g.get("latency_ms") or 0.0)
                skew = float(g.get("fanOutSkewMs") or g.get("fan_out_skew_ms") or 0.0)
                rekey = float(g.get("keyRotationConvergenceMs") or g.get("key_rotation_convergence_ms") or 0.0)

                if size > 0 and lat > 0:
                    latencies_by_size[size].append(lat)
                if skew > 0:
                    skews.append(skew)
                if rekey > 0:
                    rekeys.append(rekey)
            except ValueError:
                pass

        latency_summary = {}
        for size, lats in latencies_by_size.items():
            latency_summary[size] = {
                "count": len(lats),
                "avg_ms": sum(lats) / len(lats),
                "p50_ms": sorted(lats)[min(int(len(lats) * 0.5), len(lats) - 1)],
                "p90_ms": sorted(lats)[min(int(len(lats) * 0.9), len(lats) - 1)],
            }

        return {
            "latency_by_group_size": latency_summary,
            "fan_out_skew": compute_percentiles(skews),
            "key_rotation_convergence": compute_percentiles(rekeys),
        }

    def generate_latex_tables(self, traffic: Dict[str, Any], network: Dict[str, Any],
                              retention: List[Dict[str, Any]], group: Dict[str, Any]):
        """
        Generates production-grade, publication-ready LaTeX tables for master's thesis.
        """
        # 1. Traffic Shaping Table
        table_traffic = os.path.join(self.output_dir, "table_traffic_shaping.tex")
        with open(table_traffic, "w", encoding="utf-8") as f:
            f.write("% Tabela: Skuteczność kształtowania ruchu Poissona i metryki anonimowości\n")
            f.write("\\begin{table}[htbp]\n\\centering\\small\n")
            f.write("\\caption{Empiryczne metryki kształtowania ruchu Poissona oraz entropia adresowania DHT}\n")
            f.write("\\label{tab:traffic_shaping_metrics}\n")
            f.write("\\begin{tabular}{llr}\n\\hline\n")
            f.write("\\textbf{Metryka Badawcza} & \\textbf{Wartość Oczekiwana / Wzór} & \\textbf{Wynik Empiryczny} \\\\\n\\hline\n")
            f.write(f"Łączna liczba pakietów wyjściowych & - & {traffic['total_outbound']} \\\\\n")
            f.write(f"Średni czas między pakietami ($\\mu$) & $\\lambda^{{-1}}$ & {traffic['mean_interval_sec']:.2f} s \\\\\n")
            f.write(f"Wariancja odstępów ($\\sigma^2$) & $\\lambda^{{-2}}$ & {traffic['variance_interval_sec']:.2f} s$^2$ \\\\\n")
            f.write(f"Współczynnik zmienności (CV) & $1.000$ (Poisson) & {traffic['cv']:.3f} \\\\\n")
            f.write(f"Statystyka testu Kołmogorowa-Smirnowa ($D$) & $D \\to 0$ & {traffic['kolmogorov_smirnov_d']:.4f} \\\\\n")
            f.write(f"Entropia Shannona prefiksów celu ($H$) & $8.000$ bitów & {traffic['entropy_bits']:.3f} bitów \\\\\n")
            f.write(f"Znormalizowana jednolitość adresów & $100.0\\%$ & {traffic['entropy_normalized_pct']:.2f}\\% \\\\\n")
            f.write("\\hline\n")
            f.write("\\multicolumn{3}{l}{\\textbf{Rozkład Typów Pakietów Wyjściowych:}} \\\\\n")
            mix = traffic["mix_percentage"]
            f.write(f"\\quad Wiadomości rzeczywiste (\\texttt{{REAL\\_MSG}}) & - & {mix['REAL_MSG']:.1f}\\% \\\\\n")
            f.write(f"\\quad Szum syntetyczny (\\texttt{{COVER\\_DUMMY}}) & - & {mix['COVER_DUMMY']:.1f}\\% \\\\\n")
            f.write(f"\\quad Przekaźnik społecznościowy (\\texttt{{BLIND\\_REPUBLISH}}) & - & {mix['BLIND_REPUBLISH']:.1f}\\% \\\\\n")
            f.write(f"\\quad Zapytania maskujące (\\texttt{{DECOY\\_GET}}) & - & {mix['DECOY_GET']:.1f}\\% \\\\\n")
            f.write(f"\\quad Nagrobki 900B (\\texttt{{TOMBSTONE\\_900B}}) & - & {mix['TOMBSTONE_900B']:.1f}\\% \\\\\n")
            f.write("\\hline\n\\end{tabular}\n\\end{table}\n")

        # 2. Network RTT Table
        table_net = os.path.join(self.output_dir, "table_network_rtt.tex")
        with open(table_net, "w", encoding="utf-8") as f:
            f.write("% Tabela: Rozkłady opóźnień RTT z podziałem na środowiska sieciowe\n")
            f.write("\\begin{table}[htbp]\n\\centering\\small\n")
            f.write("\\caption{Opóźnienia transportowe KRPC DHT (RTT) w funkcji środowiska fizycznego}\n")
            f.write("\\label{tab:network_rtt_percentiles}\n")
            f.write("\\begin{tabular}{lrrrrrr}\n\\hline\n")
            f.write("\\textbf{Środowisko Sieci} & \\textbf{Próbki} & \\textbf{Śr. [ms]} & \\textbf{p50 [ms]} & \\textbf{p90 [ms]} & \\textbf{p99 [ms]} & \\textbf{Max [ms]} \\\\\n\\hline\n")
            for net, stats in network.items():
                f.write(f"{net} & {stats['count']} & {stats['avg']:.1f} & {stats['p50']:.0f} & {stats['p90']:.0f} & {stats['p99']:.0f} & {stats['max']:.0f} \\\\\n")
            f.write("\\hline\n\\end{tabular}\n\\end{table}\n")

        # 3. Retention Survival Table
        table_ret = os.path.join(self.output_dir, "table_retention_survival.tex")
        with open(table_ret, "w", encoding="utf-8") as f:
            f.write("% Tabela: Przeżywalność rekordów BEP 44 na Mainline DHT\n")
            f.write("\\begin{table}[htbp]\n\\centering\\small\n")
            f.write("\\caption{Przeżywalność rekordów BEP 44 w funkcji czasu i trybu republishingu}\n")
            f.write("\\label{tab:retention_survival}\n")
            f.write("\\begin{tabular}{lrrrr}\n\\hline\n")
            f.write("\\textbf{Horyzont} & \\textbf{Czas [h]} & \\textbf{Bez Republishingu [\\%]} & \\textbf{Z Republishingiem [\\%]} & \\textbf{Śr. Węzłów Responded} \\\\\n\\hline\n")
            # Group by horizon label
            by_label = defaultdict(dict)
            for r in retention:
                key = "with" if r["republish_active"] else "no"
                by_label[r["horizon_label"]][key] = r

            for label in ["5m", "1h", "2h", "6h", "12h", "24h", "48h"]:
                if label in by_label:
                    no_r = by_label[label].get("no", {})
                    with_r = by_label[label].get("with", {})
                    h = no_r.get("horizon_hours", with_r.get("horizon_hours", 0.0))
                    no_rate = no_r.get("survival_rate_pct", 0.0)
                    with_rate = with_r.get("survival_rate_pct", 0.0)
                    resp = with_r.get("avg_nodes_responded", no_r.get("avg_nodes_responded", 0.0))
                    f.write(f"{label} & {h:.2f} & {no_rate:.1f}\\% & {with_rate:.1f}\\% & {resp:.1f} / 8 \\\\\n")
            f.write("\\hline\n\\end{tabular}\n\\end{table}\n")

        # 4. Group Chat Table
        table_group = os.path.join(self.output_dir, "table_group_chat.tex")
        with open(table_group, "w", encoding="utf-8") as f:
            f.write("% Tabela: Skalowalność czatów grupowych i rozrzut dostarczenia\n")
            f.write("\\begin{table}[htbp]\n\\centering\\small\n")
            f.write("\\caption{Opóźnienia dostarczenia wiadomości grupowej i zbieżność rotacji klucza}\n")
            f.write("\\label{tab:group_chat_performance}\n")
            f.write("\\begin{tabular}{rrrrr}\n\\hline\n")
            f.write("\\textbf{Rozmiar Grupy $M$} & \\textbf{Liczba Prób} & \\textbf{Śr. Czas [ms]} & \\textbf{p50 [ms]} & \\textbf{p90 [ms]} \\\\\n\\hline\n")
            for size, stats in sorted(group["latency_by_group_size"].items()):
                f.write(f"{size} & {stats['count']} & {stats['avg_ms']:.1f} & {stats['p50_ms']:.0f} & {stats['p90_ms']:.0f} \\\\\n")
            f.write("\\hline\n\\end{tabular}\n")
            skew = group["fan_out_skew"]
            rekey = group["key_rotation_convergence"]
            f.write("\\begin{tablenotes}\\small\n")
            f.write(f"\\item Rozrzut czasowy nadania (Fan-Out Skew $\\Delta t_{{skew}}$): śr. = {skew['avg']:.1f} ms, p90 = {skew['p90']:.0f} ms, max = {skew['max']:.0f} ms.\n")
            f.write(f"\\item Zbieżność rotacji klucza (Rekey Convergence): śr. = {rekey['avg']:.1f} ms, p90 = {rekey['p90']:.0f} ms.\n")
            f.write("\\end{tablenotes}\n\\end{table}\n")

        # 5. Thesis Summary Macros
        macros_file = os.path.join(self.output_dir, "thesis_summary_macros.tex")
        with open(macros_file, "w", encoding="utf-8") as f:
            f.write("% Automatycznie wygenerowane makra LaTeX dla pracy magisterskiej\n")
            f.write(f"\\newcommand{{\\researchTotalPackets}}{{{traffic['total_outbound']}}}\n")
            f.write(f"\\newcommand{{\\researchMeanIntervalSec}}{{{traffic['mean_interval_sec']:.2f}}}\n")
            f.write(f"\\newcommand{{\\researchTrafficCV}}{{{traffic['cv']:.3f}}}\n")
            f.write(f"\\newcommand{{\\researchKolmogorovSmirnovD}}{{{traffic['kolmogorov_smirnov_d']:.4f}}}\n")
            f.write(f"\\newcommand{{\\researchEntropyBits}}{{{traffic['entropy_bits']:.2f}}}\n")
            f.write(f"\\newcommand{{\\researchEntropyUniformity}}{{{traffic['entropy_normalized_pct']:.1f}}}\n")
            f.write(f"\\newcommand{{\\researchCoverTrafficRatio}}{{{traffic['mix_percentage']['COVER_DUMMY']:.1f}}}\n")
            f.write(f"\\newcommand{{\\researchDecoyRatio}}{{{traffic['mix_percentage']['DECOY_GET']:.1f}}}\n")
            f.write(f"\\newcommand{{\\researchTombstoneRatio}}{{{traffic['mix_percentage']['TOMBSTONE_900B']:.1f}}}\n")

    def generate_plots(self, traffic: Dict[str, Any], network: Dict[str, Any],
                       retention: List[Dict[str, Any]], group: Dict[str, Any]):
        """
        Generates publication charts using matplotlib if available.
        """
        if not HAS_MATPLOTLIB:
            print("Notice: matplotlib not installed; skipping graphic plot generation (LaTeX tables were generated).")
            return

        # 1. Inter-packet distribution histogram
        intervals = traffic.get("intervals_sec", [])
        if len(intervals) >= 10:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.hist(intervals, bins=30, density=True, alpha=0.6, color="#1976D2", edgecolor="black", label="Empiryczny rozkład $\\Delta t$")
            mean_sec = traffic["mean_interval_sec"]
            if mean_sec > 0:
                xs = [i * (max(intervals) / 100.0) for i in range(101)]
                ys = [(1.0 / mean_sec) * math.exp(-x / mean_sec) for x in xs]
                ax.plot(xs, ys, "r--", linewidth=2, label="Model Poissona $\\lambda e^{-\\lambda x}$")
            ax.set_xlabel("Odstęp między pakietami [s]")
            ax.set_ylabel("Gęstość prawdopodobieństwa")
            ax.set_title(f"Rozkład kształtowania ruchu (CV={traffic['cv']:.3f}, D={traffic['kolmogorov_smirnov_d']:.4f})")
            ax.legend()
            ax.grid(True, linestyle=":", alpha=0.6)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, "fig_inter_packet_distribution.png"), dpi=300)
            plt.close()

        # 2. Retention survival curves
        by_label = defaultdict(dict)
        for r in retention:
            key = "with" if r["republish_active"] else "no"
            by_label[r["horizon_label"]][key] = r

        labels = ["5m", "1h", "2h", "6h", "12h", "24h", "48h"]
        labels_present = [l for l in labels if l in by_label]
        if labels_present:
            hours = [by_label[l].get("no", by_label[l].get("with", {})).get("horizon_hours", 0) for l in labels_present]
            no_rates = [by_label[l].get("no", {}).get("survival_rate_pct", 0.0) for l in labels_present]
            with_rates = [by_label[l].get("with", {}).get("survival_rate_pct", 0.0) for l in labels_present]

            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(hours, with_rates, "g-o", linewidth=2, label="Aktywny Republishing")
            ax.plot(hours, no_rates, "r--s", linewidth=2, label="Bez Republishingu (Decay)")
            ax.set_xlabel("Czas od pierwszego zapisu [h]")
            ax.set_ylabel("Wskaźnik przeżywalności rekordów [%]")
            ax.set_title("Krzywa przeżywalności rekordów BEP 44 na BitTorrent DHT")
            ax.set_ylim(-5, 105)
            ax.grid(True, linestyle=":", alpha=0.6)
            ax.legend()
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, "fig_retention_survival_curve.png"), dpi=300)
            plt.close()


def main():
    parser = argparse.ArgumentParser(description="PQChat DHT Academic Research Telemetry Analyzer")
    parser.add_argument("--input-dir", "-i", type=str, default=".", help="Directory containing CSV/JSON telemetry or zip file")
    parser.add_argument("--output-dir", "-o", type=str, default="build/research_analysis", help="Output directory for LaTeX and plots")
    parser.add_argument("--latex", action="store_true", default=True, help="Generate LaTeX tables")
    parser.add_argument("--plots", action="store_true", default=True, help="Generate publication charts")
    args = parser.parse_args()

    dataset = ResearchDataset()
    dataset.load_from_directory_or_zip(args.input_dir)

    analyzer = ResearchAnalyzer(dataset, args.output_dir)
    traffic = analyzer.analyze_traffic_shaping()
    network = analyzer.analyze_network_rtt()
    retention = analyzer.analyze_retention_survival()
    group = analyzer.analyze_group_chat()

    if args.latex:
        analyzer.generate_latex_tables(traffic, network, retention, group)

    if args.plots:
        analyzer.generate_plots(traffic, network, retention, group)

    summary_file = os.path.join(args.output_dir, "research_summary.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump({
            "traffic": {k: v for k, v in traffic.items() if k != "intervals_sec"},
            "network": network,
            "retention": retention,
            "group": group,
        }, f, indent=2)

    print(f"Research analysis complete. Outputs written to: {args.output_dir}")


if __name__ == "__main__":
    main()
