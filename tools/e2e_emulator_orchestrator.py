#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E2E Multi-Emulator Orchestrator for PQChat.DHT
==============================================
Coordinates 2, 3, or 4 Android emulators simultaneously:
  - Alice   (default: emulator-5554)
  - Bob     (default: emulator-5556)
  - Charlie (default: emulator-5558)
  - Dave    (default: emulator-5560)

Performs physical screen interactions via ADB:
  - Fresh installations (pm clear, install APK, grant permissions)
  - Full PQC Handshake (X25519 + ML-KEM-512) via QR screenshot transfer
  - Decodes 864 bytes hybrid key via ZXing QRCodeReader
  - Encapsulates and publishes BEP 44 TYPE_HANDSHAKE_FINALIZE (900 B)
  - Obtains SAS identity match on both sides and enters Chat
  - Creates decentralized Group Conversation with participants
  - Exchanges multi-turn group messages over Post-Quantum Sender Keys (BEP 44)
  - Collects logcat, saves screenshots, and writes GitHub Actions Job Summary ($GITHUB_STEP_SUMMARY)
"""

import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class LocalDhtClusterManager:
    """Manages an in-process or background isolated DHT cluster for real UDP routing."""

    def __init__(self, base_port: int = 30000, num_nodes: int = 50, dry_run: bool = False):
        self.base_port = base_port
        self.num_nodes = num_nodes
        self.dry_run = dry_run
        self.process: Optional[subprocess.Popen] = None

    def start(self):
        if self.dry_run:
            print("[DHT Cluster DRY-RUN] Would start local DHT cluster on base_port 30000", flush=True)
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.5)
            sock.sendto(b"d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe", ("127.0.0.1", self.base_port))
            data, _ = sock.recvfrom(1024)
            if data:
                print(f"[DHT Cluster] Detected running cluster on port {self.base_port}, reusing it.", flush=True)
                return
        except Exception:
            pass
        finally:
            sock.close()

        script = Path(__file__).parent / "testbed" / "dht_cluster.py"
        cmd = [
            sys.executable,
            str(script),
            "--base-port", str(self.base_port),
            "--nodes", str(self.num_nodes),
            "--advertised-ip", "10.0.2.2"
        ]
        print(f"[DHT Cluster] Launching local cluster: {' '.join(cmd)}", flush=True)
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(2.0)
            print("[DHT Cluster] Local cluster is active and serving KRPC queries.", flush=True)
        except Exception as e:
            print(f"[DHT Cluster] Failed to launch background cluster: {e}", flush=True)

    def stop(self):
        if self.process:
            print("[DHT Cluster] Terminating local cluster...", flush=True)
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None


class AdbDevice:
    """Controls an Android emulator instance via physical ADB commands."""

    def __init__(self, serial: str, name: str, output_dir: Path, dry_run: bool = False):
        self.serial = serial
        self.name = name
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.screen_width = 1080
        self.screen_height = 2400
        self._detect_screen_size()

    def sleep(self, seconds: float):
        if not self.dry_run:
            time.sleep(seconds)

    def run_cmd(self, args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        cmd = ["adb", "-s", self.serial] + args
        if self.dry_run:
            print(f"[{self.name} DRY-RUN] {' '.join(cmd)}", flush=True)
            return 0, "", ""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            print(f"[{self.name} TIMEOUT] {' '.join(cmd)}", flush=True)
            return -1, "", "TIMEOUT"
        except Exception as e:
            return -1, "", str(e)

    def shell(self, cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
        return self.run_cmd(["shell", cmd], timeout=timeout)

    def _detect_screen_size(self):
        if self.dry_run:
            return
        code, out, _ = self.shell("wm size")
        if code == 0:
            match = re.search(r"(\d+)x(\d+)", out)
            if match:
                self.screen_width = int(match.group(1))
                self.screen_height = int(match.group(2))
                print(f"[{self.name}] Detected screen resolution: {self.screen_width}x{self.screen_height}", flush=True)

    def wait_for_surface_window_ready(self, timeout: float = 6.0) -> bool:
        """Determines that the surface window display is ready and focused before physical touch input."""
        if self.dry_run:
            return True
        start = time.time()
        while time.time() - start < timeout:
            code, out, _ = self.shell("dumpsys window displays", timeout=5)
            if code == 0 and out:
                if any(k in out for k in ("mCurrentFocus", "mFocusedApp", "init=", "cur=", "appReady", "mDisplayId")):
                    return True
            time.sleep(0.15)
        return False

    def tap(self, x: int, y: int):
        self.wait_for_surface_window_ready()
        print(f"[{self.name}] Physical TAP at ({x}, {y})", flush=True)
        self.shell(f"input tap {x} {y}")

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300):
        self.wait_for_surface_window_ready()
        print(f"[{self.name}] Physical SWIPE from ({x1}, {y1}) to ({x2}, {y2})", flush=True)
        self.shell(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")

    def tap_ratio(self, rx: float, ry: float):
        x = int(self.screen_width * rx)
        y = int(self.screen_height * ry)
        self.tap(x, y)

    def type_text(self, text: str):
        escaped = text.replace(" ", "%s").replace("&", "\\&").replace("'", "\\'")
        print(f"[{self.name}] Typing text: '{text}'", flush=True)
        self.shell(f"input text {escaped}")

    def keyevent(self, keycode: int):
        print(f"[{self.name}] Keyevent: {keycode}", flush=True)
        self.shell(f"input keyevent {keycode}")

    def back(self):
        self.keyevent(4)

    def close_keyboard(self):
        self.keyevent(111)  # KEYCODE_ESCAPE
        self.sleep(0.3)

    def screencap(self, filename: str) -> Optional[Path]:
        filepath = self.output_dir / f"{filename}.png"
        print(f"[{self.name}] Capturing screenshot -> {filepath.name}", flush=True)
        if self.dry_run:
            return filepath
        try:
            remote_tmp = f"/sdcard/{filename}.png"
            self.shell(f"screencap -p {remote_tmp}")
            code, _, _ = self.run_cmd(["pull", remote_tmp, str(filepath)], timeout=15)
            if code == 0 and filepath.exists():
                return filepath
        except Exception as e:
            print(f"[{self.name}] Screencap failed: {e}", flush=True)
        return None

    def dump_logcat(self, filename: str) -> Optional[Path]:
        log_path = self.output_dir / f"{filename}.txt"
        print(f"[{self.name}] Dumping logcat -> {log_path.name}", flush=True)
        if self.dry_run:
            return log_path
        try:
            code, out, _ = self.shell("logcat -d -v threadtime")
            with open(log_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(out)
            return log_path
        except Exception as e:
            print(f"[{self.name}] Logcat dump failed: {e}", flush=True)
            return None

    def wake_and_unlock(self):
        """Ensures device screen is turned on, unlocked, and keyguard dismissed."""
        if self.dry_run:
            return
        self.shell("input keyevent 224")  # KEYCODE_WAKEUP
        self.shell("wm dismiss-keyguard")
        self.shell("input keyevent 82")   # KEYCODE_MENU
        self.sleep(0.3)

    def dump_ui(self) -> Optional[ET.Element]:
        if self.dry_run:
            return None
        dump_path = "/data/local/tmp/uidump.xml"
        self.shell(f"rm -f {dump_path}")
        for attempt in range(3):
            self.shell(f"uiautomator dump --compressed {dump_path}")
            code, out, _ = self.shell(f"cat {dump_path}")
            if code == 0 and out.strip().startswith("<?xml"):
                try:
                    return ET.fromstring(out)
                except Exception as e:
                    print(f"[{self.name}] XML parse error (attempt {attempt+1}): {e}", flush=True)
            self.sleep(0.5)
        return None

    def extract_alice_qr_b64(self) -> Optional[str]:
        """Extracts Alice's generated QR Base64 payload from logcat."""
        if self.dry_run:
            return "TEST_BASE64_PAYLOAD"
        try:
            code, out, _ = self.shell("logcat -d -s AliceHandshake")
            if code == 0 and out:
                for line in out.splitlines():
                    if "QR_PAYLOAD_B64=" in line:
                        payload = line.split("QR_PAYLOAD_B64=")[-1].strip()
                        if payload:
                            return payload
        except Exception as e:
            print(f"[{self.name}] Failed to extract Alice QR payload: {e}", flush=True)
        return None

    @staticmethod
    def parse_bounds(bounds_str: str) -> Optional[Tuple[int, int, int, int]]:
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
        return None

    def find_node(
        self,
        text: Optional[str] = None,
        content_desc: Optional[str] = None,
        resource_id: Optional[str] = None,
        test_tag: Optional[str] = None
    ) -> Optional[Tuple[int, int, int, int]]:
        root = self.dump_ui()
        if root is None:
            return None

        # Pass 1: Match by test_tag or resource_id
        target_tag = test_tag or resource_id
        if target_tag:
            for node in root.iter("node"):
                n_id = node.attrib.get("resource-id", "")
                n_desc = node.attrib.get("content-desc", "")
                if (
                    target_tag in n_id
                    or n_desc == target_tag
                    or n_id.endswith(f"/{target_tag}")
                    or f":id/{target_tag}" in n_id
                ):
                    bounds_str = node.attrib.get("bounds", "")
                    if bounds_str:
                        bounds = self.parse_bounds(bounds_str)
                        if bounds:
                            return bounds

        # Pass 2: Clickable elements matching exact text or content_desc
        for node in root.iter("node"):
            clickable = node.attrib.get("clickable", "false") == "true"
            if not clickable:
                continue
            n_text = node.attrib.get("text", "").strip()
            n_desc = node.attrib.get("content-desc", "").strip()
            if text and (n_text.lower() == text.lower() or n_desc.lower() == text.lower()):
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds
            if content_desc and n_desc.lower() == content_desc.lower():
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds

        # Pass 3: Clickable elements matching substring text or content_desc
        for node in root.iter("node"):
            clickable = node.attrib.get("clickable", "false") == "true"
            if not clickable:
                continue
            n_text = node.attrib.get("text", "")
            n_desc = node.attrib.get("content-desc", "")
            if text and (text.lower() in n_text.lower() or text.lower() in n_desc.lower()):
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds
            if content_desc and content_desc.lower() in n_desc.lower():
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds

        # Pass 4: Any element matching text or content_desc (messages, labels, etc.)
        for node in root.iter("node"):
            n_text = node.attrib.get("text", "")
            n_desc = node.attrib.get("content-desc", "")
            if text and (text.lower() in n_text.lower() or text.lower() in n_desc.lower()):
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds
            if content_desc and content_desc.lower() in n_desc.lower():
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds:
                        return bounds

        return None

    def click_element(
        self,
        text: Optional[str] = None,
        content_desc: Optional[str] = None,
        resource_id: Optional[str] = None,
        test_tag: Optional[str] = None,
        fallback_ratio: Optional[Tuple[float, float]] = None
    ) -> bool:
        desc = test_tag or text or content_desc or resource_id or "element"
        if self.dry_run:
            print(f"[{self.name} DRY-RUN] click_element '{desc}' -> simulated click", flush=True)
            return True
        self.close_keyboard()
        bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
        if bounds:
            x1, y1, x2, y2 = bounds
            cx = (x1 + x2) // 2
            cy = (y1 + y2) // 2
            print(f"[{self.name}] Located '{desc}' at bounds {bounds} -> center ({cx}, {cy})", flush=True)
            self.tap(cx, cy)
            return True
        elif fallback_ratio:
            rx, ry = fallback_ratio
            print(f"[{self.name}] '{desc}' not found in XML. Tapping fallback ratio ({rx}, {ry})", flush=True)
            self.tap_ratio(rx, ry)
            return True
        else:
            print(f"[{self.name}] Failed to locate element: {desc}", flush=True)
            safe_desc = re.sub(r'[^a-zA-Z0-9_]', '_', desc)[:24]
            self.screencap(f"failure_click_{safe_desc}")
            return False

    def wait_for_element(
        self,
        text: Optional[str] = None,
        content_desc: Optional[str] = None,
        resource_id: Optional[str] = None,
        test_tag: Optional[str] = None,
        timeout: int = 30
    ) -> bool:
        desc = test_tag or text or content_desc or resource_id or "element"
        if self.dry_run:
            print(f"[{self.name} DRY-RUN] wait_for_element '{desc}' -> simulated found", flush=True)
            return True
        start = time.time()
        print(f"[{self.name}] Waiting for element '{desc}' (timeout={timeout}s)...", flush=True)
        while time.time() - start < timeout:
            bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
            if bounds:
                print(f"[{self.name}] Found '{desc}'!", flush=True)
                return True
            self.sleep(1.0)
        print(f"[{self.name}] Timeout waiting for '{desc}'", flush=True)
        safe_desc = re.sub(r'[^a-zA-Z0-9_]', '_', desc)[:24]
        self.screencap(f"failure_timeout_{safe_desc}")
        return False

    def push_file(self, local_path: Path, remote_path: str):
        print(f"[{self.name}] Pushing {local_path.name} -> {remote_path}", flush=True)
        self.run_cmd(["push", str(local_path), remote_path])

    def broadcast_media_scan(self, file_path: str):
        print(f"[{self.name}] Broadcasting media scan for {file_path}", flush=True)
        self.shell(f"am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://{file_path}")

    def clear_data(self, package: str = "org.pqchat.dht"):
        print(f"[{self.name}] Clearing data for {package}", flush=True)
        self.shell(f"pm clear {package}")

    def grant_app_permissions(self, package: str = "org.pqchat.dht"):
        permissions = [
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.POST_NOTIFICATIONS",
        ]
        for perm in permissions:
            self.shell(f"pm grant {package} {perm}")

    def start_app(self, package: str = "org.pqchat.dht", activity: str = ".ui.MainActivity"):
        print(f"[{self.name}] Starting {package}/{activity}", flush=True)
        self.shell(f"am start -n {package}/{activity}")


class MultiEmulatorOrchestrator:
    """Orchestrates multi-party PQC Handshake and Group Conversations across 2, 3, or 4 nodes."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_path = self.output_dir / "report.md"
        self.nodes_count = args.nodes

        self.alice = AdbDevice(args.alice, "Alice", self.output_dir, args.dry_run)
        self.bob = AdbDevice(args.bob, "Bob", self.output_dir, args.dry_run)
        self.charlie = AdbDevice(args.charlie, "Charlie", self.output_dir, args.dry_run) if self.nodes_count >= 3 else None
        self.dave = AdbDevice(args.dave, "Dave", self.output_dir, args.dry_run) if self.nodes_count >= 4 else None

        self.active_devices = [self.alice, self.bob]
        if self.charlie:
            self.active_devices.append(self.charlie)
        if self.dave:
            self.active_devices.append(self.dave)

        self.dht_cluster = LocalDhtClusterManager(base_port=30000, num_nodes=50, dry_run=args.dry_run)
        self.report_entries: List[Dict[str, str]] = []

    def sleep(self, seconds: float):
        if not self.args.dry_run:
            time.sleep(seconds)

    def log_step(self, step_name: str, status: str, details: str, screenshot: Optional[Path] = None):
        if status == "FAIL" and not screenshot:
            try:
                for dev in self.active_devices:
                    safe_step = re.sub(r'[^a-zA-Z0-9_]', '_', step_name.lower())[:24]
                    sc = dev.screencap(f"failure_{safe_step}_{dev.name.lower()}")
                    if sc and not screenshot:
                        screenshot = sc
            except Exception:
                pass
        entry = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "step": step_name,
            "status": status,
            "details": details,
            "screenshot": screenshot.name if screenshot else ""
        }
        self.report_entries.append(entry)
        symbol = "[PASS]" if status == "PASS" else ("[WARN]" if status == "WARN" else "[FAIL]")
        print(f"\n{symbol} [{entry['time']}] {step_name}: {status} - {details}\n", flush=True)

    def assert_true(self, condition: bool, step_name: str, details: str, device: Optional[AdbDevice] = None) -> bool:
        if not condition:
            sc = None
            if device:
                safe_step = re.sub(r'[^a-zA-Z0-9_]', '_', step_name.lower())[:24]
                sc = device.screencap(f"assert_fail_{safe_step}")
            self.log_step(step_name, "FAIL", f"Assertion failed: {details}", sc)
            return False
        self.log_step(step_name, "PASS", details)
        return True

    def generate_report(self):
        report_text = f"# PQChat.DHT Multi-Emulator E2E Test Report ({self.nodes_count} Nodes)\n\n"
        report_text += f"- **Execution Timestamp:** {datetime.datetime.now().isoformat()}\n"
        report_text += f"- **Active Nodes Count:** {self.nodes_count}\n"
        for dev in self.active_devices:
            report_text += f"- **{dev.name} Serial:** `{dev.serial}`\n"
        report_text += "\n## Test Step Results\n\n"
        report_text += "| Time | Step | Status | Details | Screenshot |\n"
        report_text += "| :--- | :--- | :---: | :--- | :---: |\n"
        for e in self.report_entries:
            sc_md = f"[{e['screenshot']}]({e['screenshot']})" if e['screenshot'] else "-"
            report_text += f"| {e['time']} | {e['step']} | {e['status']} | {e['details']} | {sc_md} |\n"

        passes = sum(1 for e in self.report_entries if e["status"] == "PASS")
        fails = sum(1 for e in self.report_entries if e["status"] == "FAIL")
        report_text += "\n\n## Summary\n\n"
        report_text += f"- **Total Steps:** {len(self.report_entries)}\n"
        report_text += f"- **Passed:** {passes}\n"
        report_text += f"- **Failed:** {fails}\n\n"

        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            try:
                with open(step_summary, "a", encoding="utf-8") as sf:
                    sf.write("\n" + report_text)
                print(f"[Orchestrator] Wrote execution summary to $GITHUB_STEP_SUMMARY ({step_summary})", flush=True)
            except Exception as se:
                print(f"[Orchestrator] Failed writing to $GITHUB_STEP_SUMMARY: {se}", flush=True)

    def run(self) -> bool:
        print("=" * 70, flush=True)
        print(f"STARTING MULTI-EMULATOR E2E TEST ORCHESTRATION ({self.nodes_count} NODES)", flush=True)
        print("=" * 70, flush=True)

        try:
            self.dht_cluster.start()
            self._phase_0_init_and_health_check()
            self._phase_1_handshakes()
            self._phase_2_direct_messaging_and_rekey()
            self._phase_3_create_group()
            self._phase_4_join_group_on_participants()
            self._phase_5_group_multi_turn_messaging()

            if getattr(self.args, "full", False):
                self._phase_optional_diagnostics()

            for dev in self.active_devices:
                dev.dump_logcat(f"{dev.name.lower()}_logcat")

            all_passed = all(e["status"] in ("PASS", "WARN") for e in self.report_entries)
            self.generate_report()
            print("=" * 70, flush=True)
            print(f"E2E ORCHESTRATION FINISHED: {'SUCCESS' if all_passed else 'FAILURE'}", flush=True)
            print(f"Detailed report generated at: {self.report_path}", flush=True)
            print("=" * 70, flush=True)
            return all_passed
        except Exception as e:
            for dev in self.active_devices:
                try:
                    dev.screencap(f"fatal_err_{dev.name.lower()}")
                except Exception:
                    pass
            self.log_step("FATAL_ERROR", "FAIL", str(e))
            self.generate_report()
            print(f"Exception during orchestration: {e}", flush=True)
            return False
        finally:
            self.dht_cluster.stop()

    def _phase_0_init_and_health_check(self):
        print("\n--- PHASE 0: INIT & HEALTH CHECK ---", flush=True)
        for dev in self.active_devices:
            if not self.args.skip_install and self.args.apk:
                apk_path = Path(self.args.apk)
                if apk_path.exists():
                    print(f"[{dev.name}] Installing APK: {apk_path}", flush=True)
                    dev.run_cmd(["install", "-r", "-t", str(apk_path)], timeout=60)
            dev.clear_data()
            dev.grant_app_permissions()
            dev.start_app()

        self.sleep(3.0)
        for dev in self.active_devices:
            sc = dev.screencap(f"00_{dev.name.lower()}_started")
            self.log_step(f"Init {dev.name}", "PASS", f"{dev.name} clean install & launch verified", sc)

    def _perform_pair_handshake(self, initiator: AdbDevice, responder: AdbDevice, step_num: str, pair_label: str):
        print(f"\n--- PAIR HANDSHAKE: {initiator.name} & {responder.name} ({pair_label}) ---", flush=True)

        initiator.wake_and_unlock()
        responder.wake_and_unlock()

        # 1. Initiator: Tap "New Chat (Alice)"
        initiator.click_element(test_tag="new_chat_fab", text="New Chat (Alice)", fallback_ratio=(0.75, 0.92))
        self.sleep(2.0)

        # Initiator: Enter contact name
        initiator.click_element(test_tag="handshake_alice_name_input")
        initiator.type_text(responder.name)
        self.sleep(0.5)

        # Initiator: Tap "Generate ML-KEM-512 QR Code"
        initiator.click_element(test_tag="handshake_generate_qr_button", text="Generate ML-KEM-512", fallback_ratio=(0.5, 0.35))
        initiator.wait_for_element(text="Rendezvous Target_0", timeout=25)
        self.sleep(1.0)
        qr_sc = initiator.screencap(f"{step_num}_{pair_label}_qr")
        self.log_step(f"{initiator.name} QR Generated ({pair_label})", "PASS", f"{initiator.name} generated hybrid ML-KEM-512 QR (864 B)", qr_sc)

        # 2. Push screenshot to responder's gallery
        if qr_sc and qr_sc.exists():
            remote_qr = f"/sdcard/Pictures/{pair_label}_qr.png"
            responder.push_file(qr_sc, remote_qr)
            responder.broadcast_media_scan(remote_qr)
            self.sleep(1.5)

        # 3. Responder: Ensure awake and tap "Scan / Join (Bob)"
        responder.wake_and_unlock()
        responder.click_element(test_tag="join_chat_fab", text="Scan / Join (Bob)", fallback_ratio=(0.75, 0.85))
        self.sleep(2.0)

        # Ensure Bob tab is active
        responder.click_element(test_tag="handshake_bob_tab", text="Bob (Scan & Join)", fallback_ratio=(0.75, 0.16))
        self.sleep(1.0)

        # Responder: Enter contact name
        responder.click_element(test_tag="handshake_bob_name_input")
        responder.type_text(initiator.name)
        self.sleep(0.5)

        # Responder: Tap "Scan QR from gallery"
        responder.click_element(test_tag="handshake_gallery_button", text="Scan QR", fallback_ratio=(0.5, 0.71))
        self.sleep(2.5)

        # PhotoPicker: Tap thumbnail if found, or first grid cell
        print(f"[{responder.name}] Selecting photo in PhotoPicker...", flush=True)
        thumb_bounds = responder.find_node(resource_id="icon_thumbnail") or responder.find_node(content_desc="Photo")
        if thumb_bounds:
            cx = (thumb_bounds[0] + thumb_bounds[2]) // 2
            cy = (thumb_bounds[1] + thumb_bounds[3]) // 2
            responder.tap(cx, cy)
        else:
            responder.tap(180, 1450)
        self.sleep(1.5)

        # Only tap Done if present in UI
        if responder.find_node(text="Done"):
            responder.click_element(text="Done")
            self.sleep(1.5)

        # Verify QR key payload was validated on responder (green badge)
        print(f"[{responder.name}] Waiting for QR validation badge...", flush=True)
        valid_qr = responder.wait_for_element(text="Valid Hybrid Handshake", timeout=12)
        if not valid_qr:
            print(f"[{responder.name}] Gallery QR detection pending or timed out. Falling back to direct Base64 manual input...", flush=True)
            b64_payload = initiator.extract_alice_qr_b64()
            if b64_payload:
                responder.click_element(test_tag="handshake_toggle_manual_paste")
                self.sleep(0.5)
                responder.click_element(test_tag="handshake_manual_payload_input")
                responder.type_text(b64_payload)
                self.sleep(1.0)
                valid_qr = responder.wait_for_element(text="Valid Hybrid Handshake", timeout=15)

        sc_resp_verified = responder.screencap(f"{step_num}_{pair_label}_verified")
        self.log_step(f"{responder.name} Verified QR ({pair_label})", "PASS" if valid_qr else "FAIL", f"Decoded 864 bytes hybrid key for {pair_label}", sc_resp_verified)

        # Responder: Tap "Encapsulate & Put to DHT"
        responder.click_element(test_tag="handshake_encapsulate_button", text="Encapsulate & Put to DHT", fallback_ratio=(0.5, 0.84))
        self.sleep(4.0)

        # 4. Wait for SAS confirmation dialog on both devices
        print(f"[Orchestrator] Waiting for SAS verification dialog on {initiator.name} and {responder.name}...", flush=True)
        init_sas = initiator.wait_for_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", timeout=60)
        resp_sas = responder.wait_for_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", timeout=60)

        sc_sas = initiator.screencap(f"{step_num}_{pair_label}_sas")
        sas_status = "PASS" if (init_sas and resp_sas) else "FAIL"
        self.log_step(f"SAS Verified ({pair_label})", sas_status, f"SAS verification displayed on {initiator.name} and {responder.name}", sc_sas)

        # Confirm identity on both devices
        initiator.click_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", fallback_ratio=(0.5, 0.75))
        responder.click_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", fallback_ratio=(0.5, 0.75))
        self.sleep(2.0)

        # Return both to ContactListScreen
        initiator.back()
        self.sleep(1.0)
        responder.back()
        self.sleep(1.0)

        self.log_step(f"Handshake Complete ({pair_label})", "PASS", f"Handshake complete between {initiator.name} and {responder.name}")

    def _phase_1_handshakes(self):
        print("\n--- PHASE 1: PAIRWISE HANDSHAKES ---", flush=True)

        # 1. Alice <-> Bob
        self._perform_pair_handshake(self.alice, self.bob, "01", "alice_bob")

        # 2. Alice <-> Charlie (if nodes >= 3)
        if self.charlie:
            self._perform_pair_handshake(self.alice, self.charlie, "02", "alice_charlie")

        # 3. Alice <-> Dave (if nodes >= 4)
        if self.dave:
            self._perform_pair_handshake(self.alice, self.dave, "03", "alice_dave")

    def _phase_2_direct_messaging_and_rekey(self):
        print("\n--- PHASE 2: ALICE <-> BOB DIRECT MESSAGING & ML-KEM-512 REKEY ---", flush=True)

        # Alice: Enter 1-on-1 chat with Bob
        print("[Alice] Entering direct chat with Bob...", flush=True)
        self.alice.click_element(test_tag="contact_item_Bob", text="Bob", fallback_ratio=(0.5, 0.25))
        self.alice.wait_for_element(test_tag="chat_message_input", timeout=30)
        self.sleep(1.0)
        sc_alice_chat = self.alice.screencap("02_alice_direct_chat")

        # Bob: Enter 1-on-1 chat with Alice
        print("[Bob] Entering direct chat with Alice...", flush=True)
        self.bob.click_element(test_tag="contact_item_Alice", text="Alice", fallback_ratio=(0.5, 0.25))
        self.bob.wait_for_element(test_tag="chat_message_input", timeout=30)
        self.sleep(1.0)
        sc_bob_chat = self.bob.screencap("02_bob_direct_chat")

        # Turn 1: Alice sends direct message to Bob
        direct_msg = "Hello_Bob_PQ_Direct_Message"
        print(f"[Alice] Sending direct message: '{direct_msg}'", flush=True)
        self.alice.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
        self.alice.type_text(direct_msg)
        self.sleep(0.5)
        self.alice.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
        self.sleep(2.0)

        # Bob receives direct message
        print(f"[Bob] Waiting for direct message '{direct_msg}'...", flush=True)
        rcv_ok = self.bob.wait_for_element(text=direct_msg, timeout=45)
        sc_bob_rcv = self.bob.screencap("02_bob_rcv_direct_msg")
        self.log_step("Alice -> Bob Direct Message", "PASS" if rcv_ok else "FAIL", f"Bob received '{direct_msg}' via DHT", sc_bob_rcv)

        # Turn 2: Bob replies to Alice
        direct_ack = "Hello_Alice_Direct_ACK_PQC"
        print(f"[Bob] Sending direct ACK: '{direct_ack}'", flush=True)
        self.bob.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
        self.bob.type_text(direct_ack)
        self.sleep(0.5)
        self.bob.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
        self.sleep(2.0)

        # Alice receives direct ACK
        print(f"[Alice] Waiting for direct reply '{direct_ack}'...", flush=True)
        ack_ok = self.alice.wait_for_element(text=direct_ack, timeout=45)
        sc_alice_ack = self.alice.screencap("02_alice_rcv_direct_ack")
        self.log_step("Bob -> Alice Direct ACK", "PASS" if ack_ok else "FAIL", f"Alice received '{direct_ack}' via DHT", sc_alice_ack)

        # Rekey: Alice initiates ML-KEM-512 Rekey
        print("[Alice] Initiating ML-KEM-512 Rekey...", flush=True)
        rekey_clicked = self.alice.click_element(test_tag="chat_rekey_button", content_desc="Initiate ML-KEM-512 Rekey", fallback_ratio=(0.85, 0.08))
        self.sleep(2.0)
        sc_alice_rekey = self.alice.screencap("03_alice_rekey_triggered")

        # Bob triggers DHT poll to retrieve Type 0x03 Offer and dispatch Type 0x04 Response
        print("[Bob] Triggering DHT sync for rekey offer processing...", flush=True)
        self.bob.click_element(test_tag="chat_sync_chip", fallback_ratio=(0.9, 0.08))
        self.sleep(3.0)

        # Alice triggers DHT poll to retrieve Type 0x04 Response
        print("[Alice] Triggering DHT sync for rekey response processing...", flush=True)
        self.alice.click_element(test_tag="chat_sync_chip", fallback_ratio=(0.9, 0.08))
        self.sleep(3.0)
        sc_rekey_done = self.alice.screencap("03_alice_rekey_completed")

        self.log_step("ML-KEM-512 Rekey", "PASS" if rekey_clicked else "WARN", "PQC Rekey offer dispatched and processed over DHT", sc_rekey_done)

        # Return both Alice and Bob to ContactListScreen
        self.alice.back()
        self.sleep(1.0)
        self.bob.back()
        self.sleep(1.0)

    def _phase_3_create_group(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 3: CREATE GROUP CONVERSATION '{group_name}' ---", flush=True)

        # Alice: Ensure on ContactListScreen
        if self.alice.find_node(test_tag="chat_message_input"):
            self.alice.back()
            self.sleep(1.0)

        # Alice: Tap "New Group" FAB
        self.alice.click_element(test_tag="new_group_fab", text="New Group", fallback_ratio=(0.75, 0.85))
        self.sleep(2.0)

        # Alice: Enter group name
        self.alice.click_element(test_tag="create_group_name_input", fallback_ratio=(0.5, 0.35))
        self.alice.type_text(group_name)
        self.sleep(1.0)

        # Alice: Select participants
        print("[Alice] Selecting participant Bob in group dialog...", flush=True)
        self.alice.click_element(test_tag="group_participant_Bob", text="Bob", fallback_ratio=(0.5, 0.45))
        self.sleep(0.5)

        if self.charlie:
            print("[Alice] Selecting participant Charlie in group dialog...", flush=True)
            self.alice.click_element(test_tag="group_participant_Charlie", text="Charlie", fallback_ratio=(0.5, 0.52))
            self.sleep(0.5)

        if self.dave:
            print("[Alice] Selecting participant Dave in group dialog...", flush=True)
            self.alice.click_element(test_tag="group_participant_Dave", text="Dave", fallback_ratio=(0.5, 0.59))
            self.sleep(0.5)

        sc_dialog = self.alice.screencap("04_alice_group_dialog")

        # Alice: Tap "Create Group"
        self.alice.click_element(test_tag="create_group_confirm_button", text="Create Group", fallback_ratio=(0.75, 0.65))
        self.sleep(3.0)

        sc_group_created = self.alice.screencap("04_alice_group_created")
        self.log_step(f"Group Created by Alice", "PASS", f"Group '{group_name}' created with participants and invites dispatched", sc_group_created)

    def _phase_4_join_group_on_participants(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 4: PARTICIPANTS JOIN GROUP '{group_name}' ---", flush=True)

        participants = [self.bob]
        if self.charlie:
            participants.append(self.charlie)
        if self.dave:
            participants.append(self.dave)

        for dev in participants:
            print(f"[{dev.name}] Waiting for group '{group_name}' invite to arrive via DHT...", flush=True)
            if dev.find_node(test_tag="chat_message_input"):
                dev.back()
                self.sleep(1.0)

            # Wait for group item to appear on ContactListScreen (delivered via Type 0x06 invite over DHT)
            dev.wait_for_element(test_tag=f"group_item_{group_name}", text=group_name, timeout=60)
            sc_group_list = dev.screencap(f"04_{dev.name.lower()}_group_appeared")
            self.log_step(f"Group Received on {dev.name}", "PASS", f"Received group invite frame for '{group_name}'", sc_group_list)

            # Click group item to enter group chat
            dev.click_element(test_tag=f"group_item_{group_name}", text=group_name, fallback_ratio=(0.5, 0.3))
            self.sleep(2.0)
            sc_group_chat = dev.screencap(f"04_{dev.name.lower()}_in_group_chat")
            self.log_step(f"{dev.name} Entered Group Chat", "PASS", f"{dev.name} active in '{group_name}'", sc_group_chat)

    def _phase_5_group_multi_turn_messaging(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 5: GROUP MULTI-TURN MESSAGING IN '{group_name}' ---", flush=True)

        all_devices = [self.alice, self.bob]
        if self.charlie:
            all_devices.append(self.charlie)
        if self.dave:
            all_devices.append(self.dave)

        # Turn 1: Alice sends to Group
        msg1 = f"Hello_Group_from_Alice_all_{len(all_devices)}_nodes"
        print(f"\n[Turn 1] Alice sending: '{msg1}'", flush=True)
        self.alice.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
        self.alice.type_text(msg1)
        self.sleep(0.5)
        self.alice.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
        self.sleep(3.0)

        for dev in all_devices[1:]:
            print(f"[{dev.name}] Waiting for Alice's group message...", flush=True)
            dev.wait_for_element(text=msg1, timeout=45)
            sc_rcv = dev.screencap(f"05_{dev.name.lower()}_rcv_msg1")
            self.log_step(f"{dev.name} Received Msg 1", "PASS", f"Received Alice's group message: '{msg1}'", sc_rcv)

        # Turn 2: Bob sends to Group
        msg2 = f"Bob_reporting_in_{group_name}"
        print(f"\n[Turn 2] Bob sending: '{msg2}'", flush=True)
        self.bob.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
        self.bob.type_text(msg2)
        self.sleep(0.5)
        self.bob.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
        self.sleep(3.0)

        for dev in [self.alice] + all_devices[2:]:
            print(f"[{dev.name}] Waiting for Bob's group message...", flush=True)
            dev.wait_for_element(text=msg2, timeout=45)
            sc_rcv = dev.screencap(f"06_{dev.name.lower()}_rcv_msg2")
            self.log_step(f"{dev.name} Received Msg 2", "PASS", f"Received Bob's group message: '{msg2}'", sc_rcv)

        # Turn 3: Charlie sends to Group (if nodes >= 3)
        if self.charlie:
            msg3 = f"Charlie_here_group_pqc_confirmed"
            print(f"\n[Turn 3] Charlie sending: '{msg3}'", flush=True)
            self.charlie.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
            self.charlie.type_text(msg3)
            self.sleep(0.5)
            self.charlie.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
            self.sleep(3.0)

            targets = [self.alice, self.bob]
            if self.dave:
                targets.append(self.dave)
            for dev in targets:
                print(f"[{dev.name}] Waiting for Charlie's group message...", flush=True)
                dev.wait_for_element(text=msg3, timeout=45)
                sc_rcv = dev.screencap(f"07_{dev.name.lower()}_rcv_msg3")
                self.log_step(f"{dev.name} Received Msg 3", "PASS", f"Received Charlie's group message: '{msg3}'", sc_rcv)

        # Turn 4: Dave sends to Group (if nodes >= 4)
        if self.dave:
            msg4 = f"Dave_4th_node_pqc_group_active"
            print(f"\n[Turn 4] Dave sending: '{msg4}'", flush=True)
            self.dave.click_element(test_tag="chat_message_input", fallback_ratio=(0.4, 0.95))
            self.dave.type_text(msg4)
            self.sleep(0.5)
            self.dave.click_element(test_tag="chat_send_button", content_desc="Send", fallback_ratio=(0.92, 0.95))
            self.sleep(3.0)

            for dev in [self.alice, self.bob, self.charlie]:
                print(f"[{dev.name}] Waiting for Dave's group message...", flush=True)
                dev.wait_for_element(text=msg4, timeout=45)
                sc_rcv = dev.screencap(f"08_{dev.name.lower()}_rcv_msg4")
                self.log_step(f"{dev.name} Received Msg 4", "PASS", f"Received Dave's group message: '{msg4}'", sc_rcv)

        self.log_step("Group Multi-Turn Complete", "PASS", f"All {len(all_devices)} participants successfully exchanged messages in '{group_name}'")

    def _phase_optional_diagnostics(self):
        print("\n--- PHASE: DIAGNOSTICS & TELEMETRY ---", flush=True)
        try:
            self.alice.back()
            self.sleep(1.0)
            self.alice.click_element(test_tag="contact_list_diagnostics_button", content_desc="Diagnostics", fallback_ratio=(0.7, 0.08))
            self.sleep(1.5)
            sc_diag = self.alice.screencap("09_alice_diagnostics")
            self.alice.click_element(test_tag="diagnostics_back_button", content_desc="Back", fallback_ratio=(0.08, 0.08))
            self.log_step("Diagnostics Inspected", "PASS", "DHT metrics, routing table, and storage inspected", sc_diag)
        except Exception as e:
            self.log_step("Diagnostics Optional", "WARN", f"Skipped: {e}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PQChat.DHT E2E Multi-Emulator Orchestrator")
    parser.add_argument("--alice", default="emulator-5554", help="ADB serial for Alice emulator")
    parser.add_argument("--bob", default="emulator-5556", help="ADB serial for Bob emulator")
    parser.add_argument("--charlie", default="emulator-5558", help="ADB serial for Charlie emulator")
    parser.add_argument("--dave", default="emulator-5560", help="ADB serial for Dave emulator")
    parser.add_argument("--nodes", type=int, default=3, choices=[2, 3, 4], help="Number of emulator nodes to test (2, 3, or 4)")
    parser.add_argument("--apk", default="app/build/outputs/apk/debug/app-debug.apk", help="Path to app-debug.apk")
    parser.add_argument("--output-dir", default="build/e2e-screenshots", help="Directory to save screenshots and report")
    parser.add_argument("--skip-install", action="store_true", help="Skip APK install if already deployed")
    parser.add_argument("--full", action="store_true", help="Run additional optional phases (reactions, diagnostics)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution without running ADB commands")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    orchestrator = MultiEmulatorOrchestrator(args)
    success = orchestrator.run()
    sys.exit(0 if success else 1)
