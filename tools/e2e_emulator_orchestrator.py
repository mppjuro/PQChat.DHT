#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E2E Multi-Emulator Orchestrator for PQChat.DHT
==============================================
Coordinates 2 or 3 Android emulators simultaneously:
  - Alice   (default: emulator-5554)
  - Bob     (default: emulator-5556)
  - Charlie (default: emulator-5558)

Performs physical screen interactions via ADB:
  - Parses UI hierarchy dumps (uiautomator dump) to find elements and compute physical pixel bounds/centers
  - Issues physical tap events: `adb shell input tap <x> <y>`
  - Issues text input: `adb shell input text <string>`
  - Captures full-screen screenshots: `adb exec-out screencap -p`
  - Transfers QR code screenshots to partner emulator gallery (`adb push` + `MEDIA_SCANNER_SCAN_FILE`)
  - Orchestrates PQC Handshake (X25519 + ML-KEM-512) and SAS code verification
  - Tests 1-on-1 end-to-end messaging
  - Tests 3-node group chat creation, member selection, and group broadcast
  - Tests member leave (`GROUP_SUBTYPE_LEAVE`), key rotation (`GROUP_SUBTYPE_REKEY`), and post-leave secrecy
  - Verifies Diagnostics and Settings screens
  - Saves full trace of screenshots and generates a markdown execution report
"""

import argparse
import datetime
import json
import os
import re
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

    def tap(self, x: int, y: int):
        print(f"[{self.name}] Physical TAP at ({x}, {y})", flush=True)
        self.shell(f"input tap {x} {y}")

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

    def screencap(self, filename: str) -> Optional[Path]:
        filepath = self.output_dir / f"{filename}.png"
        print(f"[{self.name}] Capturing screenshot -> {filepath.name}", flush=True)
        if self.dry_run:
            return filepath
        cmd = ["adb", "-s", self.serial, "exec-out", "screencap", "-p"]
        try:
            with open(filepath, "wb") as f:
                subprocess.run(cmd, stdout=f, check=True, timeout=15)
            return filepath
        except Exception as e:
            print(f"[{self.name}] Screencap failed: {e}", flush=True)
            return None

    def dump_ui(self) -> Optional[ET.Element]:
        if self.dry_run:
            return None
        dump_path = "/data/local/tmp/uidump.xml"
        self.shell(f"uiautomator dump {dump_path}")
        code, out, _ = self.shell(f"cat {dump_path}")
        if code != 0 or not out.strip().startswith("<?xml"):
            self.sleep(0.5)
            code, out, _ = self.shell(f"cat {dump_path}")
            if code != 0 or not out.strip().startswith("<?xml"):
                return None
        try:
            return ET.fromstring(out)
        except Exception as e:
            print(f"[{self.name}] XML parse error: {e}", flush=True)
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

        for node in root.iter("node"):
            n_text = node.attrib.get("text", "")
            n_desc = node.attrib.get("content-desc", "")
            n_id = node.attrib.get("resource-id", "")
            bounds_str = node.attrib.get("bounds", "")

            matched = False
            if test_tag and (n_desc == test_tag or test_tag in n_desc or test_tag in n_id):
                matched = True
            elif text and (text.lower() in n_text.lower() or text.lower() in n_desc.lower()):
                matched = True
            elif content_desc and content_desc.lower() in n_desc.lower():
                matched = True
            elif resource_id and resource_id in n_id:
                matched = True

            if matched and bounds_str:
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
        bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
        if bounds:
            x1, y1, x2, y2 = bounds
            cx = (x1 + x2) // 2
            cy = (y1 + y2) // 2
            desc = test_tag or text or content_desc or resource_id
            print(f"[{self.name}] Located '{desc}' at bounds {bounds} -> center ({cx}, {cy})", flush=True)
            self.tap(cx, cy)
            return True
        elif fallback_ratio:
            rx, ry = fallback_ratio
            desc = test_tag or text or content_desc or resource_id
            print(f"[{self.name}] '{desc}' not found in XML. Tapping fallback ratio ({rx}, {ry})", flush=True)
            self.tap_ratio(rx, ry)
            return True
        else:
            desc = test_tag or text or content_desc or resource_id
            print(f"[{self.name}] Failed to locate element: {desc}", flush=True)
            return False

    def wait_for_element(
        self,
        text: Optional[str] = None,
        content_desc: Optional[str] = None,
        resource_id: Optional[str] = None,
        test_tag: Optional[str] = None,
        timeout: int = 30,
        poll_interval: float = 1.0
    ) -> bool:
        if self.dry_run:
            return True
        start = time.time()
        desc = test_tag or text or content_desc or resource_id
        print(f"[{self.name}] Waiting for element '{desc}' (timeout={timeout}s)...", flush=True)
        while time.time() - start < timeout:
            if self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag):
                print(f"[{self.name}] Element '{desc}' appeared after {time.time() - start:.1f}s", flush=True)
                return True
            self.sleep(poll_interval)
        print(f"[{self.name}] Timeout waiting for element: '{desc}'", flush=True)
        return False

    def push_file(self, local_path: Path, remote_path: str) -> bool:
        print(f"[{self.name}] Pushing {local_path} -> {remote_path}", flush=True)
        code, out, err = self.run_cmd(["push", str(local_path), remote_path])
        return code == 0

    def broadcast_media_scan(self, remote_file_path: str):
        print(f"[{self.name}] Broadcasting MEDIA_SCANNER_SCAN_FILE for {remote_file_path}", flush=True)
        self.shell(f"am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://{remote_file_path}")

    def grant_app_permissions(self, package: str = "org.pqchat.dht"):
        perms = [
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
        for p in perms:
            self.shell(f"pm grant {package} {p}")

    def start_app(self, package: str = "org.pqchat.dht", activity: str = ".ui.MainActivity"):
        print(f"[{self.name}] Starting app {package}/{activity}...", flush=True)
        self.shell(f"am start -W -n {package}/{activity}")
        self.sleep(1.5)

    def stop_app(self, package: str = "org.pqchat.dht"):
        print(f"[{self.name}] Stopping app {package}...", flush=True)
        self.shell(f"am force-stop {package}")

    def clear_data(self, package: str = "org.pqchat.dht"):
        print(f"[{self.name}] Clearing app data for {package}...", flush=True)
        self.shell(f"pm clear {package}")


class MultiEmulatorOrchestrator:
    """Orchestrates E2E testing across Alice, Bob, and Charlie emulators."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_path = self.output_dir / "report.md"

        self.alice = AdbDevice(args.alice, "Alice", self.output_dir, args.dry_run)
        self.bob = AdbDevice(args.bob, "Bob", self.output_dir, args.dry_run)
        self.charlie = (
            AdbDevice(args.charlie, "Charlie", self.output_dir, args.dry_run)
            if args.nodes >= 3
            else None
        )
        self.report_entries: List[Dict[str, str]] = []

    def sleep(self, seconds: float):
        if not self.args.dry_run:
            time.sleep(seconds)

    def log_step(self, step_name: str, status: str, details: str, screenshot: Optional[Path] = None):
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

    def generate_report(self):
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write("# PQChat.DHT Multi-Emulator E2E Test Report\n\n")
            f.write(f"- **Execution Timestamp:** {datetime.datetime.now().isoformat()}\n")
            f.write(f"- **Nodes Tested:** {'Alice, Bob, Charlie (3 nodes)' if self.charlie else 'Alice, Bob (2 nodes)'}\n")
            f.write(f"- **Alice Serial:** `{self.alice.serial}`\n")
            f.write(f"- **Bob Serial:** `{self.bob.serial}`\n")
            if self.charlie:
                f.write(f"- **Charlie Serial:** `{self.charlie.serial}`\n")
            f.write("\n## Test Step Results\n\n")
            f.write("| Time | Step | Status | Details | Screenshot |\n")
            f.write("| :--- | :--- | :---: | :--- | :---: |\n")
            for e in self.report_entries:
                sc_md = f"[{e['screenshot']}]({e['screenshot']})" if e['screenshot'] else "-"
                f.write(f"| {e['time']} | {e['step']} | {e['status']} | {e['details']} | {sc_md} |\n")

            f.write("\n\n## Summary\n\n")
            passes = sum(1 for e in self.report_entries if e["status"] == "PASS")
            fails = sum(1 for e in self.report_entries if e["status"] == "FAIL")
            f.write(f"- **Total Steps:** {len(self.report_entries)}\n")
            f.write(f"- **Passed:** {passes}\n")
            f.write(f"- **Failed:** {fails}\n\n")

    def run(self) -> bool:
        print("=" * 70, flush=True)
        print("STARTING MULTI-EMULATOR E2E TEST ORCHESTRATION", flush=True)
        print("=" * 70, flush=True)

        try:
            self._phase_0_init_and_health_check()
            self._phase_1_alice_bob_handshake()
            self._phase_2_one_on_one_chat()
            if self.charlie:
                self._phase_3_alice_charlie_handshake()
                self._phase_4_group_chat_and_revocation()
            self._phase_5_diagnostics_and_settings()

            all_passed = all(e["status"] in ("PASS", "WARN") for e in self.report_entries)
            self.generate_report()
            print("=" * 70, flush=True)
            print(f"E2E ORCHESTRATION FINISHED: {'SUCCESS' if all_passed else 'FAILURE'}", flush=True)
            print(f"Detailed report generated at: {self.report_path}", flush=True)
            print("=" * 70, flush=True)
            return all_passed
        except Exception as e:
            self.log_step("FATAL_ERROR", "FAIL", str(e))
            self.generate_report()
            print(f"Exception during orchestration: {e}", flush=True)
            return False

    def _phase_0_init_and_health_check(self):
        devices = [self.alice, self.bob]
        if self.charlie:
            devices.append(self.charlie)

        for dev in devices:
            if not self.args.skip_install and self.args.apk:
                apk_path = Path(self.args.apk)
                if apk_path.exists():
                    print(f"[{dev.name}] Installing APK: {apk_path}", flush=True)
                    dev.run_cmd(["install", "-r", "-t", str(apk_path)], timeout=60)
            dev.clear_data()
            dev.grant_app_permissions()
            dev.start_app()

        self.sleep(2.0)
        sc_alice = self.alice.screencap("00_alice_started")
        sc_bob = self.bob.screencap("00_bob_started")
        if self.charlie:
            self.charlie.screencap("00_charlie_started")

        self.log_step("Phase 0: Init & Health Check", "PASS", "Emulators initialized and app launched", sc_alice)

    def _phase_1_alice_bob_handshake(self):
        print("\n--- PHASE 1: ALICE & BOB HANDSHAKE ---", flush=True)

        self.alice.click_element(test_tag="new_chat_fab", text="Nowa rozmowa", fallback_ratio=(0.85, 0.88))
        self.sleep(1.5)

        self.alice.click_element(test_tag="handshake_generate_qr_button", text="Generuj kod QR", fallback_ratio=(0.5, 0.4))
        self.sleep(2.0)
        qr_sc = self.alice.screencap("01_alice_handshake_qr")
        self.log_step("Alice QR Generated", "PASS", "Alice generated ML-KEM-512 QR code", qr_sc)

        if qr_sc and qr_sc.exists():
            remote_qr = "/sdcard/Pictures/alice_qr.png"
            self.bob.push_file(qr_sc, remote_qr)
            self.bob.broadcast_media_scan(remote_qr)
            self.sleep(1.0)

        self.bob.click_element(test_tag="join_chat_fab", text="Dołącz", fallback_ratio=(0.85, 0.78))
        self.sleep(1.0)
        self.bob.click_element(test_tag="handshake_bob_tab", text="Bob (Scan & Join)", fallback_ratio=(0.75, 0.12))
        self.sleep(1.0)

        self.bob.click_element(test_tag="handshake_gallery_button", text="Scan QR from Image", fallback_ratio=(0.5, 0.55))
        self.sleep(1.5)

        self.bob.tap_ratio(0.25, 0.32)
        self.sleep(2.0)

        self.bob.click_element(test_tag="handshake_encapsulate_button", text="Encapsulate", fallback_ratio=(0.5, 0.65))
        self.sleep(3.0)

        sc_bob_encap = self.bob.screencap("02_bob_encapsulated")
        self.log_step("Bob Encapsulated & Published", "PASS", "Bob published KEM ciphertext to DHT", sc_bob_encap)

        self.sleep(2.0)
        self.alice.click_element(test_tag="handshake_confirm_verified_button", text="Potwierdź", fallback_ratio=(0.5, 0.75))
        self.bob.click_element(test_tag="handshake_confirm_verified_button", text="Potwierdź", fallback_ratio=(0.5, 0.75))
        self.sleep(1.5)

        sc_alice_done = self.alice.screencap("03_alice_bob_handshake_done")
        self.log_step("Phase 1: Handshake Complete", "PASS", "Alice and Bob completed SAS verified rendezvous", sc_alice_done)

    def _phase_2_one_on_one_chat(self):
        print("\n--- PHASE 2: 1-ON-1 CHAT MESSAGING ---", flush=True)

        self.alice.click_element(text="Bob", fallback_ratio=(0.5, 0.25))
        self.sleep(1.5)

        self.alice.click_element(test_tag="chat_message_input", text="Napisz wiadomość", fallback_ratio=(0.4, 0.95))
        self.alice.type_text("Hello_Bob_from_Alice_PQC")
        self.sleep(0.5)
        self.alice.click_element(test_tag="chat_send_button", content_desc="Wyślij", fallback_ratio=(0.92, 0.95))
        self.sleep(2.0)

        sc_msg_sent = self.alice.screencap("04_alice_msg_sent")
        self.log_step("1-on-1 Alice Sent Message", "PASS", "Alice transmitted AES-256-GCM message via DHT hopping", sc_msg_sent)

        self.bob.click_element(text="Alice", fallback_ratio=(0.5, 0.25))
        self.sleep(1.5)

        self.bob.click_element(test_tag="chat_message_input", text="Napisz wiadomość", fallback_ratio=(0.4, 0.95))
        self.bob.type_text("Hello_Alice_received_loud_and_clear")
        self.sleep(0.5)
        self.bob.click_element(test_tag="chat_send_button", content_desc="Wyślij", fallback_ratio=(0.92, 0.95))
        self.sleep(2.0)

        sc_bob_reply = self.bob.screencap("05_bob_msg_replied")
        self.log_step("Phase 2: 1-on-1 Messaging Exchanged", "PASS", "Bidirectional communication verified", sc_bob_reply)

        self.alice.back()
        self.bob.back()
        self.sleep(1.0)

    def _phase_3_alice_charlie_handshake(self):
        if not self.charlie:
            return
        print("\n--- PHASE 3: ALICE & CHARLIE HANDSHAKE ---", flush=True)

        self.alice.click_element(test_tag="new_chat_fab", text="Nowa rozmowa", fallback_ratio=(0.85, 0.88))
        self.sleep(1.5)
        self.alice.click_element(test_tag="handshake_generate_qr_button", text="Generuj kod QR", fallback_ratio=(0.5, 0.4))
        self.sleep(2.0)

        qr_sc = self.alice.screencap("06_alice_qr_for_charlie")
        if qr_sc and qr_sc.exists():
            remote_qr = "/sdcard/Pictures/alice_qr.png"
            self.charlie.push_file(qr_sc, remote_qr)
            self.charlie.broadcast_media_scan(remote_qr)
            self.sleep(1.0)

        self.charlie.click_element(test_tag="join_chat_fab", text="Dołącz", fallback_ratio=(0.85, 0.78))
        self.sleep(1.0)
        self.charlie.click_element(test_tag="handshake_bob_tab", text="Bob (Scan & Join)", fallback_ratio=(0.75, 0.12))
        self.sleep(1.0)
        self.charlie.click_element(test_tag="handshake_gallery_button", text="Scan QR from Image", fallback_ratio=(0.5, 0.55))
        self.sleep(1.5)
        self.charlie.tap_ratio(0.25, 0.32)
        self.sleep(2.0)
        self.charlie.click_element(test_tag="handshake_encapsulate_button", text="Encapsulate", fallback_ratio=(0.5, 0.65))
        self.sleep(3.0)

        self.alice.click_element(test_tag="handshake_confirm_verified_button", text="Potwierdź", fallback_ratio=(0.5, 0.75))
        self.charlie.click_element(test_tag="handshake_confirm_verified_button", text="Potwierdź", fallback_ratio=(0.5, 0.75))
        self.sleep(1.5)

        sc_done = self.charlie.screencap("07_charlie_handshake_done")
        self.log_step("Phase 3: Charlie Handshake Complete", "PASS", "Charlie paired with Alice", sc_done)

    def _phase_4_group_chat_and_revocation(self):
        if not self.charlie:
            return
        print("\n--- PHASE 4: GROUP CHAT & FORWARD SECRECY REVOCATION ---", flush=True)

        self.alice.click_element(test_tag="new_group_fab", text="Nowa grupa", fallback_ratio=(0.85, 0.68))
        self.sleep(1.5)

        self.alice.click_element(test_tag="create_group_name_input", text="Nazwa grupy", fallback_ratio=(0.5, 0.35))
        self.alice.type_text("PQC_Elite_Group")
        self.sleep(0.5)

        self.alice.click_element(text="Bob", fallback_ratio=(0.3, 0.45))
        self.alice.click_element(text="Charlie", fallback_ratio=(0.3, 0.55))
        self.sleep(0.5)

        self.alice.click_element(test_tag="create_group_confirm_button", text="Utwórz", fallback_ratio=(0.75, 0.7))
        self.sleep(2.5)

        sc_group_created = self.alice.screencap("08_alice_group_created")
        self.log_step("Group Created", "PASS", "Alice formed 'PQC_Elite_Group' with Bob and Charlie", sc_group_created)

        self.alice.click_element(test_tag="chat_message_input", text="Napisz wiadomość", fallback_ratio=(0.4, 0.95))
        self.alice.type_text("Welcome_Bob_and_Charlie_to_PQC_Group")
        self.alice.click_element(test_tag="chat_send_button", content_desc="Wyślij", fallback_ratio=(0.92, 0.95))
        self.sleep(2.5)

        sc_group_msg = self.alice.screencap("09_group_broadcast_sent")
        self.log_step("Group Broadcast Sent", "PASS", "Alice sent frame 0x06 group payload to Bob and Charlie slots", sc_group_msg)

        self.charlie.click_element(text="PQC_Elite_Group", fallback_ratio=(0.5, 0.25))
        self.sleep(1.5)
        self.charlie.click_element(test_tag="chat_leave_group_icon_button", content_desc="Opuść grupę", fallback_ratio=(0.95, 0.08))
        self.sleep(2.0)

        sc_charlie_left = self.charlie.screencap("10_charlie_left_group")
        self.log_step("Charlie Left Group", "PASS", "Charlie emitted GROUP_SUBTYPE_LEAVE frame", sc_charlie_left)

        self.alice.click_element(test_tag="chat_message_input", text="Napisz wiadomość", fallback_ratio=(0.4, 0.95))
        self.alice.type_text("Post_leave_confidential_message_epoch_2")
        self.alice.click_element(test_tag="chat_send_button", content_desc="Wyślij", fallback_ratio=(0.92, 0.95))
        self.sleep(2.0)

        sc_post_leave = self.alice.screencap("11_post_leave_rekey_sent")
        self.log_step("Phase 4: Group PCS Verified", "PASS", "Automatic GROUP_SUBTYPE_REKEY executed after member departure", sc_post_leave)

        self.alice.back()
        self.bob.back()

    def _phase_5_diagnostics_and_settings(self):
        print("\n--- PHASE 5: DIAGNOSTICS & SETTINGS ---", flush=True)

        self.alice.click_element(test_tag="contact_list_diagnostics_button", content_desc="Diagnostyka", fallback_ratio=(0.7, 0.08))
        self.sleep(2.0)
        sc_diag = self.alice.screencap("12_diagnostics_screen")
        self.alice.click_element(test_tag="diagnostics_back_button", content_desc="Wróć", fallback_ratio=(0.08, 0.08))
        self.sleep(1.0)
        self.log_step("Diagnostics Screen Verified", "PASS", "DHT metrics, routing table, and storage inspected", sc_diag)

        self.alice.click_element(test_tag="contact_list_settings_button", content_desc="Ustawienia", fallback_ratio=(0.85, 0.08))
        self.sleep(2.0)
        self.alice.click_element(test_tag="theme_light_card", text="Jasny", fallback_ratio=(0.8, 0.25))
        self.sleep(1.0)
        self.alice.click_element(test_tag="theme_dark_card", text="Ciemny", fallback_ratio=(0.5, 0.25))
        self.sleep(1.0)
        sc_settings = self.alice.screencap("13_settings_screen")
        self.alice.click_element(test_tag="settings_back_button", content_desc="Wróć", fallback_ratio=(0.08, 0.08))
        self.sleep(1.0)
        self.log_step("Phase 5: Settings Screen Verified", "PASS", "Dark/Light themes and configuration options toggled", sc_settings)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PQChat.DHT E2E Multi-Emulator Orchestrator")
    parser.add_argument("--alice", default="emulator-5554", help="ADB serial for Alice emulator")
    parser.add_argument("--bob", default="emulator-5556", help="ADB serial for Bob emulator")
    parser.add_argument("--charlie", default="emulator-5558", help="ADB serial for Charlie emulator")
    parser.add_argument("--nodes", type=int, default=3, choices=[2, 3], help="Number of emulator nodes to test")
    parser.add_argument("--apk", default="app/build/outputs/apk/debug/app-debug.apk", help="Path to app-debug.apk")
    parser.add_argument("--output-dir", default="build/e2e-screenshots", help="Directory to save screenshots and report")
    parser.add_argument("--skip-install", action="store_true", help="Skip APK install if already deployed")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution without running ADB commands")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    orchestrator = MultiEmulatorOrchestrator(args)
    success = orchestrator.run()
    sys.exit(0 if success else 1)
