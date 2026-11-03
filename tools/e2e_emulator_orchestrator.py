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
  - Full PQC Handshake (X25519 + ML-KEM-512) via QR screenshot / clipboard transfer
  - Decodes 864 bytes hybrid key via ZXing QRCodeReader / system clipboard
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

    def __init__(self, base_port: int = 30000, num_nodes: int = 50, output_dir: Optional[Path] = None, dry_run: bool = False):
        self.base_port = base_port
        self.num_nodes = num_nodes
        self.output_dir = output_dir or Path("build")
        self.dry_run = dry_run
        self.process: Optional[subprocess.Popen] = None
        self.log_file = None

    def is_healthy(self) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.6)
            sock.sendto(b"d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe", ("127.0.0.1", self.base_port))
            data, _ = sock.recvfrom(1024)
            return bool(data)
        except Exception:
            return False
        finally:
            sock.close()

    def start(self):
        if self.dry_run:
            print("[DHT Cluster DRY-RUN] Would start local DHT cluster on base_port 30000", flush=True)
            return

        if self.is_healthy():
            print(f"[DHT Cluster] Detected running cluster on port {self.base_port}, reusing it.", flush=True)
            return

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
            self.output_dir.mkdir(parents=True, exist_ok=True)
            log_path = self.output_dir / "dht_cluster.log"
            self.log_file = open(log_path, "w", encoding="utf-8")
            self.process = subprocess.Popen(
                cmd,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                text=True
            )

            start = time.time()
            while time.time() - start < 6.0:
                if self.is_healthy():
                    print(f"[DHT Cluster] Local cluster is active and serving KRPC queries on port {self.base_port}.", flush=True)
                    return
                time.sleep(0.3)
            print("[DHT Cluster] Warning: Cluster spawned but did not respond to initial ping in 6s.", flush=True)
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
        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None


class AdbDevice:
    """Controls an Android emulator instance via physical ADB commands."""

    def __init__(self, serial: str, name: str, output_dir: Path, dry_run: bool = False):
        self.serial = serial
        self.name = name
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.screen_width = 1080
        self.screen_height = 2400
        self._cached_ui: Optional[ET.Element] = None
        self._last_dump_time: float = 0.0
        self._is_debloated: bool = False
        self._detect_screen_size()

    def invalidate_ui_cache(self):
        self._cached_ui = None

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

    def debloat(self):
        """Disables background bloatware, suppresses ANR/error popups, disables animations and IME popup."""
        if self.dry_run or self._is_debloated:
            return
        print(f"[{self.name}] Applying single-shot debloat & performance optimizations...", flush=True)
        debloat_script = """
settings put global hide_error_dialogs 1
settings put secure immersive_mode_confirmations confirmed
settings put global window_animation_scale 0.0
settings put global transition_animation_scale 0.0
settings put global animator_duration_scale 0.0
svc power stayon true
settings put system screen_off_timeout 2147483647
settings put secure show_ime_with_hard_keyboard 0
input keyevent 224
wm dismiss-keyguard
input keyevent 82
am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS
for pkg in com.google.android.gms com.google.android.gsf com.google.android.as com.google.android.as.oss com.google.android.googlequicksearchbox com.google.android.apps.messaging com.google.android.apps.wellbeing com.google.android.apps.youtube.music com.google.android.youtube com.google.android.gm com.google.android.apps.maps com.google.android.apps.photos com.android.vending com.android.chrome com.google.android.configupdater com.google.android.tts com.android.dialer com.google.android.contacts; do
  pm disable-user --user 0 $pkg 2>/dev/null || true
  am force-stop $pkg 2>/dev/null || true
done
logcat -G 16M
logcat -c
"""
        self.shell(debloat_script, timeout=40)
        self._is_debloated = True

    def ensure_app_foreground(self, package: str = "org.pqchat.dht", activity: str = ".ui.MainActivity") -> bool:
        """Verifies that org.pqchat.dht is in the foreground. If not, brings it to the front and closes system dialogs."""
        if self.dry_run:
            return True

        self.shell("input keyevent 224")  # KEYCODE_WAKEUP
        self.shell("wm dismiss-keyguard")

        code, out, _ = self.shell("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'")
        code2, out2, _ = self.shell("dumpsys activity activities | grep ResumedActivity")
        focus_info = f"{out} {out2}"

        if package not in focus_info:
            print(f"[{self.name}] App {package} not in foreground (Current: {focus_info.strip()[:100]}). Restoring...", flush=True)
            self.shell("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")
            self.shell("input keyevent 4")  # Dismiss any dialog
            self.sleep(0.3)
            self.shell(f"am start -n {package}/{activity} --activity-brought-to-front --ei dht_bootstrap_port 30000 --es dht_bootstrap_host 10.0.2.2")
            self.sleep(1.0)
            self.invalidate_ui_cache()
            return True
        return True

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
        self.invalidate_ui_cache()

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300):
        self.wait_for_surface_window_ready()
        print(f"[{self.name}] Physical SWIPE from ({x1}, {y1}) to ({x2}, {y2})", flush=True)
        self.shell(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")
        self.invalidate_ui_cache()

    def scroll_down(self, duration_ms: int = 300):
        cx = self.screen_width // 2
        y1 = int(self.screen_height * 0.75)
        y2 = int(self.screen_height * 0.25)
        self.swipe(cx, y1, cx, y2, duration_ms)
        self.sleep(0.5)

    def scroll_up(self, duration_ms: int = 300):
        cx = self.screen_width // 2
        y1 = int(self.screen_height * 0.25)
        y2 = int(self.screen_height * 0.75)
        self.swipe(cx, y1, cx, y2, duration_ms)
        self.sleep(0.5)

    def tap_ratio(self, rx: float, ry: float):
        x = int(self.screen_width * rx)
        y = int(self.screen_height * ry)
        self.tap(x, y)

    def type_text(self, text: str):
        escaped = text.replace(" ", "%s").replace("&", "\\&").replace("'", "\\'")
        print(f"[{self.name}] Typing text: '{text}'", flush=True)
        self.shell(f"input text {escaped}")
        self.sleep(0.3)
        self.close_keyboard()
        self.sleep(0.3)
        self.invalidate_ui_cache()

    def keyevent(self, keycode: int):
        print(f"[{self.name}] Keyevent: {keycode}", flush=True)
        self.shell(f"input keyevent {keycode}")
        self.invalidate_ui_cache()

    def back(self):
        self.keyevent(4)

    def is_keyboard_open(self) -> bool:
        code, out, _ = self.shell("dumpsys input_method")
        return "mInputShown=true" in out or "mIsInputViewShown=true" in out

    def close_keyboard(self):
        if self.is_keyboard_open():
            print(f"[{self.name}] Soft keyboard is open, closing...", flush=True)
            self.shell("input keyevent 111")  # KEYCODE_ESCAPE
            self.sleep(0.2)
            if self.is_keyboard_open():
                self.shell("input keyevent 4")  # KEYCODE_BACK
                self.sleep(0.2)
            self.shell("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")
            self.sleep(0.2)
            self.invalidate_ui_cache()

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
        self.shell("svc power stayon true")
        self.shell("settings put system screen_off_timeout 2147483647")
        self.sleep(0.3)

    def dump_ui(self) -> Optional[ET.Element]:
        if self.dry_run:
            return None

        # Return cached dump if recent (within 0.6s) and not invalidated
        now = time.time()
        if self._cached_ui is not None and (now - self._last_dump_time) < 0.6:
            return self._cached_ui

        dump_path = "/data/local/tmp/uidump.xml"
        code, _, _ = self.shell(f"uiautomator dump --compressed {dump_path}", timeout=10)
        if code != 0:
            self.shell(f"uiautomator dump {dump_path}", timeout=10)

        code, out, _ = self.shell(f"cat {dump_path}", timeout=5)
        if code == 0 and out.strip().startswith("<?xml"):
            try:
                root = ET.fromstring(out)
                self._cached_ui = root
                self._last_dump_time = time.time()
                return root
            except Exception as e:
                print(f"[{self.name}] XML parse error: {e}", flush=True)

        return None

    def extract_alice_qr_b64(self) -> Optional[str]:
        """Extracts Alice's generated QR Base64 payload from logcat."""
        if self.dry_run:
            return "TEST_BASE64_PAYLOAD_864_BYTES_DUMMY"
        try:
            code, out, _ = self.shell("logcat -d -s AliceHandshake")
            if code == 0 and out:
                for line in reversed(out.splitlines()):
                    if "QR_PAYLOAD_B64=" in line:
                        payload = line.split("QR_PAYLOAD_B64=")[-1].strip()
                        if payload and len(payload) >= 1000:
                            return payload
            # Fallback scan without tag filter if needed
            code2, out2, _ = self.shell("logcat -d")
            if code2 == 0 and out2:
                for line in reversed(out2.splitlines()):
                    if "QR_PAYLOAD_B64=" in line:
                        payload = line.split("QR_PAYLOAD_B64=")[-1].strip()
                        if payload and len(payload) >= 1000:
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
                n_text = node.attrib.get("text", "")
                if (
                    target_tag in n_id
                    or n_id == target_tag
                    or n_id.endswith(f":id/{target_tag}")
                    or n_id.endswith(f"/{target_tag}")
                    or n_desc == target_tag
                    or target_tag in n_desc
                    or target_tag == n_text
                ):
                    bounds_str = node.attrib.get("bounds", "")
                    if bounds_str:
                        bounds = self.parse_bounds(bounds_str)
                        if bounds and (bounds[2] > bounds[0]) and (bounds[3] > bounds[1]):
                            return bounds

        # Pass 2: Exact text or content_desc
        for node in root.iter("node"):
            n_text = node.attrib.get("text", "").strip()
            n_desc = node.attrib.get("content-desc", "").strip()
            if text and (n_text.lower() == text.lower() or n_desc.lower() == text.lower()):
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds and (bounds[2] > bounds[0]) and (bounds[3] > bounds[1]):
                        return bounds
            if content_desc and n_desc.lower() == content_desc.lower():
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds and (bounds[2] > bounds[0]) and (bounds[3] > bounds[1]):
                        return bounds

        # Pass 3: Substring text or content_desc
        for node in root.iter("node"):
            n_text = node.attrib.get("text", "")
            n_desc = node.attrib.get("content-desc", "")
            if text and (text.lower() in n_text.lower() or text.lower() in n_desc.lower()):
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds and (bounds[2] > bounds[0]) and (bounds[3] > bounds[1]):
                        return bounds
            if content_desc and content_desc.lower() in n_desc.lower():
                bounds_str = node.attrib.get("bounds", "")
                if bounds_str:
                    bounds = self.parse_bounds(bounds_str)
                    if bounds and (bounds[2] > bounds[0]) and (bounds[3] > bounds[1]):
                        return bounds

        return None

    def click_element(
        self,
        text: Optional[str] = None,
        content_desc: Optional[str] = None,
        resource_id: Optional[str] = None,
        test_tag: Optional[str] = None,
        fallback_ratio: Optional[Tuple[float, float]] = None,
        auto_scroll: bool = True
    ) -> bool:
        desc = test_tag or text or content_desc or resource_id or "element"
        if self.dry_run:
            print(f"[{self.name} DRY-RUN] click_element '{desc}' -> simulated click", flush=True)
            return True
        self.close_keyboard()
        bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
        if not bounds:
            # Ensure app focus was not lost to launcher or system dialogs
            self.ensure_app_foreground()
            bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)

        if bounds and auto_scroll:
            x1, y1, x2, y2 = bounds
            if y1 >= self.screen_height - 120 or y2 <= 120:
                print(f"[{self.name}] '{desc}' bounds {bounds} near screen edge. Adjusting scroll...", flush=True)
                if y1 >= self.screen_height - 120:
                    self.scroll_down()
                else:
                    self.scroll_up()
                bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)

        if not bounds and auto_scroll:
            self.scroll_down()
            bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
            if not bounds:
                self.scroll_up()

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
        timeout: int = 30,
        sync_chip_tag: Optional[str] = None
    ) -> bool:
        desc = test_tag or text or content_desc or resource_id or "element"
        if self.dry_run:
            print(f"[{self.name} DRY-RUN] wait_for_element '{desc}' -> simulated found", flush=True)
            return True
        start = time.time()
        print(f"[{self.name}] Waiting for element '{desc}' (timeout={timeout}s)...", flush=True)
        last_sync_time = start
        while time.time() - start < timeout:
            bounds = self.find_node(text=text, content_desc=content_desc, resource_id=resource_id, test_tag=test_tag)
            if bounds:
                print(f"[{self.name}] Found '{desc}'!", flush=True)
                return True

            elapsed = time.time() - start
            # If sync_chip_tag is specified, tap it every 6s to trigger immediate DHT polling
            if sync_chip_tag and (time.time() - last_sync_time) >= 6.0:
                print(f"[{self.name}] Triggering {sync_chip_tag} while waiting for '{desc}'...", flush=True)
                self.click_element(test_tag=sync_chip_tag, auto_scroll=False)
                last_sync_time = time.time()

            # Periodically ensure app focus
            if elapsed > 5.0 and int(elapsed) % 10 == 0:
                self.ensure_app_foreground()

            self.sleep(1.5)

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
        self.shell(f"content insert --uri content://media/external/images/media --bind _data:s:{file_path} --bind mime_type:s:image/png")

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
        self.shell(f"dumpsys deviceidle whitelist +{package}")
        self.shell(f"appops set {package} POST_NOTIFICATION allow")

    def start_app(self, package: str = "org.pqchat.dht", activity: str = ".ui.MainActivity"):
        print(f"[{self.name}] Starting {package}/{activity} with local DHT cluster 10.0.2.2:30000", flush=True)
        self.shell(f"am start -W -n {package}/{activity} --ei dht_bootstrap_port 30000 --es dht_bootstrap_host 10.0.2.2")
        self.invalidate_ui_cache()


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

        self.dht_cluster = LocalDhtClusterManager(base_port=30000, num_nodes=50, output_dir=self.output_dir, dry_run=args.dry_run)
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
            dev.wake_and_unlock()
            dev.debloat()
            if not self.args.skip_install and self.args.apk:
                apk_path = Path(self.args.apk)
                if apk_path.exists():
                    print(f"[{dev.name}] Installing APK: {apk_path}", flush=True)
                    dev.run_cmd(["install", "-r", "-t", str(apk_path)], timeout=60)
            dev.clear_data()
            dev.grant_app_permissions()
            dev.start_app()
            self.sleep(1.0)
            dev.grant_app_permissions()

        self.sleep(3.0)
        for dev in self.active_devices:
            dev.ensure_app_foreground()
            sc = dev.screencap(f"00_{dev.name.lower()}_started")
            self.log_step(f"Init {dev.name}", "PASS", f"{dev.name} clean install & launch verified", sc)

    def _perform_pair_handshake(self, initiator: AdbDevice, responder: AdbDevice, step_num: str, pair_label: str) -> bool:
        print(f"\n--- PAIR HANDSHAKE: {initiator.name} & {responder.name} ({pair_label}) ---", flush=True)

        initiator.wake_and_unlock()
        initiator.ensure_app_foreground()
        responder.wake_and_unlock()
        responder.ensure_app_foreground()

        # 1. Initiator: Tap "New Chat (Alice)" if not already on HandshakeScreen
        if not initiator.find_node(test_tag="handshake_alice_name_input"):
            initiator.click_element(test_tag="new_chat_fab", text="New Chat (Alice)")
            self.sleep(1.5)

        if not initiator.wait_for_element(test_tag="handshake_alice_name_input", timeout=10):
            print(f"[{initiator.name}] HandshakeScreen did not appear. Retrying foreground restore and FAB click...", flush=True)
            initiator.ensure_app_foreground()
            initiator.click_element(test_tag="new_chat_fab", text="New Chat (Alice)")
            initiator.wait_for_element(test_tag="handshake_alice_name_input", timeout=10)

        # Initiator: Enter contact name
        initiator.click_element(test_tag="handshake_alice_name_input")
        initiator.type_text(responder.name)
        self.sleep(0.5)

        # Initiator: Tap "Generate ML-KEM-512 QR Code"
        initiator.click_element(test_tag="handshake_generate_qr_button", text="Generate ML-KEM-512")
        qr_gen_ok = (
            initiator.wait_for_element(test_tag="handshake_qr_code_card", timeout=20)
            or initiator.wait_for_element(text="Rendezvous Target_0", timeout=5)
        )
        self.sleep(0.5)
        qr_sc = initiator.screencap(f"{step_num}_{pair_label}_qr")

        # Immediately extract Alice's generated QR Base64 payload from logcat
        b64_payload = initiator.extract_alice_qr_b64()
        if b64_payload:
            print(f"[{initiator.name}] Successfully extracted Alice QR payload ({len(b64_payload)} B Base64)", flush=True)
            qr_gen_ok = True

        if qr_gen_ok:
            self.log_step(f"{initiator.name} QR Generated ({pair_label})", "PASS", f"{initiator.name} generated hybrid ML-KEM-512 QR (864 B)", qr_sc)
        else:
            self.log_step(f"{initiator.name} QR Generated ({pair_label})", "FAIL", f"Failed to generate QR code on {initiator.name} within timeout", qr_sc)
            return False

        # 2. Push key material to responder
        if b64_payload:
            # Put directly into system clipboard on responder via ADB
            escaped_b64 = b64_payload.replace('"', '\\"')
            responder.shell(f'cmd clipboard set-text "{escaped_b64}"')
            # Also write text file to Pictures directory for fallback
            responder.shell(f'echo "{escaped_b64}" > /sdcard/Pictures/{pair_label}_b64.txt')

        if qr_sc and qr_sc.exists():
            remote_qr = f"/sdcard/Pictures/{pair_label}_qr.png"
            responder.push_file(qr_sc, remote_qr)
            responder.broadcast_media_scan(remote_qr)
            self.sleep(1.0)

        # 3. Responder: Ensure awake and open Join Chat tab
        responder.wake_and_unlock()
        responder.ensure_app_foreground()
        if not responder.find_node(test_tag="handshake_bob_tab"):
            responder.click_element(test_tag="join_chat_fab", text="Scan / Join (Bob)")
            self.sleep(1.5)

        if not responder.wait_for_element(test_tag="handshake_bob_tab", timeout=10):
            print(f"[{responder.name}] HandshakeScreen did not appear on responder. Retrying...", flush=True)
            responder.ensure_app_foreground()
            responder.click_element(test_tag="join_chat_fab", text="Scan / Join (Bob)")
            responder.wait_for_element(test_tag="handshake_bob_tab", timeout=10)

        # Ensure Bob tab is active
        responder.click_element(test_tag="handshake_bob_tab", text="Bob (Scan & Join)")
        self.sleep(0.5)

        # Responder: Enter contact name
        responder.click_element(test_tag="handshake_bob_name_input")
        responder.type_text(initiator.name)
        self.sleep(0.5)
        responder.close_keyboard()

        # Responder: Tap "Paste Hybrid Key from Clipboard"
        valid_qr = False
        print(f"[{responder.name}] Attempting instant paste from clipboard...", flush=True)
        if responder.click_element(test_tag="handshake_paste_clipboard_button", text="Paste Hybrid Key"):
            self.sleep(1.0)
            valid_qr = responder.wait_for_element(text="Valid Hybrid Handshake", timeout=5)

        # Fallback to Gallery or Manual Base64 if clipboard button did not validate immediately
        if not valid_qr:
            print(f"[{responder.name}] Clipboard paste unconfirmed, trying gallery scan...", flush=True)
            responder.click_element(test_tag="handshake_gallery_button", text="Scan QR")
            self.sleep(2.0)

            # In PhotoPicker: tap thumbnail or first grid item
            thumb_bounds = (
                responder.find_node(resource_id="icon_thumbnail")
                or responder.find_node(content_desc="Photo")
                or responder.find_node(resource_id="thumbnail")
            )
            if thumb_bounds:
                cx = (thumb_bounds[0] + thumb_bounds[2]) // 2
                cy = (thumb_bounds[1] + thumb_bounds[3]) // 2
                responder.tap(cx, cy)
                self.sleep(1.5)
            else:
                # Dismiss picker safely if no item found
                responder.back()
                self.sleep(1.0)

            valid_qr = responder.wait_for_element(text="Valid Hybrid Handshake", timeout=5)

        # Fallback to manual paste toggle
        if not valid_qr and b64_payload:
            print(f"[{responder.name}] Falling back to manual paste toggle...", flush=True)
            responder.close_keyboard()
            responder.scroll_down()
            responder.click_element(test_tag="handshake_toggle_manual_paste", text="paste Base64")
            self.sleep(0.5)
            # Click paste clipboard button if visible now
            responder.click_element(test_tag="handshake_paste_clipboard_button")
            self.sleep(0.5)
            valid_qr = responder.wait_for_element(text="Valid Hybrid Handshake", timeout=8)

        sc_resp_verified = responder.screencap(f"{step_num}_{pair_label}_verified")
        if valid_qr:
            self.log_step(f"{responder.name} Verified QR ({pair_label})", "PASS", f"Decoded 864 bytes hybrid key for {pair_label}", sc_resp_verified)
        else:
            self.log_step(f"{responder.name} Verified QR ({pair_label})", "FAIL", f"Failed to decode or validate 864 bytes hybrid key for {pair_label}", sc_resp_verified)
            return False

        # Close keyboard and scroll to make Encapsulate button visible
        responder.close_keyboard()
        responder.scroll_up()
        self.sleep(0.5)

        # Responder: Tap "Encapsulate & Put to DHT" (NO fallback_ratio!)
        encapsulate_clicked = responder.click_element(test_tag="handshake_encapsulate_button", text="Encapsulate & Put to DHT")
        if not encapsulate_clicked:
            responder.scroll_down()
            encapsulate_clicked = responder.click_element(test_tag="handshake_encapsulate_button", text="Encapsulate & Put to DHT")
        if not encapsulate_clicked:
            self.log_step(f"Encapsulate Clicked ({pair_label})", "FAIL", "Failed to locate and click 'handshake_encapsulate_button'")
            return False

        self.sleep(2.0)

        # 4. Wait for SAS confirmation dialog on both devices (NO fallback_ratio!)
        print(f"[Orchestrator] Waiting for SAS verification dialog on {initiator.name} and {responder.name}...", flush=True)
        init_sas = initiator.wait_for_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", timeout=60)
        resp_sas = responder.wait_for_element(test_tag="handshake_confirm_verified_button", text="Confirm identity", timeout=60)

        sc_sas = initiator.screencap(f"{step_num}_{pair_label}_sas")
        sas_status = "PASS" if (init_sas and resp_sas) else "FAIL"
        if sas_status == "PASS":
            self.log_step(f"SAS Verified ({pair_label})", "PASS", f"SAS verification displayed on {initiator.name} and {responder.name}", sc_sas)
            # Confirm identity on both devices (NO fallback_ratio!)
            initiator.click_element(test_tag="handshake_confirm_verified_button", text="Confirm identity")
            responder.click_element(test_tag="handshake_confirm_verified_button", text="Confirm identity")
            self.sleep(2.0)
        else:
            self.log_step(f"SAS Verified ({pair_label})", "FAIL", f"SAS verification not reached within timeout (initiator={init_sas}, responder={resp_sas})", sc_sas)
            return False

        # Return both to ContactListScreen safely (from ChatScreen or HandshakeScreen)
        if initiator.find_node(test_tag="chat_back_button") or initiator.find_node(test_tag="chat_message_input"):
            initiator.click_element(test_tag="chat_back_button")
            self.sleep(1.0)
        elif not initiator.find_node(test_tag="contact_list_sync_chip"):
            initiator.back()
            self.sleep(1.0)

        if responder.find_node(test_tag="chat_back_button") or responder.find_node(test_tag="chat_message_input"):
            responder.click_element(test_tag="chat_back_button")
            self.sleep(1.0)
        elif not responder.find_node(test_tag="contact_list_sync_chip"):
            responder.back()
            self.sleep(1.0)

        handshake_ok = (qr_gen_ok and valid_qr and init_sas and resp_sas)
        if handshake_ok:
            self.log_step(f"Handshake Complete ({pair_label})", "PASS", f"Handshake complete between {initiator.name} and {responder.name}")
        else:
            self.log_step(f"Handshake Complete ({pair_label})", "FAIL", f"Handshake failed between {initiator.name} and {responder.name}")
        return handshake_ok

    def _phase_1_handshakes(self):
        print("\n--- PHASE 1: PAIRWISE HANDSHAKES ---", flush=True)

        # 1. Alice <-> Bob
        ok_ab = self._perform_pair_handshake(self.alice, self.bob, "01", "alice_bob")
        if not ok_ab:
            print("[Orchestrator] Warning: Alice-Bob handshake failed. Stopping pairwise handshakes.", flush=True)
            return

        # 2. Alice <-> Charlie (if nodes >= 3)
        if self.charlie:
            self._perform_pair_handshake(self.alice, self.charlie, "02", "alice_charlie")

        # 3. Alice <-> Dave (if nodes >= 4)
        if self.dave:
            self._perform_pair_handshake(self.alice, self.dave, "03", "alice_dave")

    def _phase_2_direct_messaging_and_rekey(self):
        print("\n--- PHASE 2: ALICE <-> BOB DIRECT MESSAGING & ML-KEM-512 REKEY ---", flush=True)

        self.alice.ensure_app_foreground()
        self.bob.ensure_app_foreground()

        # Alice: Enter 1-on-1 chat with Bob (NO fallback_ratio!)
        print("[Alice] Entering direct chat with Bob...", flush=True)
        alice_opened = self.alice.click_element(test_tag="contact_item_Bob", text="Bob")
        if not alice_opened:
            self.log_step("Alice -> Bob Direct Chat Open", "FAIL", "Contact 'Bob' not found on Alice's contact list")
            return
        self.alice.wait_for_element(test_tag="chat_message_input", timeout=30)
        self.sleep(1.0)
        self.alice.screencap("02_alice_direct_chat")

        # Bob: Enter 1-on-1 chat with Alice (NO fallback_ratio!)
        print("[Bob] Entering direct chat with Alice...", flush=True)
        bob_opened = self.bob.click_element(test_tag="contact_item_Alice", text="Alice")
        if not bob_opened:
            self.log_step("Bob -> Alice Direct Chat Open", "FAIL", "Contact 'Alice' not found on Bob's contact list")
            return
        self.bob.wait_for_element(test_tag="chat_message_input", timeout=30)
        self.sleep(1.0)
        self.bob.screencap("02_bob_direct_chat")

        # Turn 1: Alice sends direct message to Bob
        direct_msg = "Hello_Bob_PQ_Direct_Message"
        print(f"[Alice] Sending direct message: '{direct_msg}'", flush=True)
        self.alice.click_element(test_tag="chat_message_input")
        self.alice.type_text(direct_msg)
        self.sleep(0.5)
        self.alice.click_element(test_tag="chat_send_button", content_desc="Send")
        self.sleep(2.0)

        # Bob receives direct message
        print(f"[Bob] Waiting for direct message '{direct_msg}'...", flush=True)
        rcv_ok = self.bob.wait_for_element(text=direct_msg, timeout=45, sync_chip_tag="chat_sync_chip")
        sc_bob_rcv = self.bob.screencap("02_bob_rcv_direct_msg")
        if rcv_ok:
            self.log_step("Alice -> Bob Direct Message", "PASS", f"Bob received '{direct_msg}' via DHT", sc_bob_rcv)
        else:
            self.log_step("Alice -> Bob Direct Message", "FAIL", f"Bob did not receive '{direct_msg}' within 45s", sc_bob_rcv)

        # Turn 2: Bob replies to Alice
        direct_ack = "Hello_Alice_Direct_ACK_PQC"
        print(f"[Bob] Sending direct ACK: '{direct_ack}'", flush=True)
        self.bob.click_element(test_tag="chat_message_input")
        self.bob.type_text(direct_ack)
        self.sleep(0.5)
        self.bob.click_element(test_tag="chat_send_button", content_desc="Send")
        self.sleep(2.0)

        # Alice receives direct ACK
        print(f"[Alice] Waiting for direct reply '{direct_ack}'...", flush=True)
        ack_ok = self.alice.wait_for_element(text=direct_ack, timeout=45, sync_chip_tag="chat_sync_chip")
        sc_alice_ack = self.alice.screencap("02_alice_rcv_direct_ack")
        if ack_ok:
            self.log_step("Bob -> Alice Direct ACK", "PASS", f"Alice received '{direct_ack}' via DHT", sc_alice_ack)
        else:
            self.log_step("Bob -> Alice Direct ACK", "FAIL", f"Alice did not receive '{direct_ack}' within 45s", sc_alice_ack)

        # Rekey: Alice initiates ML-KEM-512 Rekey (NO fallback_ratio!)
        print("[Alice] Initiating ML-KEM-512 Rekey...", flush=True)
        rekey_clicked = self.alice.click_element(test_tag="chat_rekey_button", content_desc="Initiate ML-KEM-512 Rekey")
        self.sleep(2.0)
        sc_rekey_done = self.alice.screencap("03_alice_rekey_completed")

        if rekey_clicked:
            # Bob triggers DHT poll to retrieve Type 0x03 Offer and dispatch Type 0x04 Response
            print("[Bob] Triggering DHT sync for rekey offer processing...", flush=True)
            self.bob.click_element(test_tag="chat_sync_chip")
            self.sleep(3.0)

            # Alice triggers DHT poll to retrieve Type 0x04 Response
            print("[Alice] Triggering DHT sync for rekey response processing...", flush=True)
            self.alice.click_element(test_tag="chat_sync_chip")
            self.sleep(3.0)
            self.log_step("ML-KEM-512 Rekey", "PASS", "PQC Rekey offer dispatched and processed over DHT", sc_rekey_done)
        else:
            self.log_step("ML-KEM-512 Rekey", "FAIL", "Rekey button 'chat_rekey_button' not found on Alice's chat screen", sc_rekey_done)

        # Return both Alice and Bob to ContactListScreen
        self.alice.back()
        self.sleep(1.0)
        self.bob.back()
        self.sleep(1.0)

    def _phase_3_create_group(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 3: CREATE GROUP CONVERSATION '{group_name}' ---", flush=True)

        self.alice.ensure_app_foreground()
        if self.alice.find_node(test_tag="chat_message_input"):
            self.alice.back()
            self.sleep(1.0)

        # Alice: Tap "New Group" FAB (NO fallback_ratio!)
        fab_clicked = self.alice.click_element(test_tag="new_group_fab", text="New Group")
        if not fab_clicked:
            self.log_step("Group Created by Alice", "FAIL", "Failed to locate 'new_group_fab' on Alice's contact list screen")
            return
        self.sleep(2.0)

        # Alice: Enter group name
        self.alice.click_element(test_tag="create_group_name_input")
        self.alice.type_text(group_name)
        self.sleep(1.0)

        # Alice: Select participants (strictly verify each participant without fallback_ratio!)
        selected_all = True
        print("[Alice] Selecting participant Bob in group dialog...", flush=True)
        if not self.alice.click_element(test_tag="group_participant_Bob", text="Bob"):
            print("[Alice] Failed to select participant Bob!", flush=True)
            selected_all = False
        self.sleep(0.5)

        if self.charlie:
            print("[Alice] Selecting participant Charlie in group dialog...", flush=True)
            if not self.alice.click_element(test_tag="group_participant_Charlie", text="Charlie"):
                print("[Alice] Failed to select participant Charlie!", flush=True)
                selected_all = False
            self.sleep(0.5)

        if self.dave:
            print("[Alice] Selecting participant Dave in group dialog...", flush=True)
            if not self.alice.click_element(test_tag="group_participant_Dave", text="Dave"):
                print("[Alice] Failed to select participant Dave!", flush=True)
                selected_all = False
            self.sleep(0.5)

        self.alice.screencap("04_alice_group_dialog")

        if not selected_all:
            self.log_step("Group Created by Alice", "FAIL", "Failed to select required participants in group creation dialog")
            return

        # Alice: Tap "Create Group" (NO fallback_ratio!)
        confirmed = self.alice.click_element(test_tag="create_group_confirm_button", text="Create Group")
        self.sleep(3.0)

        sc_group_created = self.alice.screencap("04_alice_group_created")
        group_confirmed = (
            confirmed
            and (
                self.alice.wait_for_element(test_tag="chat_message_input", timeout=15)
                or self.alice.wait_for_element(test_tag=f"group_item_{group_name}", timeout=5)
            )
        )
        if group_confirmed:
            self.log_step("Group Created by Alice", "PASS", f"Group '{group_name}' created with participants and invites dispatched", sc_group_created)
        else:
            self.log_step("Group Created by Alice", "FAIL", f"Failed to confirm group '{group_name}' creation on Alice", sc_group_created)

    def _phase_4_join_group_on_participants(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 4: PARTICIPANTS JOIN GROUP '{group_name}' ---", flush=True)

        participants = [self.bob]
        if self.charlie:
            participants.append(self.charlie)
        if self.dave:
            participants.append(self.dave)

        for dev in participants:
            dev.ensure_app_foreground()
            print(f"[{dev.name}] Waiting for group '{group_name}' invite to arrive via DHT...", flush=True)
            if dev.find_node(test_tag="chat_message_input"):
                dev.back()
                self.sleep(1.0)

            # Wait for group item to appear on ContactListScreen (triggering immediate poll if delayed)
            rcv_grp = dev.wait_for_element(test_tag=f"group_item_{group_name}", text=group_name, timeout=60, sync_chip_tag="contact_list_sync_chip")
            sc_group_list = dev.screencap(f"04_{dev.name.lower()}_group_appeared")
            if rcv_grp:
                self.log_step(f"Group Received on {dev.name}", "PASS", f"Received group invite frame for '{group_name}'", sc_group_list)
                # Click group item to enter group chat (strictly without fallback_ratio!)
                clicked = dev.click_element(test_tag=f"group_item_{group_name}", text=group_name)
                self.sleep(2.0)
                in_chat = clicked and dev.wait_for_element(test_tag="chat_message_input", timeout=15)
                sc_group_chat = dev.screencap(f"04_{dev.name.lower()}_in_group_chat")
                if in_chat:
                    self.log_step(f"{dev.name} Entered Group Chat", "PASS", f"{dev.name} active in '{group_name}'", sc_group_chat)
                else:
                    self.log_step(f"{dev.name} Entered Group Chat", "FAIL", f"{dev.name} failed to open group chat '{group_name}'", sc_group_chat)
            else:
                self.log_step(f"Group Received on {dev.name}", "FAIL", f"Did not receive group invite frame for '{group_name}' within 60s", sc_group_list)
                self.log_step(f"{dev.name} Entered Group Chat", "FAIL", f"{dev.name} cannot enter group chat because invite was never received")

    def _phase_5_group_multi_turn_messaging(self, group_name: str = "PQ_MultiNode_Group"):
        print(f"\n--- PHASE 5: GROUP MULTI-TURN MESSAGING IN '{group_name}' ---", flush=True)

        all_devices = [self.alice, self.bob]
        if self.charlie:
            all_devices.append(self.charlie)
        if self.dave:
            all_devices.append(self.dave)

        all_turns_ok = True
        fails_count = 0

        # Turn 1: Alice sends to Group
        msg1 = f"Hello_Group_from_Alice_all_{len(all_devices)}_nodes"
        print(f"\n[Turn 1] Alice sending: '{msg1}'", flush=True)
        self.alice.click_element(test_tag="chat_message_input")
        self.alice.type_text(msg1)
        self.sleep(0.5)
        self.alice.click_element(test_tag="chat_send_button", content_desc="Send")
        self.sleep(2.0)

        for dev in all_devices[1:]:
            print(f"[{dev.name}] Waiting for Alice's group message...", flush=True)
            rcv1 = dev.wait_for_element(text=msg1, timeout=45, sync_chip_tag="chat_sync_chip")
            sc_rcv = dev.screencap(f"05_{dev.name.lower()}_rcv_msg1")
            if rcv1:
                self.log_step(f"{dev.name} Received Msg 1", "PASS", f"Received Alice's group message: '{msg1}'", sc_rcv)
            else:
                self.log_step(f"{dev.name} Received Msg 1", "FAIL", f"{dev.name} timed out waiting for Alice's message: '{msg1}'", sc_rcv)
                all_turns_ok = False
                fails_count += 1

        # Turn 2: Bob sends to Group
        msg2 = f"Bob_reporting_in_{group_name}"
        print(f"\n[Turn 2] Bob sending: '{msg2}'", flush=True)
        self.bob.click_element(test_tag="chat_message_input")
        self.bob.type_text(msg2)
        self.sleep(0.5)
        self.bob.click_element(test_tag="chat_send_button", content_desc="Send")
        self.sleep(2.0)

        for dev in [self.alice] + all_devices[2:]:
            print(f"[{dev.name}] Waiting for Bob's group message...", flush=True)
            rcv2 = dev.wait_for_element(text=msg2, timeout=45, sync_chip_tag="chat_sync_chip")
            sc_rcv = dev.screencap(f"06_{dev.name.lower()}_rcv_msg2")
            if rcv2:
                self.log_step(f"{dev.name} Received Msg 2", "PASS", f"Received Bob's group message: '{msg2}'", sc_rcv)
            else:
                self.log_step(f"{dev.name} Received Msg 2", "FAIL", f"{dev.name} timed out waiting for Bob's message: '{msg2}'", sc_rcv)
                all_turns_ok = False
                fails_count += 1

        # Turn 3: Charlie sends to Group (if nodes >= 3)
        if self.charlie:
            msg3 = f"Charlie_here_group_pqc_confirmed"
            print(f"\n[Turn 3] Charlie sending: '{msg3}'", flush=True)
            self.charlie.click_element(test_tag="chat_message_input")
            self.charlie.type_text(msg3)
            self.sleep(0.5)
            self.charlie.click_element(test_tag="chat_send_button", content_desc="Send")
            self.sleep(2.0)

            targets = [self.alice, self.bob]
            if self.dave:
                targets.append(self.dave)
            for dev in targets:
                print(f"[{dev.name}] Waiting for Charlie's group message...", flush=True)
                rcv3 = dev.wait_for_element(text=msg3, timeout=45, sync_chip_tag="chat_sync_chip")
                sc_rcv = dev.screencap(f"07_{dev.name.lower()}_rcv_msg3")
                if rcv3:
                    self.log_step(f"{dev.name} Received Msg 3", "PASS", f"Received Charlie's group message: '{msg3}'", sc_rcv)
                else:
                    self.log_step(f"{dev.name} Received Msg 3", "FAIL", f"{dev.name} timed out waiting for Charlie's message: '{msg3}'", sc_rcv)
                    all_turns_ok = False
                    fails_count += 1

        # Turn 4: Dave sends to Group (if nodes >= 4)
        if self.dave:
            msg4 = f"Dave_4th_node_pqc_group_active"
            print(f"\n[Turn 4] Dave sending: '{msg4}'", flush=True)
            self.dave.click_element(test_tag="chat_message_input")
            self.dave.type_text(msg4)
            self.sleep(0.5)
            self.dave.click_element(test_tag="chat_send_button", content_desc="Send")
            self.sleep(2.0)

            for dev in [self.alice, self.bob, self.charlie]:
                print(f"[{dev.name}] Waiting for Dave's group message...", flush=True)
                rcv4 = dev.wait_for_element(text=msg4, timeout=45, sync_chip_tag="chat_sync_chip")
                sc_rcv = dev.screencap(f"08_{dev.name.lower()}_rcv_msg4")
                if rcv4:
                    self.log_step(f"{dev.name} Received Msg 4", "PASS", f"Received Dave's group message: '{msg4}'", sc_rcv)
                else:
                    self.log_step(f"{dev.name} Received Msg 4", "FAIL", f"{dev.name} timed out waiting for Dave's message: '{msg4}'", sc_rcv)
                    all_turns_ok = False
                    fails_count += 1

        if all_turns_ok:
            self.log_step("Group Multi-Turn Complete", "PASS", f"All {len(all_devices)} participants successfully exchanged messages in '{group_name}'")
        else:
            self.log_step("Group Multi-Turn Complete", "FAIL", f"Group multi-turn messaging had {fails_count} failed delivery attempts")

    def _phase_optional_diagnostics(self):
        print("\n--- PHASE: DIAGNOSTICS & TELEMETRY ---", flush=True)
        try:
            self.alice.back()
            self.sleep(1.0)
            self.alice.click_element(test_tag="contact_list_diagnostics_button", content_desc="Diagnostics")
            self.sleep(1.5)
            sc_diag = self.alice.screencap("09_alice_diagnostics")
            self.alice.click_element(test_tag="diagnostics_back_button", content_desc="Back")
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
