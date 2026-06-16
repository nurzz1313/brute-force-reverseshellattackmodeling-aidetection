from __future__ import annotations

import csv
import json
import math
import mimetypes
import subprocess
import shutil
import time
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "attack_detector.joblib"
RAW_LOG_PATH = BASE_DIR / "logs" / "raw_events.csv"
BLOCKLIST_PATH = BASE_DIR / "blocked_ips.json"
ALERTS_LOG_PATH = BASE_DIR / "alerts.log"
FIREWALL_LOG_PATH = BASE_DIR / "firewall_actions.log"

SUSPICIOUS_EXTENSIONS = {"php", "jsp", "aspx", "py", "sh", "exe", "bat", "js"}
BLOCK_MINUTES = 15
POLL_INTERVAL_SECONDS = 0.2


FAILED_IP_60 = defaultdict(deque)
FAILED_USER_60 = defaultdict(deque)
FAILED_IP_300 = defaultdict(deque)

LAST_EVENT_BY_IP: Dict[str, datetime] = {}
LAST_AUTH_BY_IP: Dict[str, datetime] = {}
LAST_UPLOAD_BY_IP: Dict[str, datetime] = {}
LAST_SUCCESS_LOGIN_BY_SESSION: Dict[str, datetime] = {}


@dataclass
class DetectorConfig:
    model_path: Path = MODEL_PATH
    raw_log_path: Path = RAW_LOG_PATH
    blocklist_path: Path = BLOCKLIST_PATH
    alerts_log_path: Path = ALERTS_LOG_PATH
    firewall_log_path: Path = FIREWALL_LOG_PATH
    block_minutes: int = BLOCK_MINUTES
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def cleanup_queue(q: deque, seconds: int, ts: datetime) -> None:
    cutoff = ts - timedelta(seconds=seconds)
    while q and q[0] < cutoff:
        q.popleft()


def expected_mime(file_ext: str) -> str:
    if not file_ext:
        return ""
    return mimetypes.guess_type(f"file.{file_ext}")[0] or ""


def mime_mismatch(file_ext: str, mime_type: str) -> int:
    exp = expected_mime(file_ext)
    if not exp or not mime_type:
        return 0
    return 1 if exp != mime_type else 0


def load_blocklist(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_blocklist(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_alert(path: Path, message: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(message + "\n")



def valid_block_target(ip: str) -> bool:
    """Return True only for normal remote IPs. Prevents command injection and accidental localhost blocks."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if obj.is_loopback or obj.is_unspecified or obj.is_multicast:
        return False

    return True


def run_command(args: list[str], log_path: Path) -> bool:
    """Run a firewall command without shell=True and log the result."""
    try:
        completed = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        status = "OK" if completed.returncode == 0 else "ERROR"
        write_alert(
            log_path,
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {status} | "
            f"cmd={' '.join(args)} | stdout={completed.stdout.strip()} | stderr={completed.stderr.strip()}",
        )
        return completed.returncode == 0
    except Exception as exc:
        write_alert(
            log_path,
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | ERROR | cmd={' '.join(args)} | exception={exc}",
        )
        return False


def command_prefix() -> list[str]:
    """Use sudo when the detector is not started as root."""
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0:
        return []
    return ["sudo"]


def apply_firewall_block(ip: str, log_path: Path) -> bool:
    """Block the attacker IP at OS level. This is the real Python-side enforcement."""
    if not valid_block_target(ip):
        write_alert(log_path, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | SKIP | invalid block target ip={ip}")
        return False

    prefix = command_prefix()

    # Avoid duplicate iptables rules.
    check_cmd = prefix + ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
    already_exists = subprocess.run(
        check_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0

    if not already_exists:
        # Insert at the top so it is checked before common ESTABLISHED/RELATED accept rules.
        ok = run_command(prefix + ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], log_path)
    else:
        ok = True
        write_alert(log_path, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | OK | firewall rule already exists for ip={ip}")

    # Optional: kill existing tracked connections if conntrack is installed.
    # This helps when the attacking client keeps an already-open TCP connection.
    if shutil.which("conntrack") is not None:
        run_command(prefix + ["conntrack", "-D", "-s", ip], log_path)

    return ok


def remove_firewall_block(ip: str, log_path: Path) -> None:
    """Remove all matching DROP rules for the IP when the block expires."""
    if not valid_block_target(ip):
        return

    prefix = command_prefix()
    while True:
        cmd = prefix + ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        removed = run_command(cmd, log_path)
        if not removed:
            break


class RealtimeDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config
        if not self.config.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.config.model_path}")
        if not self.config.raw_log_path.exists():
            raise FileNotFoundError(f"Raw log not found: {self.config.raw_log_path}")

        self.model = joblib.load(self.config.model_path)
        self.blocklist = load_blocklist(self.config.blocklist_path)

    def purge_expired_blocks(self) -> None:
        changed = False
        now = datetime.now()
        for ip in list(self.blocklist.keys()):
            until_str = self.blocklist[ip].get("until", "")
            try:
                until_dt = datetime.strptime(until_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                remove_firewall_block(ip, self.config.firewall_log_path)
                del self.blocklist[ip]
                changed = True
                continue

            if now >= until_dt:
                remove_firewall_block(ip, self.config.firewall_log_path)
                del self.blocklist[ip]
                changed = True

        if changed:
            save_blocklist(self.config.blocklist_path, self.blocklist)

    def block_ip(self, ip: str, reason: str) -> None:
        until = datetime.now() + timedelta(minutes=self.config.block_minutes)
        firewall_applied = apply_firewall_block(ip, self.config.firewall_log_path)
        self.blocklist[ip] = {
            "until": until.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
            "enforced_by": "python_detector_iptables",
            "firewall_applied": firewall_applied,
        }
        save_blocklist(self.config.blocklist_path, self.blocklist)

    def build_auth_features(self, *, ts: datetime, ip: str, username: str, status: str, session_id: str = "") -> pd.DataFrame:
        cleanup_queue(FAILED_IP_60[ip], 60, ts)
        cleanup_queue(FAILED_USER_60[username], 60, ts)
        cleanup_queue(FAILED_IP_300[ip], 300, ts)

        failed_attempts_ip_60s = len(FAILED_IP_60[ip])
        failed_attempts_user_60s = len(FAILED_USER_60[username])
        failed_attempts_ip_300s = len(FAILED_IP_300[ip])

        seconds_since_prev_event_ip = -1
        if ip in LAST_EVENT_BY_IP:
            seconds_since_prev_event_ip = int((ts - LAST_EVENT_BY_IP[ip]).total_seconds())

        seconds_since_prev_auth_ip = -1
        if ip in LAST_AUTH_BY_IP:
            seconds_since_prev_auth_ip = int((ts - LAST_AUTH_BY_IP[ip]).total_seconds())

        success_after_failed_burst = 1 if status == "SUCCESS" and failed_attempts_ip_300s >= 3 else 0

        row = {
            "event_type": "AUTH",
            "status": status,
            "http_status": 200 if status == "SUCCESS" else 401,
            "resource": "/login",
            "file_ext": "",
            "file_size": 0,
            "mime_type": "",
            "failed_attempts_ip_60s": failed_attempts_ip_60s,
            "failed_attempts_user_60s": failed_attempts_user_60s,
            "failed_attempts_ip_300s": failed_attempts_ip_300s,
            "success_after_failed_burst": success_after_failed_burst,
            "seconds_since_prev_event_ip": seconds_since_prev_event_ip,
            "seconds_since_prev_auth_ip": seconds_since_prev_auth_ip,
            "seconds_since_prev_upload_ip": -1,
            "upload_after_login_seconds": -1,
            "upload_after_failed_burst": 0,
            "suspicious_extension_flag": 0,
            "mime_mismatch_flag": 0,
            "filename_length": 0,
            "filename_entropy": 0.0,
        }

        if status == "FAILED":
            FAILED_IP_60[ip].append(ts)
            FAILED_USER_60[username].append(ts)
            FAILED_IP_300[ip].append(ts)
        elif status == "SUCCESS" and session_id:
            LAST_SUCCESS_LOGIN_BY_SESSION[session_id] = ts

        LAST_EVENT_BY_IP[ip] = ts
        LAST_AUTH_BY_IP[ip] = ts

        return pd.DataFrame([row])

    def build_upload_features(
        self,
        *,
        ts: datetime,
        ip: str,
        filename: str,
        file_ext: str,
        file_size: int,
        mime_type: str,
        session_id: str = "",
    ) -> pd.DataFrame:
        cleanup_queue(FAILED_IP_300[ip], 300, ts)

        seconds_since_prev_event_ip = -1
        if ip in LAST_EVENT_BY_IP:
            seconds_since_prev_event_ip = int((ts - LAST_EVENT_BY_IP[ip]).total_seconds())

        seconds_since_prev_upload_ip = -1
        if ip in LAST_UPLOAD_BY_IP:
            seconds_since_prev_upload_ip = int((ts - LAST_UPLOAD_BY_IP[ip]).total_seconds())

        upload_after_login_seconds = -1
        if session_id in LAST_SUCCESS_LOGIN_BY_SESSION:
            upload_after_login_seconds = int((ts - LAST_SUCCESS_LOGIN_BY_SESSION[session_id]).total_seconds())

        suspicious_extension_flag = 1 if file_ext.lower() in SUSPICIOUS_EXTENSIONS else 0
        mismatch = mime_mismatch(file_ext.lower(), mime_type)
        upload_after_failed_burst = 1 if len(FAILED_IP_300[ip]) >= 3 else 0

        row = {
            "event_type": "UPLOAD",
            "status": "SUCCESS",
            "http_status": 200,
            "resource": "/upload",
            "file_ext": file_ext.lower(),
            "file_size": file_size,
            "mime_type": mime_type,
            "failed_attempts_ip_60s": 0,
            "failed_attempts_user_60s": 0,
            "failed_attempts_ip_300s": len(FAILED_IP_300[ip]),
            "success_after_failed_burst": 0,
            "seconds_since_prev_event_ip": seconds_since_prev_event_ip,
            "seconds_since_prev_auth_ip": -1,
            "seconds_since_prev_upload_ip": seconds_since_prev_upload_ip,
            "upload_after_login_seconds": upload_after_login_seconds,
            "upload_after_failed_burst": upload_after_failed_burst,
            "suspicious_extension_flag": suspicious_extension_flag,
            "mime_mismatch_flag": mismatch,
            "filename_length": len(filename or ""),
            "filename_entropy": shannon_entropy(filename or ""),
        }

        LAST_EVENT_BY_IP[ip] = ts
        LAST_UPLOAD_BY_IP[ip] = ts

        return pd.DataFrame([row])

    def predict_row(self, row: dict) -> Optional[str]:
        event_type = str(row.get("event_type", "")).upper().strip()
        ts_raw = str(row.get("timestamp", "")).strip()
        ip = str(row.get("source_ip", "")).strip()
        username = str(row.get("username", "")).strip()
        status = str(row.get("status", "")).upper().strip()
        session_id = str(row.get("session_id", "")).strip()
        filename = str(row.get("filename", "")).strip()
        file_ext = str(row.get("file_ext", "")).strip()
        mime_type = str(row.get("mime_type", "")).strip()

        if not ts_raw or not ip or not event_type:
            return None

        ts = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")

        if event_type == "AUTH":
            X = self.build_auth_features(ts=ts, ip=ip, username=username, status=status, session_id=session_id)
            return self.model.predict(X)[0]

        if event_type == "UPLOAD":
            try:
                file_size = int(row.get("file_size") or 0)
            except Exception:
                file_size = 0
            X = self.build_upload_features(
                ts=ts,
                ip=ip,
                filename=filename,
                file_ext=file_ext,
                file_size=file_size,
                mime_type=mime_type,
                session_id=session_id,
            )
            return self.model.predict(X)[0]

        return None

    def process_row(self, row: dict) -> None:
        self.purge_expired_blocks()

        prediction = self.predict_row(row)
        if prediction is None:
            return

        ip = str(row.get("source_ip", "")).strip()
        event_type = str(row.get("event_type", "")).upper().strip()
        username = str(row.get("username", "")).strip()
        filename = str(row.get("filename", "")).strip()

        if prediction in ("bruteforce", "suspicious_upload"):
            self.block_ip(ip, prediction)
            alert_message = (
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | ALERT | "
                f"prediction={prediction} | ip={ip} | event_type={event_type} | "
                f"username={username} | filename={filename}"
            )
            write_alert(self.config.alerts_log_path, alert_message)
            print(f"[ALERT] {prediction} detected from {ip}")
        else:
            print(f"[INFO] benign event from {ip}")

    def follow_csv(self) -> None:
        with self.config.raw_log_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)

            # пропускаем уже существующие строки
            for _ in reader:
                pass

            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    time.sleep(self.config.poll_interval_seconds)
                    f.seek(pos)
                    continue

                line = line.strip()
                if not line:
                    continue

                row_reader = csv.DictReader(
                    [",".join(reader.fieldnames), line],
                    fieldnames=reader.fieldnames,
                )
                next(row_reader)
                row = next(row_reader)
                self.process_row(row)

    def run(self) -> None:
        print("[OK] Real-time AI detector started")
        print(f"[OK] Watching: {self.config.raw_log_path}")
        print(f"[OK] Model:    {self.config.model_path}")
        print(f"[OK] Alerts:   {self.config.alerts_log_path}")
        print(f"[OK] Blocks:   {self.config.blocklist_path}")
        print(f"[OK] Firewall: {self.config.firewall_log_path}")
        self.follow_csv()


def main() -> None:
    detector = RealtimeDetector(DetectorConfig())
    detector.run()


if __name__ == "__main__":
    main()