import math
import mimetypes
from collections import defaultdict, deque
from pathlib import Path

import pandas as pd

RAW_LOG = Path("raw_events.csv")
OUTPUT_DATASET = Path("train_dataset.csv")
OUTPUT_SUMMARY = Path("dataset_summary.txt")

SUSPICIOUS_EXTENSIONS = {"php", "jsp", "aspx", "py", "sh", "exe", "bat", "js"}


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


def expected_mime_for_extension(file_ext: str) -> str:
    if not file_ext:
        return ""
    guessed = mimetypes.guess_type(f"file.{file_ext}")[0]
    return guessed or ""


def load_raw_events(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Raw log file not found: {path}")

    df = pd.read_csv(path)

    required_columns = {
        "event_id",
        "timestamp",
        "event_type",
        "source_ip",
        "username",
        "session_id",
        "status",
        "http_status",
        "user_agent",
        "resource",
        "filename",
        "file_ext",
        "file_size",
        "mime_type",
        "sha256",
    }

    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in raw_events.csv: {sorted(missing)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df = df.sort_values("timestamp").reset_index(drop=True)

    text_cols = [
        "event_id",
        "event_type",
        "source_ip",
        "username",
        "session_id",
        "status",
        "user_agent",
        "resource",
        "filename",
        "file_ext",
        "mime_type",
        "sha256",
    ]
    for col in text_cols:
        df[col] = df[col].fillna("").astype(str)

    df["http_status"] = pd.to_numeric(df["http_status"], errors="coerce").fillna(0).astype(int)
    df["file_size"] = pd.to_numeric(df["file_size"], errors="coerce").fillna(0).astype(int)

    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    fail_by_ip_60 = defaultdict(deque)
    fail_by_user_60 = defaultdict(deque)
    fail_by_ip_300 = defaultdict(deque)

    last_event_time_by_ip = {}
    last_success_login_by_session = {}
    last_auth_time_by_ip = {}
    last_upload_time_by_ip = {}

    for _, row in df.iterrows():
        ts = row["timestamp"]
        ip = row["source_ip"]
        username = row["username"]
        session_id = row["session_id"]
        event_type = row["event_type"].upper()
        status = row["status"].upper()
        filename = row["filename"]
        file_ext = row["file_ext"].lower().strip()
        mime_type = row["mime_type"].strip()
        file_size = int(row["file_size"])
        http_status = int(row["http_status"])

        cutoff_60 = ts - pd.Timedelta(seconds=60)
        cutoff_300 = ts - pd.Timedelta(seconds=300)

        while fail_by_ip_60[ip] and fail_by_ip_60[ip][0] < cutoff_60:
            fail_by_ip_60[ip].popleft()
        while fail_by_user_60[username] and fail_by_user_60[username][0] < cutoff_60:
            fail_by_user_60[username].popleft()
        while fail_by_ip_300[ip] and fail_by_ip_300[ip][0] < cutoff_300:
            fail_by_ip_300[ip].popleft()

        failed_attempts_ip_60s = len(fail_by_ip_60[ip])
        failed_attempts_user_60s = len(fail_by_user_60[username])
        failed_attempts_ip_300s = len(fail_by_ip_300[ip])

        seconds_since_prev_event_ip = -1
        if ip in last_event_time_by_ip:
            seconds_since_prev_event_ip = int((ts - last_event_time_by_ip[ip]).total_seconds())

        seconds_since_prev_auth_ip = -1
        if ip in last_auth_time_by_ip:
            seconds_since_prev_auth_ip = int((ts - last_auth_time_by_ip[ip]).total_seconds())

        seconds_since_prev_upload_ip = -1
        if ip in last_upload_time_by_ip:
            seconds_since_prev_upload_ip = int((ts - last_upload_time_by_ip[ip]).total_seconds())

        expected_mime = expected_mime_for_extension(file_ext)
        mime_mismatch_flag = 0
        if event_type == "UPLOAD" and file_ext and mime_type and expected_mime:
            mime_mismatch_flag = 1 if expected_mime != mime_type else 0

        suspicious_extension_flag = 1 if file_ext in SUSPICIOUS_EXTENSIONS else 0
        filename_length = len(filename)
        filename_entropy = shannon_entropy(filename)

        upload_after_login_seconds = -1
        if event_type == "UPLOAD" and session_id in last_success_login_by_session:
            upload_after_login_seconds = int((ts - last_success_login_by_session[session_id]).total_seconds())

        success_after_failed_burst = 0
        if event_type == "AUTH" and status == "SUCCESS" and failed_attempts_ip_300s >= 3:
            success_after_failed_burst = 1

        upload_after_failed_burst = 0
        if event_type == "UPLOAD" and failed_attempts_ip_300s >= 3:
            upload_after_failed_burst = 1

        label = "benign"

        if event_type == "AUTH":
            if status == "FAILED":
                if failed_attempts_ip_60s >= 2:
                    label = "bruteforce"
            elif status == "SUCCESS":
                if success_after_failed_burst == 1:
                    label = "bruteforce"

        elif event_type == "UPLOAD":
            if suspicious_extension_flag == 1 or mime_mismatch_flag == 1:
                label = "suspicious_upload"

        row_out = {
            "event_id": row["event_id"],
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "source_ip": ip,
            "username": username,
            "session_id": session_id,
            "status": status,
            "http_status": http_status,
            "resource": row["resource"],
            "filename": filename,
            "file_ext": file_ext,
            "file_size": file_size,
            "mime_type": mime_type,
            "sha256": row["sha256"],
            "failed_attempts_ip_60s": failed_attempts_ip_60s,
            "failed_attempts_user_60s": failed_attempts_user_60s,
            "failed_attempts_ip_300s": failed_attempts_ip_300s,
            "success_after_failed_burst": success_after_failed_burst,
            "seconds_since_prev_event_ip": seconds_since_prev_event_ip,
            "seconds_since_prev_auth_ip": seconds_since_prev_auth_ip,
            "seconds_since_prev_upload_ip": seconds_since_prev_upload_ip,
            "upload_after_login_seconds": upload_after_login_seconds,
            "upload_after_failed_burst": upload_after_failed_burst,
            "suspicious_extension_flag": suspicious_extension_flag,
            "mime_mismatch_flag": mime_mismatch_flag,
            "filename_length": filename_length,
            "filename_entropy": filename_entropy,
            "label": label,
        }
        rows.append(row_out)

        if event_type == "AUTH" and status == "FAILED":
            fail_by_ip_60[ip].append(ts)
            fail_by_user_60[username].append(ts)
            fail_by_ip_300[ip].append(ts)

        if event_type == "AUTH":
            last_auth_time_by_ip[ip] = ts

        if event_type == "UPLOAD":
            last_upload_time_by_ip[ip] = ts

        if event_type == "AUTH" and status == "SUCCESS" and session_id:
            last_success_login_by_session[session_id] = ts

        last_event_time_by_ip[ip] = ts

    prepared = pd.DataFrame(rows)
    return prepared


def save_summary(df: pd.DataFrame, output_path: Path) -> None:
    lines = []
    lines.append("Dataset summary")
    lines.append("=" * 60)
    lines.append(f"Total events: {len(df)}")
    lines.append("")
    lines.append("Class distribution:")
    class_counts = df["label"].value_counts(dropna=False).to_dict()
    for label, count in class_counts.items():
        lines.append(f"  {label}: {count}")

    lines.append("")
    lines.append("Event type distribution:")
    event_counts = df["event_type"].value_counts(dropna=False).to_dict()
    for event_type, count in event_counts.items():
        lines.append(f"  {event_type}: {count}")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    df_raw = load_raw_events(RAW_LOG)
    df_prepared = build_features(df_raw)

    df_prepared.to_csv(OUTPUT_DATASET, index=False, encoding="utf-8")
    save_summary(df_prepared, OUTPUT_SUMMARY)

    print(f"[OK] Loaded raw events: {len(df_raw)}")
    print(f"[OK] Saved training dataset: {OUTPUT_DATASET}")
    print(f"[OK] Saved summary: {OUTPUT_SUMMARY}")
    print()
    print("Label distribution:")
    print(df_prepared["label"].value_counts(dropna=False))


if __name__ == "__main__":
    main()