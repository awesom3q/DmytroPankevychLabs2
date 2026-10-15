"""Завдання 2 (Варіант 4): Парсер логів аутентифікації SSH (Linux Auth Log)."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import re
import sys

logger = logging.getLogger("ssh_bruteforce_analyzer")

# Регулярний вираз для розбору рядків Failed password та Accepted password
SSH_LOG_PATTERN = re.compile(
    r"^(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<action>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)


@dataclass(frozen=True)
class SSHAuthEvent:
    """Модель події входу SSH."""

    timestamp: datetime
    action: str
    username: str
    ip: str
    port: int


def _parse_log_datetime(match: re.Match[str], default_year: int = 2026) -> datetime:
    """Розбирає дату й час із рядка журналу (підтримує Syslog та ISO формат)."""
    iso_ts = match.group("iso_ts")
    if iso_ts:
        clean_iso = iso_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        return dt.replace(tzinfo=None)

    month = match.group("month")
    day = match.group("day")
    time_str = match.group("time")
    parsed = datetime.strptime(
        f"{default_year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S"
    )
    return parsed


def parse_auth_log(log_path: Path) -> tuple[int, list[SSHAuthEvent]]:
    """Читає файл auth.log і повертає загальну кількість рядків та список подій SSH."""
    if not log_path.exists() or not log_path.is_file():
        raise FileNotFoundError(f"Файл журналу не знайдено: {log_path}")

    total_lines = 0
    events: list[SSHAuthEvent] = []

    with log_path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            total_lines += 1
            match = SSH_LOG_PATTERN.search(line.strip())
            if not match:
                continue

            timestamp = _parse_log_datetime(match)
            events.append(
                SSHAuthEvent(
                    timestamp=timestamp,
                    action=match.group("action"),
                    username=match.group("user"),
                    ip=match.group("ip"),
                    port=int(match.group("port")),
                )
            )

    return total_lines, events


def analyze_bruteforce(
    events: list[SSHAuthEvent],
    threshold: int,
    window_min: int,
) -> tuple[dict[str, dict[str, object]], list[str]]:
    """Виявляє IP-адреси з кількістю невдалих спроб >= threshold за window_min хвилин."""
    failed_by_ip: dict[str, list[SSHAuthEvent]] = defaultdict(list)

    for event in events:
        if event.action == "Failed":
            failed_by_ip[event.ip].append(event)

    detections: dict[str, dict[str, object]] = {}
    blocklist: list[str] = []
    window_delta = timedelta(minutes=window_min)

    for ip, ip_events in failed_by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        max_in_window = 0
        users_targeted: list[str] = []

        for idx, start_event in enumerate(ip_events):
            if start_event.username not in users_targeted:
                users_targeted.append(start_event.username)

            end_time = start_event.timestamp + window_delta
            count = 0
            for current_event in ip_events[idx:]:
                if current_event.timestamp <= end_time:
                    count += 1
                else:
                    break
            if count > max_in_window:
                max_in_window = count

        if max_in_window >= threshold:
            detections[ip] = {
                "total_failures": len(ip_events),
                "max_in_window": max_in_window,
                "target_users": users_targeted,
            }
            blocklist.append(ip)

    return detections, blocklist


def run_ssh_audit(
    auth_log: Path,
    threshold: int = 5,
    window_min: int = 5,
    output_json: Path | None = None,
) -> None:
    """Виконує повний цикл аналізу auth.log, виводить звіт і зберігає JSON."""
    if threshold <= 0 or window_min <= 0:
        raise ValueError(
            "Параметри threshold та window_min мають бути додатними числами."
        )

    print(f"[INFO] Analyzing authentication events in {auth_log.as_posix()}...")
    total_lines, events = parse_auth_log(auth_log)

    if events:
        start_ts = min(e.timestamp for e in events).strftime("%Y-%m-%d %H:%M:%S")
        end_ts = max(e.timestamp for e in events).strftime("%H:%M:%S")
        print(
            f"[INFO] Processed {total_lines} lines (Time range: {start_ts} - {end_ts})"
        )
    else:
        print(f"[INFO] Processed {total_lines} lines (No SSH auth events found)")

    print("\n=== SSH Bruteforce Detection Results ===")
    print(
        f"Failed Attempts Threshold: >={threshold} attempts in {window_min} minutes\n"
    )

    detections, blocklist = analyze_bruteforce(events, threshold, window_min)

    if detections:
        for ip, info in detections.items():
            users_list = info["target_users"]
            users_str = ", ".join(users_list) if isinstance(users_list, list) else ""
            msg = (
                f"Bruteforce Detected! IP: {ip} | "
                f"Total Failures: {info['total_failures']} | "
                f"Target Users: {users_str}"
            )
            logger.error(msg)
    else:
        print("[INFO] No bruteforce activity detected for the given threshold.")

    print("\n=== Recommended Blocklist (IPs) ===")
    if blocklist:
        for ip in blocklist:
            print(ip)
    else:
        print("None")

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        report_payload = {
            "source_log": auth_log.as_posix(),
            "total_lines_processed": total_lines,
            "total_ssh_events": len(events),
            "threshold": threshold,
            "window_minutes": window_min,
            "recommended_blocklist": blocklist,
            "detected_incidents": detections,
        }
        with output_json.open("w", encoding="utf-8") as out_file:
            json.dump(report_payload, out_file, indent=2, ensure_ascii=False)
        print(f"\n[INFO] Exported blocklist to {output_json.as_posix()}")


def build_arg_parser() -> argparse.ArgumentParser:
    """Конфігурує CLI-аргументи для автономного запуску task2.py."""
    parser = argparse.ArgumentParser(
        description="Варіант 4: Парсер логів аутентифікації SSH (Bruteforce Detector)"
    )
    parser.add_argument(
        "--auth-log",
        type=Path,
        default=Path("labs/lab02/data/data_v04/auth.log"),
        help="Шлях до файлу auth.log",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб входу (за замовчуванням: 5)",
    )
    parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Часове вікно у хвилинах (за замовчуванням: 5)",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("labs/lab02/data/blocklist_ips.json"),
        help="Шлях до вихідного JSON-звіту",
    )
    return parser


def main() -> None:
    """Точка входу при прямому запуску модуля task2."""
    logging.basicConfig(level=logging.ERROR, format="[ALERT] %(message)s")
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        run_ssh_audit(
            auth_log=args.auth_log,
            threshold=args.threshold,
            window_min=args.window_min,
            output_json=args.output_json,
        )
    except Exception as exc:
        logging.error("Critical error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
