#!/usr/bin/env python3
"""
Build an HTML report from AIX Oracle CPU placement diagnostics.

The tool expects outputs from:
  oratop -b -n 10 -f -r / as sysdba
  trace -a -o /tmp/trace.out
  lssrad -av
  mpstat -d 1 60
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Iterable


TIERS = ("primary", "secondary", "tertiary")
NUMBER_RE = r"\d+(?:\.\d+)?"


@dataclass
class CpuPlacement:
    cpu: int
    ref: int | None
    srad: int
    tier: str
    group: str


@dataclass
class MpstatCpu:
    cpu: int
    samples: list[dict[str, float | None]] = field(default_factory=list)

    def avg(self, key: str, default: float = 0.0) -> float:
        values = [row[key] for row in self.samples if row.get(key) is not None]
        return mean(values) if values else default

    def total_avg(self, keys: Iterable[str]) -> float:
        return sum(self.avg(key) for key in keys)


@dataclass
class OracleProcess:
    pid: int
    name: str = ""
    sid: str = ""
    username: str = ""
    service: str = ""
    status: str = ""
    state: str = ""
    wait_class: str = ""
    event: str = ""
    sql_id: str = ""
    oratop_cpu: float | None = None


@dataclass
class TraceThread:
    pid: int
    tid: int | None = None
    name: str = ""
    samples: int = 0
    cpus: Counter[int] = field(default_factory=Counter)
    tiers: Counter[str] = field(default_factory=Counter)


def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def expand_cpu_group(group: str) -> list[int]:
    cpus: list[int] = []
    for part in group.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))
    return cpus


def parse_lssrad(text: str) -> dict[int, CpuPlacement]:
    placements: dict[int, CpuPlacement] = {}
    current_ref: int | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("REF"):
            continue
        if re.fullmatch(r"\d+", stripped) and not line.startswith((" ", "\t")):
            current_ref = int(stripped)
            continue

        match = re.match(r"^\s*(\d+)\s+([\d.]+)\s+(.+?)\s*$", line)
        if not match:
            continue

        srad = int(match.group(1))
        groups = match.group(3).split()
        for index, group in enumerate(groups):
            tier = TIERS[index] if index < len(TIERS) else f"tier-{index + 1}"
            for cpu in expand_cpu_group(group):
                placements[cpu] = CpuPlacement(
                    cpu=cpu,
                    ref=current_ref,
                    srad=srad,
                    tier=tier,
                    group=group,
                )
    return placements


def parse_number(token: str) -> float | None:
    if token == "-":
        return None
    try:
        return float(token)
    except ValueError:
        return None


def parse_mpstat(text: str) -> tuple[dict[int, MpstatCpu], dict[str, str]]:
    cpus: dict[int, MpstatCpu] = {}
    config: dict[str, str] = {}
    header: list[str] = []

    config_match = re.search(r"System configuration:\s*(.+)", text)
    if config_match:
        for item in config_match.group(1).split():
            if "=" in item:
                key, value = item.split("=", 1)
                config[key] = value
            elif item.lower() in {"capped", "uncapped"}:
                config["mode"] = item

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if stripped.startswith("cpu "):
            header = stripped.split()
            continue
        if not header:
            continue

        parts = stripped.split()
        if len(parts) != len(header) or parts[0] == "ALL":
            continue
        if not parts[0].isdigit():
            continue

        row = {key: parse_number(value) for key, value in zip(header[1:], parts[1:])}
        cpu = int(parts[0])
        cpus.setdefault(cpu, MpstatCpu(cpu=cpu)).samples.append(row)
    return cpus, config


def is_probably_text(path: Path) -> bool:
    chunk = path.read_bytes()[:4096]
    if b"\0" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def load_trace_report(path: str | Path) -> str:
    trace_path = Path(path)
    if is_probably_text(trace_path):
        return read_text(trace_path)

    trcrpt = shutil.which("trcrpt")
    if not trcrpt:
        raise RuntimeError(
            "The trace file is binary and the local system does not provide 'trcrpt'. "
            "Run this tool on AIX or generate text first: trcrpt /tmp/trace.out > /tmp/trace.trcrpt "
            "and pass that file with --trace."
        )

    attempts = [
        [trcrpt, str(trace_path)],
        [trcrpt, "-O", "exec=on,pid=on,tid=on,cpu=on", str(trace_path)],
    ]
    last_error = ""
    for cmd in attempts:
        result = subprocess.run(cmd, text=True, capture_output=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        last_error = result.stderr.strip() or result.stdout.strip()
    raise RuntimeError(f"Could not decode trace through trcrpt: {last_error}")


def extract_first_int(patterns: Iterable[str], line: str) -> int | None:
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def parse_trace_report(text: str, placements: dict[int, CpuPlacement]) -> dict[tuple[int, int | None], TraceThread]:
    threads: dict[tuple[int, int | None], TraceThread] = {}
    cpu_patterns = (
        r"\b(?:cpu|cpuid|processor|processor_number)\s*[=: ]\s*(\d+)\b",
        r"\bCPU\s+Number\s+(\d+)\b",
    )
    pid_patterns = (r"\bpid\s*[=: ]\s*(\d+)\b", r"\bPid\s+(\d+)\b")
    tid_patterns = (r"\btid\s*[=: ]\s*(\d+)\b", r"\bTid\s+(\d+)\b")
    name_re = re.compile(r"\b((?:oracle|ora_|asm_)[A-Za-z0-9_+@$#.-]*)\b", re.IGNORECASE)

    for line in text.splitlines():
        cpu = extract_first_int(cpu_patterns, line)
        pid = extract_first_int(pid_patterns, line)
        tid = extract_first_int(tid_patterns, line)
        name_match = name_re.search(line)

        if pid is None:
            pair_match = re.search(r"\b([A-Za-z0-9_+@$#.-]+)\((\d+)\s+(\d+)\)", line)
            if pair_match:
                name = pair_match.group(1)
                if is_oracle_name(name):
                    pid = int(pair_match.group(2))
                    tid = int(pair_match.group(3))
                    if name_match is None:
                        name_match = pair_match

        if cpu is None or pid is None:
            continue

        name = ""
        if name_match:
            name = name_match.group(1)
        if name and not is_oracle_name(name):
            continue

        key = (pid, tid)
        row = threads.setdefault(key, TraceThread(pid=pid, tid=tid))
        row.name = row.name or name
        row.samples += 1
        row.cpus[cpu] += 1
        placement = placements.get(cpu)
        if placement:
            row.tiers[placement.tier] += 1
    return threads


def merge_trace_by_pid(trace_threads: dict[tuple[int, int | None], TraceThread]) -> dict[int, TraceThread]:
    by_pid: dict[int, TraceThread] = {}
    for row in trace_threads.values():
        target = by_pid.setdefault(row.pid, TraceThread(pid=row.pid))
        target.name = target.name or row.name
        target.samples += row.samples
        target.cpus.update(row.cpus)
        target.tiers.update(row.tiers)
    return by_pid


def is_oracle_name(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(("oracle", "ora_", "asm_")) or "oracle@" in lower


def is_oratop_metric_token(token: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+)?[A-Za-z]*", token))


def parse_oratop_event_line(line: str) -> dict[str, str] | None:
    parts = line.split()
    if len(parts) < 6:
        return None

    dbt_index = None
    for index in range(len(parts) - 1, 2, -1):
        if parse_number(parts[index]) is not None:
            dbt_index = index
            break
    if dbt_index is None or dbt_index < 3 or dbt_index + 1 >= len(parts):
        return None

    wait_index = dbt_index - 3
    event_end = wait_index
    sessions = ""
    if event_end > 0 and is_oratop_metric_token(parts[event_end - 1]):
        sessions = parts[event_end - 1]
        event_end -= 1

    event = " ".join(parts[:event_end]).strip()
    wait_class = " ".join(parts[dbt_index + 1 :]).strip()
    if not event or not wait_class:
        return None

    return {
        "event": event,
        "sessions": sessions,
        "waits": parts[wait_index],
        "time": parts[wait_index + 1],
        "avg": parts[wait_index + 2],
        "dbt": parts[dbt_index],
        "class": wait_class,
    }


def parse_oratop(text: str) -> tuple[dict[int, OracleProcess], list[dict[str, str]]]:
    processes: dict[int, OracleProcess] = {}
    events: list[dict[str, str]] = []
    in_events = False
    in_sessions = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("EVENT (RT)"):
            in_events = True
            in_sessions = False
            continue
        if stripped.startswith("ID   SID"):
            in_sessions = True
            in_events = False
            continue
        if not stripped or stripped.startswith("-"):
            continue

        if in_events:
            if stripped.startswith("ID "):
                in_events = False
                continue
            event = parse_oratop_event_line(line)
            if event:
                events.append(event)
            continue

        if in_sessions and re.match(r"^\s*\d+\s+\d+\s+\d+\s+", line):
            parts = line.split()
            if len(parts) < 12:
                continue
            status_index = next((i for i, value in enumerate(parts) if value in {"ACT", "INA", "KIL"}), None)
            if status_index is None or status_index < 4:
                continue

            pid = int(parts[2])
            proc = processes.setdefault(pid, OracleProcess(pid=pid))
            proc.sid = parts[1]
            proc.username = parts[3]
            proc.name = proc.name or "oratop-session"
            proc.status = parts[status_index]
            proc.state = parts[status_index + 1] if status_index + 1 < len(parts) else ""
            proc.wait_class = parts[status_index + 2] if status_index + 2 < len(parts) else ""
            proc.event = " ".join(parts[status_index + 3 :])
            if status_index >= 3:
                proc.oratop_cpu = parse_number(parts[status_index - 3])
            sql_candidates = [
                value
                for value in parts[4:status_index]
                if re.fullmatch(r"[0-9a-zA-Z]{13}", value) and not value.isdigit()
            ]
            if sql_candidates:
                proc.sql_id = sql_candidates[-1]
            if "DED" in parts[4:status_index]:
                ded_index = parts.index("DED", 4, status_index)
                proc.service = parts[ded_index + 1] if ded_index + 1 < status_index else ""

    return processes, events


def summarize_events(events: list[dict[str, str]]) -> list[dict[str, str | float | int]]:
    grouped: dict[tuple[str, str], dict[str, str | float | int]] = {}
    for event in events:
        key = (event.get("event", ""), event.get("class", ""))
        row = grouped.setdefault(
            key,
            {
                "event": key[0],
                "class": key[1],
                "samples": 0,
                "dbt_sum": 0.0,
                "dbt_max": 0.0,
                "last_waits": "",
                "last_time": "",
                "last_avg": "",
            },
        )
        dbt = parse_number(event.get("dbt", "")) or 0.0
        row["samples"] = int(row["samples"]) + 1
        row["dbt_sum"] = float(row["dbt_sum"]) + dbt
        row["dbt_max"] = max(float(row["dbt_max"]), dbt)
        row["last_waits"] = event.get("waits", "")
        row["last_time"] = event.get("time", "")
        row["last_avg"] = event.get("avg", "")
    return sorted(grouped.values(), key=lambda row: float(row["dbt_sum"]), reverse=True)


def summarize_sql_ids(
    processes: dict[int, OracleProcess], trace_by_pid: dict[int, TraceThread]
) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for proc in processes.values():
        if not proc.sql_id:
            continue
        row = grouped.setdefault(
            proc.sql_id,
            {
                "sql_id": proc.sql_id,
                "cpu": 0.0,
                "pids": set(),
                "cpus": Counter(),
                "tiers": Counter(),
                "waits": Counter(),
                "users": Counter(),
            },
        )
        row["cpu"] = float(row["cpu"]) + (proc.oratop_cpu or 0.0)
        row["pids"].add(proc.pid)
        if proc.wait_class:
            row["waits"][proc.wait_class] += 1
        if proc.username:
            row["users"][proc.username] += 1
        trace = trace_by_pid.get(proc.pid)
        if trace:
            row["cpus"].update(trace.cpus)
            row["tiers"].update(trace.tiers)

    return sorted(grouped.values(), key=lambda row: float(row["cpu"]), reverse=True)


def merge_processes(*sources: dict[int, OracleProcess]) -> dict[int, OracleProcess]:
    merged: dict[int, OracleProcess] = {}
    for source in sources:
        for pid, proc in source.items():
            target = merged.setdefault(pid, OracleProcess(pid=pid))
            for field_name in proc.__dataclass_fields__:
                if field_name == "pid":
                    continue
                value = getattr(proc, field_name)
                current = getattr(target, field_name)
                if value in ("", None):
                    continue
                if field_name == "name" and current and current != "oratop-session":
                    continue
                if current in ("", None) or field_name != "name":
                    setattr(target, field_name, value)
    return merged


def layer_stats(
    placements: dict[int, CpuPlacement], mpstat: dict[int, MpstatCpu]
) -> dict[str, dict[str, float]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for cpu, placement in placements.items():
        grouped[placement.tier].append(cpu)

    stats: dict[str, dict[str, float]] = {}
    for tier, cpus in grouped.items():
        mp_rows = [mpstat[cpu] for cpu in cpus if cpu in mpstat]
        stats[tier] = {
            "cpus": len(cpus),
            "active_cpus": len(mp_rows),
            "cs": sum(row.avg("cs") for row in mp_rows),
            "ics": sum(row.avg("ics") for row in mp_rows),
            "rq": sum(row.avg("rq") for row in mp_rows),
            "bound": sum(row.avg("bound") for row in mp_rows),
            "s0rd": avg_of(mp_rows, "S0rd"),
            "s1rd": avg_of(mp_rows, "S1rd"),
            "s3rd": avg_of(mp_rows, "S3rd"),
            "s3hrd": avg_of(mp_rows, "S3hrd"),
            "s4hrd": avg_of(mp_rows, "S4hrd"),
            "s5hrd": avg_of(mp_rows, "S5hrd"),
            "nsp": avg_of(mp_rows, "%nsp"),
        }
    return stats


def avg_of(rows: list[MpstatCpu], key: str) -> float:
    values = [row.avg(key) for row in rows if row.avg(key) is not None]
    return mean(values) if values else 0.0


def build_findings(
    stats: dict[str, dict[str, float]],
    events: list[dict[str, str]],
    processes: dict[int, OracleProcess],
) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []
    total_rq = sum(tier.get("rq", 0.0) for tier in stats.values())
    total_bound = sum(tier.get("bound", 0.0) for tier in stats.values())

    if total_rq >= 8 or total_bound >= 8:
        findings.append(
            (
                "critical",
                "System appears CPU-bound",
                f"mpstat shows high LCPU pressure with total average run queue {total_rq:.1f}. "
                "If Oracle work is waiting for CPU, vpm_throughput_mode can help by making virtual processors unfold faster and stay ready for throughput.",
            )
        )

    primary = stats.get("primary", {})
    secondary = stats.get("secondary", {})
    tertiary = stats.get("tertiary", {})
    if primary and secondary and primary.get("rq", 0) > secondary.get("rq", 0) * 1.6 + 1:
        findings.append(
            (
                "warning",
                "Run queue is concentrated on primary LCPUs",
                f"Primary rq={primary.get('rq', 0):.1f}, secondary rq={secondary.get('rq', 0):.1f}. "
                "This may indicate uneven thread placement or delayed virtual processor unfolding.",
            )
        )
    high_remote = [
        (tier, values)
        for tier, values in stats.items()
        if values.get("s3rd", 0) >= 5 or values.get("s3hrd", 100) < 85
    ]
    for tier, values in high_remote:
        findings.append(
            (
                "warning",
                f"Elevated remote dispatch/readiness on {tier}",
                f"{tier}: S3rd={values.get('s3rd', 0):.1f}%, S3hrd={values.get('s3hrd', 0):.1f}%. "
                "This is a signal of possible scheduler or affinity latency.",
            )
        )

    cpu_runqueue = [
        proc
        for proc in processes.values()
        if proc.wait_class == "CPU" and "Runqueue" in proc.event and (proc.oratop_cpu or 0) > 0
    ]
    if cpu_runqueue:
        top = sorted(cpu_runqueue, key=lambda proc: proc.oratop_cpu or 0, reverse=True)[:5]
        pids = ", ".join(f"{proc.pid}({proc.oratop_cpu:.1f}%)" for proc in top if proc.oratop_cpu is not None)
        findings.append(
            (
                "critical",
                "Oracle sessions are waiting on CPU Runqueue",
                f"oratop reports CPU Runqueue for SPID: {pids}. This confirms CPU pressure visible in mpstat and trace.",
            )
        )

    summarized = summarize_events(events)
    log_file_sync = next((event for event in summarized if "log file sync" in str(event.get("event", ""))), None)
    if log_file_sync:
        findings.append(
            (
                "info",
                "Commit/log file sync latency is visible",
                f"log file sync accounts for {float(log_file_sync.get('dbt_sum', 0.0)):.1f}% total DB time across oratop samples, "
                f"last avg={log_file_sync.get('last_avg')}. When the system is CPU-bound, some of that latency can be amplified by CPU queues; "
                "LGWR, storage, and redo transport should still be treated as separate suspects.",
            )
        )

    if not findings:
        findings.append(("ok", "No strong heuristic anomalies", "No alert thresholds were detected in the supplied files."))
    return findings


def diagnose_vpm_throughput_mode(
    stats: dict[str, dict[str, float]],
    events: list[dict[str, str]],
    processes: dict[int, OracleProcess],
    trace_by_pid: dict[int, TraceThread],
) -> dict[str, object]:
    total_rq = sum(tier.get("rq", 0.0) for tier in stats.values())
    total_bound = sum(tier.get("bound", 0.0) for tier in stats.values())
    primary = stats.get("primary", {})
    secondary = stats.get("secondary", {})
    tertiary = stats.get("tertiary", {})
    primary_rq = primary.get("rq", 0.0)
    secondary_rq = secondary.get("rq", 0.0)
    tertiary_rq = tertiary.get("rq", 0.0)
    non_primary_rq = secondary_rq + tertiary_rq
    cpu_bound = total_rq >= 8 or total_bound >= 8
    primary_skew = primary_rq > max(secondary_rq * 1.6 + 1, non_primary_rq * 0.65)
    remote_latency = any(values.get("s3rd", 0.0) >= 5 or values.get("s3hrd", 100.0) < 85 for values in stats.values())
    oracle_cpu_wait = any(
        proc.wait_class == "CPU" and "Runqueue" in proc.event and (proc.oratop_cpu or 0) > 0
        for proc in processes.values()
    )

    trace_tiers: Counter[str] = Counter()
    for row in trace_by_pid.values():
        trace_tiers.update(row.tiers)
    trace_total = sum(trace_tiers.values())
    primary_trace_share = trace_tiers.get("primary", 0) / trace_total if trace_total else 0.0

    summarized = summarize_events(events)
    cpu_event_dbt = sum(
        float(event.get("dbt_sum", 0.0))
        for event in summarized
        if str(event.get("class", "")).upper() == "CPU" or "runqueue" in str(event.get("event", "")).lower()
    )

    evidence = [
        f"mpstat total rq={total_rq:.1f}, total bound={total_bound:.1f}; CPU-bound={yes_no(cpu_bound)}.",
        f"Tier run queue: primary={primary_rq:.1f}, secondary={secondary_rq:.1f}, tertiary={tertiary_rq:.1f}; primary skew={yes_no(primary_skew)}.",
        f"Oracle CPU Runqueue waits={yes_no(oracle_cpu_wait)}, aggregated CPU wait DB time={cpu_event_dbt:.1f}%.",
    ]
    if trace_total:
        evidence.append(
            f"Trace tier samples: {top_counter(trace_tiers, 5)}; primary trace share={primary_trace_share * 100:.1f}%."
        )
    else:
        evidence.append("Trace did not contain decodable Oracle CPU samples, so the vpm diagnosis is based on mpstat and oratop only.")
    if remote_latency:
        evidence.append("Remote dispatch/readiness metrics are elevated, which can compound placement or unfolding latency.")

    score = sum([cpu_bound, primary_skew, oracle_cpu_wait, remote_latency])
    if cpu_bound and primary_skew and (oracle_cpu_wait or remote_latency):
        level = "critical"
        title = "vpm_throughput_mode is likely worth testing"
        recommended_value = 1
        body = (
            "The same capture window shows CPU pressure, stronger queues on primary LCPUs, and Oracle CPU wait or remote readiness signals. "
            "That pattern is consistent with folding or slow unfolding of virtual processors, so vpm_throughput_mode has a plausible chance of improving throughput."
        )
    elif cpu_bound and (oracle_cpu_wait or primary_skew):
        level = "warning"
        title = "vpm_throughput_mode may help, but evidence is partial"
        recommended_value = 1
        body = (
            "The report sees CPU pressure plus at least one Oracle or tier-placement signal, but the full folding/unfolding pattern is not conclusive. "
            "Testing vpm_throughput_mode is reasonable if the LPAR is throughput-sensitive and power saving is less important."
        )
    elif score:
        level = "info"
        title = "vpm_throughput_mode is not the primary recommendation"
        recommended_value = 0
        body = (
            "Some weak CPU or placement signals are present, but the report does not show a clear CPU-bound unfolding problem in this capture window."
        )
    else:
        level = "ok"
        title = "vpm_throughput_mode is not indicated by this report"
        recommended_value = 0
        body = "The supplied files do not show CPU-bound queues, Oracle CPU Runqueue waits, or tier imbalance strong enough to point at folding or slow unfolding."
    commands = {
        "show_current": "schedo -o vpm_throughput_mode",
        "set_runtime": f"schedo -o vpm_throughput_mode={recommended_value}",
        "set_persistent": f"schedo -p -o vpm_throughput_mode={recommended_value}",
    }
    if recommended_value == 1:
        commands["rollback_runtime"] = "schedo -o vpm_throughput_mode=0"
        commands["rollback_persistent"] = "schedo -p -o vpm_throughput_mode=0"
    return {
        "level": level,
        "title": title,
        "recommended_value": recommended_value,
        "recommended_action": (
            "Set vpm_throughput_mode=1 for a controlled throughput test."
            if recommended_value == 1
            else "Keep vpm_throughput_mode=0 unless a separate workload test proves a benefit."
        ),
        "commands": commands,
        "evidence": evidence,
        "interpretation": body,
    }


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def fmt(value: float | int | None, digits: int = 1) -> str:
    if value is None:
        return "-"
    if isinstance(value, int):
        return str(value)
    return f"{value:.{digits}f}"


def esc(value: object) -> str:
    return html.escape(str(value))


def render_report(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    mp_config: dict[str, str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
    out_path: Path,
) -> None:
    stats = layer_stats(placements, mpstat)
    findings = build_findings(stats, events, processes)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)

    top_processes = sorted(
        processes.values(),
        key=lambda proc: ((proc.oratop_cpu or 0), trace_by_pid.get(proc.pid, TraceThread(proc.pid)).samples),
        reverse=True,
    )[:80]

    html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ORAIX AIX Oracle LCPU Report</title>
<style>
body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17202a; background: #f6f7f9; }}
header {{ background: #18324a; color: white; padding: 24px 32px; }}
main {{ padding: 24px 32px 48px; }}
h1 {{ margin: 0 0 6px; font-size: 28px; }}
h2 {{ margin: 28px 0 12px; font-size: 20px; }}
p {{ line-height: 1.45; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }}
.card {{ background: white; border: 1px solid #d8dde5; border-radius: 8px; padding: 14px; }}
.label {{ color: #5c6b7a; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
.value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d8dde5; }}
th, td {{ padding: 8px 10px; border-bottom: 1px solid #e8ebef; text-align: left; font-size: 13px; vertical-align: top; }}
th {{ background: #eef2f6; color: #26394d; position: sticky; top: 0; }}
tr:hover td {{ background: #fafcff; }}
.finding {{ border-left: 5px solid #7b8794; background: white; margin: 10px 0; padding: 12px 14px; border-radius: 6px; border-top: 1px solid #d8dde5; border-right: 1px solid #d8dde5; border-bottom: 1px solid #d8dde5; }}
.critical {{ border-left-color: #c62828; }}
.warning {{ border-left-color: #ef8f00; }}
.info {{ border-left-color: #2672b9; }}
.ok {{ border-left-color: #2e7d32; }}
.pill {{ display: inline-block; padding: 2px 7px; border-radius: 99px; font-size: 12px; background: #e9eef5; }}
.primary {{ background: #dcecff; }}
.secondary {{ background: #e1f3df; }}
.tertiary {{ background: #fff0cf; }}
.note {{ background: #fff; border: 1px solid #d8dde5; border-radius: 8px; padding: 12px 14px; }}
code {{ background: #eef2f6; padding: 1px 4px; border-radius: 4px; }}
</style>
</head>
<body>
<header>
<h1>ORAIX AIX Oracle LCPU Report</h1>
<div>Generated: {esc(generated)}</div>
</header>
<main>
<section class="cards">
<div class="card"><div class="label">LCPU</div><div class="value">{esc(mp_config.get("lcpu", len(placements)))}</div></div>
<div class="card"><div class="label">Entitlement</div><div class="value">{esc(mp_config.get("ent", "-"))}</div></div>
<div class="card"><div class="label">Mode</div><div class="value">{esc(mp_config.get("mode", "-"))}</div></div>
<div class="card"><div class="label">Oracle PIDs in trace</div><div class="value">{len(trace_by_pid)}</div></div>
</section>

<h2>Findings</h2>
{render_findings(findings)}

<h2>Primary / secondary / tertiary LCPU</h2>
<p class="note">Tier classification comes from the CPU group order reported by <code>lssrad -av</code> within each SRAD. PID/TID to CPU placement comes from the raw AIX trace decoded by <code>trcrpt</code>.</p>
{render_layer_table(stats)}

<h2>LCPU Map</h2>
{render_cpu_table(placements, mpstat)}

<h2>Oracle Processes</h2>
{render_process_table(top_processes, trace_by_pid)}

<h2>Trace Processes by CPU</h2>
{render_trace_table(trace_by_pid)}

<h2>Top SQL_IDs from oratop</h2>
{render_sql_table(top_sql)}

<h2>Top Wait Events from oratop</h2>
{render_events_table(summarized_events)}

<h2>vpm_throughput_mode Diagnosis</h2>
{render_vpm_diagnosis(vpm_diagnosis)}
</main>
<script>
document.querySelectorAll('table').forEach((table, idx) => {{
  const input = document.createElement('input');
  input.placeholder = 'Filter table...';
  input.style.cssText = 'margin:8px 0 10px;padding:8px 10px;width:320px;max-width:100%;border:1px solid #cbd4df;border-radius:6px';
  table.parentNode.insertBefore(input, table);
  input.addEventListener('input', () => {{
    const q = input.value.toLowerCase();
    table.querySelectorAll('tbody tr').forEach(tr => {{
      tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
    }});
  }});
  table.querySelectorAll('th').forEach((th, col) => {{
    th.style.cursor = 'pointer';
    th.title = 'Sort';
    th.addEventListener('click', () => {{
      const tbody = table.querySelector('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const asc = th.dataset.asc !== 'true';
      table.querySelectorAll('th').forEach(h => delete h.dataset.asc);
      th.dataset.asc = asc;
      rows.sort((a, b) => {{
        const av = a.children[col]?.innerText.trim() || '';
        const bv = b.children[col]?.innerText.trim() || '';
        const an = parseFloat(av.replace(/[^0-9.-]/g, ''));
        const bn = parseFloat(bv.replace(/[^0-9.-]/g, ''));
        const cmp = !Number.isNaN(an) && !Number.isNaN(bn) ? an - bn : av.localeCompare(bv);
        return asc ? cmp : -cmp;
      }});
      rows.forEach(row => tbody.appendChild(row));
    }});
  }});
}});
</script>
</body>
</html>
"""
    out_path.write_text(html_text, encoding="utf-8")


def render_findings(findings: list[tuple[str, str, str]]) -> str:
    return "\n".join(
        f'<div class="finding {esc(level)}"><strong>{esc(title)}</strong><p>{esc(body)}</p></div>'
        for level, title, body in findings
    )


def render_vpm_diagnosis(diagnosis: dict[str, object]) -> str:
    commands = diagnosis.get("commands", {})
    command_lines = "".join(
        f"<li><strong>{esc(label.replace('_', ' ').title())}:</strong> <code>{esc(command)}</code></li>"
        for label, command in commands.items()
    )
    evidence_lines = "".join(f"<li>{esc(line)}</li>" for line in diagnosis.get("evidence", []))
    return (
        f'<div class="finding {esc(diagnosis.get("level", "info"))}">'
        f'<strong>{esc(diagnosis.get("title", ""))}</strong>'
        f'<p><strong>Recommended value:</strong> <code>{esc(diagnosis.get("recommended_value", "-"))}</code>. '
        f'{esc(diagnosis.get("recommended_action", ""))}</p>'
        f'<p>{esc(diagnosis.get("interpretation", ""))}</p>'
        f'<p><strong>AIX commands</strong></p><ul>{command_lines}</ul>'
        f'<p><strong>Evidence</strong></p><ul>{evidence_lines}</ul>'
        "</div>"
    )


def render_layer_table(stats: dict[str, dict[str, float]]) -> str:
    rows = []
    for tier in TIERS:
        values = stats.get(tier)
        if not values:
            continue
        rows.append(
            "<tr>"
            f'<td><span class="pill {tier}">{tier}</span></td>'
            f"<td>{fmt(values.get('cpus'), 0)}</td>"
            f"<td>{fmt(values.get('rq'))}</td>"
            f"<td>{fmt(values.get('bound'))}</td>"
            f"<td>{fmt(values.get('s0rd'))}%</td>"
            f"<td>{fmt(values.get('s1rd'))}%</td>"
            f"<td>{fmt(values.get('s3rd'))}%</td>"
            f"<td>{fmt(values.get('s3hrd'))}%</td>"
            f"<td>{fmt(values.get('nsp'))}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Tier</th><th>LCPU</th><th>rq</th><th>bound</th>"
        "<th>S0rd</th><th>S1rd</th><th>S3rd</th><th>S3hrd</th><th>%nsp</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_cpu_table(
    placements: dict[int, CpuPlacement], mpstat: dict[int, MpstatCpu]
) -> str:
    rows = []
    for cpu in sorted(placements):
        placement = placements[cpu]
        mp = mpstat.get(cpu)
        rows.append(
            "<tr>"
            f"<td>{cpu}</td>"
            f"<td>{esc(placement.ref if placement.ref is not None else '-')}</td>"
            f"<td>{placement.srad}</td>"
            f'<td><span class="pill {placement.tier}">{placement.tier}</span></td>'
            f"<td>{esc(placement.group)}</td>"
            f"<td>{fmt(mp.avg('rq') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('cs') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('ics') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('S0rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S1rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3hrd') if mp else None)}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>LCPU</th><th>REF</th><th>SRAD</th><th>Tier</th><th>Group</th>"
        "<th>rq</th><th>cs</th><th>ics</th><th>S0rd</th><th>S1rd</th><th>S3rd</th><th>S3hrd</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def top_counter(counter: Counter, limit: int = 5) -> str:
    if not counter:
        return "-"
    return ", ".join(f"{key}:{value}" for key, value in counter.most_common(limit))


def render_process_table(processes: list[OracleProcess], trace_by_pid: dict[int, TraceThread]) -> str:
    rows = []
    for proc in processes:
        trace = trace_by_pid.get(proc.pid)
        trace_samples = trace.samples if trace else 0
        cpus = top_counter(trace.cpus if trace else Counter())
        tiers = top_counter(trace.tiers if trace else Counter())
        rows.append(
            "<tr>"
            f"<td>{proc.pid}</td>"
            f"<td>{esc(proc.name or '-')}</td>"
            f"<td>{esc(proc.sid or '-')}</td>"
            f"<td>{esc(proc.username or '-')}</td>"
            f"<td>{esc(proc.sql_id or '-')}</td>"
            f"<td>{fmt(proc.oratop_cpu)}%</td>"
            f"<td>{trace_samples}</td>"
            f"<td>{esc(cpus)}</td>"
            f"<td>{esc(tiers)}</td>"
            f"<td>{esc(proc.status or '-')} {esc(proc.state or '')}</td>"
            f"<td>{esc(proc.wait_class or '-')}</td>"
            f"<td>{esc(proc.event or '-')}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>PID/SPID</th><th>Name</th><th>SID</th><th>User</th><th>SQL_ID</th><th>oratop %CPU</th>"
        "<th>trace samples</th><th>CPU</th><th>Tier</th><th>Status</th><th>Wait class</th><th>Event</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_trace_table(trace_by_pid: dict[int, TraceThread]) -> str:
    rows = []
    for trace in sorted(trace_by_pid.values(), key=lambda row: row.samples, reverse=True):
        rows.append(
            "<tr>"
            f"<td>{trace.pid}</td>"
            f"<td>{esc(trace.name or '-')}</td>"
            f"<td>{trace.samples}</td>"
            f"<td>{esc(top_counter(trace.cpus, 12))}</td>"
            f"<td>{esc(top_counter(trace.tiers, 5))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>PID</th><th>Name</th><th>trace samples</th><th>CPU</th><th>Tier</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_sql_table(rows_data: list[dict[str, object]]) -> str:
    rows = []
    for row in rows_data[:100]:
        pids = sorted(row["pids"])
        rows.append(
            "<tr>"
            f"<td>{esc(row['sql_id'])}</td>"
            f"<td>{fmt(float(row['cpu']))}%</td>"
            f"<td>{len(pids)}</td>"
            f"<td>{esc(', '.join(str(pid) for pid in pids[:12]))}</td>"
            f"<td>{esc(top_counter(row['cpus'], 12))}</td>"
            f"<td>{esc(top_counter(row['tiers'], 5))}</td>"
            f"<td>{esc(top_counter(row['users'], 5))}</td>"
            f"<td>{esc(top_counter(row['waits'], 5))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>SQL_ID</th><th>sum %CPU</th><th>PIDs</th><th>PID list</th><th>CPU</th><th>Tier</th><th>Users</th><th>Wait classes</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_events_table(events: list[dict[str, str | float | int]]) -> str:
    rows = []
    for event in events[:20]:
        rows.append(
            "<tr>"
            f"<td>{esc(event.get('event', '-'))}</td>"
            f"<td>{esc(event.get('samples', '-'))}</td>"
            f"<td>{esc(event.get('last_waits', '-'))}</td>"
            f"<td>{esc(event.get('last_time', '-'))}</td>"
            f"<td>{esc(event.get('last_avg', '-'))}</td>"
            f"<td>{fmt(float(event.get('dbt_sum', 0.0)))}%</td>"
            f"<td>{fmt(float(event.get('dbt_max', 0.0)))}%</td>"
            f"<td>{esc(event.get('class', '-'))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Event</th><th>Samples</th><th>Last waits</th><th>Last time</th><th>Last avg</th><th>sum %DBT</th><th>max %DBT</th><th>Class</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def counter_to_dict(counter: Counter) -> dict[str, int]:
    return {str(key): int(value) for key, value in counter.items()}


def build_json_report(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    mp_config: dict[str, str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
) -> dict[str, object]:
    stats = layer_stats(placements, mpstat)
    findings = build_findings(stats, events, processes)
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid)

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "mpstat_config": mp_config,
        "summary": {
            "lcpu": mp_config.get("lcpu", len(placements)),
            "entitlement": mp_config.get("ent", "-"),
            "mode": mp_config.get("mode", "-"),
            "oracle_pids_in_trace": len(trace_by_pid),
        },
        "findings": [
            {"level": level, "title": title, "details": details}
            for level, title, details in findings
        ],
        "vpm_throughput_mode": vpm_diagnosis,
        "tier_stats": stats,
        "lcpu_map": [
            {
                "lcpu": cpu,
                "ref": placement.ref,
                "srad": placement.srad,
                "tier": placement.tier,
                "group": placement.group,
                "mpstat": {
                    "rq": mpstat[cpu].avg("rq") if cpu in mpstat else None,
                    "cs": mpstat[cpu].avg("cs") if cpu in mpstat else None,
                    "ics": mpstat[cpu].avg("ics") if cpu in mpstat else None,
                    "S0rd": mpstat[cpu].avg("S0rd") if cpu in mpstat else None,
                    "S1rd": mpstat[cpu].avg("S1rd") if cpu in mpstat else None,
                    "S3rd": mpstat[cpu].avg("S3rd") if cpu in mpstat else None,
                    "S3hrd": mpstat[cpu].avg("S3hrd") if cpu in mpstat else None,
                },
            }
            for cpu, placement in sorted(placements.items())
        ],
        "oracle_processes": [
            {
                "pid": proc.pid,
                "name": proc.name,
                "sid": proc.sid,
                "username": proc.username,
                "service": proc.service,
                "status": proc.status,
                "state": proc.state,
                "wait_class": proc.wait_class,
                "event": proc.event,
                "sql_id": proc.sql_id,
                "oratop_cpu": proc.oratop_cpu,
                "trace": {
                    "samples": trace_by_pid[proc.pid].samples if proc.pid in trace_by_pid else 0,
                    "cpus": counter_to_dict(trace_by_pid[proc.pid].cpus) if proc.pid in trace_by_pid else {},
                    "tiers": counter_to_dict(trace_by_pid[proc.pid].tiers) if proc.pid in trace_by_pid else {},
                },
            }
            for proc in sorted(processes.values(), key=lambda item: item.pid)
        ],
        "trace_processes": [
            {
                "pid": trace.pid,
                "name": trace.name,
                "samples": trace.samples,
                "cpus": counter_to_dict(trace.cpus),
                "tiers": counter_to_dict(trace.tiers),
            }
            for trace in sorted(trace_by_pid.values(), key=lambda row: row.samples, reverse=True)
        ],
        "top_sql_ids": [
            {
                "sql_id": row["sql_id"],
                "sum_cpu": row["cpu"],
                "pids": sorted(row["pids"]),
                "cpus": counter_to_dict(row["cpus"]),
                "tiers": counter_to_dict(row["tiers"]),
                "users": counter_to_dict(row["users"]),
                "wait_classes": counter_to_dict(row["waits"]),
            }
            for row in top_sql
        ],
        "top_wait_events": summarized_events,
    }


def write_json_report(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    mp_config: dict[str, str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
    out_path: Path,
) -> None:
    data = build_json_report(placements, mpstat, mp_config, trace_by_pid, processes, events)
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    epilog = """Commands to collect input data on AIX:

  oratop -b -n 10 -f -r / as sysdba > /tmp/oratop.out
  trace -a -o /tmp/trace.out
  # keep trace running during the same workload window as oratop/mpstat
  trcstop
  trcrpt /tmp/trace.out > /tmp/trace.trcrpt
  lssrad -av > /tmp/lssrad_av.out
  mpstat -d 1 60 > /tmp/mpstat_d.out

The --trace argument accepts either the raw /tmp/trace.out file when the tool is run on AIX
with trcrpt available, or the pre-decoded /tmp/trace.trcrpt text file.

Example:

  python3 oraix_report.py \\
    --oratop /tmp/oratop.out \\
    --trace /tmp/trace.out \\
    --lssrad /tmp/lssrad_av.out \\
    --mpstat /tmp/mpstat_d.out \\
    --output /tmp/oraix_report.html

  python3 oraix_report.py \\
    --oratop /tmp/oratop.out \\
    --trace /tmp/trace.trcrpt \\
    --lssrad /tmp/lssrad_av.out \\
    --mpstat /tmp/mpstat_d.out \\
    --format json \\
    --output /tmp/oraix_report.json
"""
    parser = argparse.ArgumentParser(
        description="Build an HTML AIX Oracle CPU/LCPU/SRAD report from oratop, trace.out, lssrad, and mpstat.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--oratop", required=True, help="File generated by: oratop -b -n 10 -f -r / as sysdba")
    parser.add_argument("--trace", required=True, help="Raw AIX trace.out file or text output from trcrpt")
    parser.add_argument("--lssrad", required=True, help="File generated by: lssrad -av")
    parser.add_argument("--mpstat", required=True, help="File generated by: mpstat -d 1 60")
    parser.add_argument("--format", choices=("html", "json", "auto"), default="auto", help="Output format. With auto, .json selects JSON; otherwise HTML.")
    parser.add_argument("--output", "-o", default="oraix_report.html", help="Output report path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    placements = parse_lssrad(read_text(args.lssrad))
    mpstat, mp_config = parse_mpstat(read_text(args.mpstat))
    trace_report = load_trace_report(args.trace)
    trace_threads = parse_trace_report(trace_report, placements)
    trace_by_pid = merge_trace_by_pid(trace_threads)
    oratop_processes, events = parse_oratop(read_text(args.oratop))
    processes = merge_processes(oratop_processes)
    for pid, trace in trace_by_pid.items():
        proc = processes.setdefault(pid, OracleProcess(pid=pid))
        if trace.name and (not proc.name or proc.name == "oratop-session"):
            proc.name = trace.name

    output = Path(args.output)
    output_format = args.format
    if output_format == "auto":
        output_format = "json" if output.suffix.lower() == ".json" else "html"
    if output_format == "json":
        write_json_report(placements, mpstat, mp_config, trace_by_pid, processes, events, output)
    else:
        render_report(placements, mpstat, mp_config, trace_by_pid, processes, events, output)
    print(f"{output_format.upper()} report written to {output}")


if __name__ == "__main__":
    main()
