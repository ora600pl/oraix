#!/usr/bin/env python3
"""
Build an HTML/JSON report from AIX Oracle CPU placement diagnostics.

The tool expects outputs from:
  smtctl
  oratop -b -n 10 -f -r / as sysdba
  trace -a -o /tmp/trace.out, decoded with trcrpt when not running on AIX
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
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Iterable


NUMBER_RE = r"\d+(?:\.\d+)?"
SMT_WIDTH_CHOICES = (1, 2, 4, 8)
SMT_LABELS = {
    0: "primary",
    1: "secondary",
    2: "tertiary",
    3: "quaternary",
}


@dataclass
class CpuPlacement:
    lcpu: int
    ref: int | None
    srad: int
    lssrad_range_index: int
    lssrad_range_label: str
    lssrad_cpu_range: str
    smt_width: int | None = None
    smt_position: int | None = None
    physical_core_id: int | None = None
    smt_class_label: str = "unknown"


@dataclass
class MpstatCpu:
    cpu: int
    samples: list[dict[str, float | None]] = field(default_factory=list)

    def avg(self, key: str) -> float | None:
        values = [row[key] for row in self.samples if row.get(key) is not None]
        return mean(values) if values else None


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
    lssrad_ranges: Counter[str] = field(default_factory=Counter)
    smt_classes: Counter[str] = field(default_factory=Counter)
    smt_positions: Counter[int] = field(default_factory=Counter)


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


def smt_class_label(position: int | None) -> str:
    if position is None:
        return "unknown"
    return SMT_LABELS.get(position, f"smt-{position + 1}")


def smt_class_labels(smt_width: int | None) -> list[str]:
    if smt_width is None:
        return []
    return [smt_class_label(pos) for pos in range(smt_width)]


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

        match = re.match(r"^\s*(\d+)\s+[\d.]+\s+(.+?)\s*$", line)
        if not match:
            continue

        srad = int(match.group(1))
        ranges = match.group(2).split()
        for index, cpu_range in enumerate(ranges, start=1):
            label = f"range-{index}"
            for lcpu in expand_cpu_group(cpu_range):
                placements[lcpu] = CpuPlacement(
                    lcpu=lcpu,
                    ref=current_ref,
                    srad=srad,
                    lssrad_range_index=index,
                    lssrad_range_label=label,
                    lssrad_cpu_range=cpu_range,
                )
    return placements


def apply_smt_topology(placements: dict[int, CpuPlacement], smt_width: int | None) -> None:
    for placement in placements.values():
        placement.smt_width = smt_width
        if smt_width is None:
            placement.smt_position = None
            placement.physical_core_id = None
            placement.smt_class_label = "unknown"
            continue
        placement.smt_position = placement.lcpu % smt_width
        placement.physical_core_id = placement.lcpu // smt_width
        placement.smt_class_label = smt_class_label(placement.smt_position)


def parse_smtctl(text: str) -> dict[str, object]:
    enabled: bool | None = None
    capable: bool | None = None
    widths: list[int] = []
    per_proc: dict[str, int] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()

        if re.search(r"\bnot\s+smt\s+capable\b|\bsmt\s+capable\s*:\s*no\b", lower):
            capable = False
        elif re.search(r"\bsmt\s+capable\b", lower):
            capable = True

        if re.search(r"\bsmt\b.*\b(disabled|off)\b|\b(disabled|off)\b.*\bsmt\b", lower):
            enabled = False
        elif re.search(r"\bsmt\b.*\b(enabled|on)\b|\b(enabled|on)\b.*\bsmt\b", lower):
            enabled = True

        proc_match = re.search(r"\b(proc\d+)\b", line, re.IGNORECASE)
        width_match = (
            re.search(r"\bproc\d+\s+has\s+([1248])\s+SMT\s+threads\b", line, re.IGNORECASE)
            or re.search(r"\bProcessor\s+proc\d+\s+is\s+in\s+SMT\s+mode\s+([1248])\b", line, re.IGNORECASE)
            or re.search(r"\bSMT\s+threads\s*(?:=|:)\s*([1248])\b", line, re.IGNORECASE)
            or re.search(r"\bSMT\s+mode\s*(?:=|:)?\s*([1248])\b", line, re.IGNORECASE)
        )
        if width_match:
            width = int(width_match.group(1))
            widths.append(width)
            if proc_match:
                per_proc[proc_match.group(1).lower()] = width

    if enabled is False:
        smt_width = 1
    elif widths:
        smt_width = Counter(widths).most_common(1)[0][0]
    else:
        smt_width = None

    mixed = len(set(per_proc.values())) > 1 if per_proc else len(set(widths)) > 1
    return {
        "smt_width": smt_width,
        "smt_enabled": enabled,
        "smt_capable": capable,
        "smt_width_per_proc": per_proc,
        "smt_width_mixed": mixed,
        "raw_widths": widths,
    }


def infer_smt_width_from_lssrad(placements: dict[int, CpuPlacement]) -> int | None:
    if not placements:
        return None
    range_lengths: Counter[int] = Counter()
    seen: set[tuple[int | None, int, int, str]] = set()
    for placement in placements.values():
        key = (
            placement.ref,
            placement.srad,
            placement.lssrad_range_index,
            placement.lssrad_cpu_range,
        )
        if key in seen:
            continue
        seen.add(key)
        length = len(expand_cpu_group(placement.lssrad_cpu_range))
        if length in SMT_WIDTH_CHOICES:
            range_lengths[length] += 1
    if not range_lengths:
        return None
    return range_lengths.most_common(1)[0][0]


def resolve_smt_topology(
    cli_width: int | None,
    smtctl_info: dict[str, object] | None,
    placements: dict[int, CpuPlacement],
) -> dict[str, object]:
    warnings: list[str] = []
    if cli_width is not None:
        width = cli_width
        source = "cli"
    elif smtctl_info and smtctl_info.get("smt_width") in SMT_WIDTH_CHOICES:
        width = int(smtctl_info["smt_width"])
        source = "smtctl"
    else:
        width = infer_smt_width_from_lssrad(placements)
        if width is not None:
            source = "inferred"
            warnings.append(
                "SMT width was inferred from lssrad CPU range lengths. On POWER/AIX this is only a heuristic; "
                "provide --smtctl or --smt-width for authoritative SMT class mapping."
            )
        else:
            source = "unknown"
            warnings.append(
                "SMT width is unknown. SMT classes and physical core IDs are not calculated; provide --smtctl or --smt-width."
            )

    if smtctl_info and smtctl_info.get("smt_width_mixed"):
        warnings.append(
            "smtctl reports mixed SMT widths across processors. The report uses the most common width and keeps per-processor widths in JSON."
        )
    if source not in {"cli", "smtctl"} and not warnings:
        warnings.append("SMT width source is not authoritative; SMT position interpretation may be uncertain.")

    return {
        "smt_width": width,
        "smt_width_source": source,
        "smtctl": smtctl_info or {},
        "warnings": warnings,
        "smt_classes": smt_class_labels(width),
    }


def parse_number(token: str) -> float | None:
    if token == "-":
        return None
    try:
        return float(token)
    except ValueError:
        return None


def parse_mpstat(text: str) -> tuple[dict[int, MpstatCpu], dict[str, str], set[str]]:
    cpus: dict[int, MpstatCpu] = {}
    config: dict[str, str] = {}
    columns: set[str] = set()
    header: list[str] = []

    config_match = re.search(r"System configuration:\s*(.+)", text)
    if config_match:
        for item in config_match.group(1).split():
            if "=" in item:
                key, value = item.split("=", 1)
                config[key.lower()] = value
            elif item.lower() in {"capped", "uncapped"}:
                config["mode"] = item.lower()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if re.match(r"^cpu\s+", stripped, re.IGNORECASE):
            header = stripped.split()
            columns.update(header[1:])
            continue
        if not header:
            continue

        parts = stripped.split()
        if len(parts) != len(header) or parts[0].upper() == "ALL" or not parts[0].isdigit():
            continue

        row = {key: parse_number(value) for key, value in zip(header[1:], parts[1:])}
        cpu = int(parts[0])
        cpus.setdefault(cpu, MpstatCpu(cpu=cpu)).samples.append(row)
    return cpus, config, columns


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
            "Run this tool on AIX or generate text first: trcrpt /tmp/trace.out > /tmp/trace.trcrpt."
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


def is_oracle_name(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(("oracle", "ora_", "asm_")) or "oracle@" in lower


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
            if pair_match and is_oracle_name(pair_match.group(1)):
                name_match = name_match or pair_match
                pid = int(pair_match.group(2))
                tid = int(pair_match.group(3))

        if cpu is None or pid is None:
            continue

        name = name_match.group(1) if name_match else ""
        if name and not is_oracle_name(name):
            continue

        key = (pid, tid)
        row = threads.setdefault(key, TraceThread(pid=pid, tid=tid))
        row.name = row.name or name
        row.samples += 1
        row.cpus[cpu] += 1
        placement = placements.get(cpu)
        if placement:
            row.lssrad_ranges[placement.lssrad_range_label] += 1
            if placement.smt_position is not None:
                row.smt_positions[placement.smt_position] += 1
                row.smt_classes[placement.smt_class_label] += 1
    return threads


def merge_trace_by_pid(trace_threads: dict[tuple[int, int | None], TraceThread]) -> dict[int, TraceThread]:
    by_pid: dict[int, TraceThread] = {}
    for row in trace_threads.values():
        target = by_pid.setdefault(row.pid, TraceThread(pid=row.pid))
        target.name = target.name or row.name
        target.samples += row.samples
        target.cpus.update(row.cpus)
        target.lssrad_ranges.update(row.lssrad_ranges)
        target.smt_classes.update(row.smt_classes)
        target.smt_positions.update(row.smt_positions)
    return by_pid


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


def parse_oratop_session_tail(parts: list[str], status_index: int) -> tuple[str, str, str, str]:
    status = parts[status_index]
    state = parts[status_index + 1] if status_index + 1 < len(parts) else ""
    tail = parts[status_index + 2 :]
    if not tail:
        return status, state, ""

    if len(tail) >= 2 and tail[0].lower() == "on" and tail[1].lower() == "cpu":
        return status, state, "CPU", " ".join(tail[:2] + tail[2:])

    wait_class = tail[0]
    event = " ".join(tail[1:])
    return status, state, wait_class, event


def oratop_session_priority(status: str, state: str, wait_class: str, event: str) -> int:
    text = f"{status} {state} {wait_class} {event}".lower()
    if wait_class == "CPU" and "on cpu" in text:
        return 100
    if wait_class == "CPU" and "runqueue" in text:
        return 90
    if status == "ACT" and state == "RUN":
        return 80
    if status == "ACT":
        return 60
    if wait_class and wait_class != "Idle":
        return 40
    if wait_class == "Idle":
        return 10
    return 0


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
            pre_status = parts[4:status_index]
            proc.name = proc.name or infer_oratop_session_name(pre_status)
            status, state, wait_class, event = parse_oratop_session_tail(parts, status_index)
            new_priority = oratop_session_priority(status, state, wait_class, event)
            current_priority = oratop_session_priority(proc.status, proc.state, proc.wait_class, proc.event)
            if new_priority >= current_priority:
                proc.status = status
                proc.state = state
                proc.wait_class = wait_class
                proc.event = event
            if status_index >= 3:
                cpu_value = parse_number(parts[status_index - 3])
                if cpu_value is not None:
                    proc.oratop_cpu = max(proc.oratop_cpu or 0.0, cpu_value)
            sql_candidates = [
                value
                for value in pre_status
                if re.fullmatch(r"[0-9a-zA-Z]{13}", value) and not value.isdigit()
            ]
            if sql_candidates:
                proc.sql_id = sql_candidates[-1]
            if "DED" in pre_status:
                ded_index = pre_status.index("DED")
                proc.service = pre_status[ded_index + 1] if ded_index + 1 < len(pre_status) else ""

    return processes, events


def infer_oratop_session_name(pre_status: list[str]) -> str:
    if not pre_status:
        return "oratop-session"
    sql_index = next(
        (index for index, value in enumerate(pre_status) if re.fullmatch(r"[0-9a-zA-Z]{13}", value) and not value.isdigit()),
        None,
    )
    end = sql_index if sql_index is not None else len(pre_status)
    service_markers = {"DED", "SHR", "PSE"}
    marker_index = next((index for index, value in enumerate(pre_status[:end]) if value in service_markers), end)
    name_tokens = pre_status[:marker_index]
    return " ".join(name_tokens) if name_tokens else "oratop-session"


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


def none_sum(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return sum(present) if present else None


def avg_present(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return mean(present) if present else None


def summarize_mpstat_rows(cpus: list[int], mpstat: dict[int, MpstatCpu]) -> dict[str, float | int | None]:
    mp_rows = [mpstat[cpu] for cpu in cpus if cpu in mpstat]
    return {
        "cpus": len(cpus),
        "active_cpus": len(mp_rows),
        "cs": none_sum(row.avg("cs") for row in mp_rows),
        "ics": none_sum(row.avg("ics") for row in mp_rows),
        "rq": none_sum(row.avg("rq") for row in mp_rows),
        "bound": none_sum(row.avg("bound") for row in mp_rows),
        "s0rd": avg_present(row.avg("S0rd") for row in mp_rows),
        "s1rd": avg_present(row.avg("S1rd") for row in mp_rows),
        "s2rd": avg_present(row.avg("S2rd") for row in mp_rows),
        "s3rd": avg_present(row.avg("S3rd") for row in mp_rows),
        "s4rd": avg_present(row.avg("S4rd") for row in mp_rows),
        "s5rd": avg_present(row.avg("S5rd") for row in mp_rows),
        "s0hrd": avg_present(row.avg("S0hrd") for row in mp_rows),
        "s1hrd": avg_present(row.avg("S1hrd") for row in mp_rows),
        "s2hrd": avg_present(row.avg("S2hrd") for row in mp_rows),
        "s3hrd": avg_present(row.avg("S3hrd") for row in mp_rows),
        "s4hrd": avg_present(row.avg("S4hrd") for row in mp_rows),
        "s5hrd": avg_present(row.avg("S5hrd") for row in mp_rows),
        "nsp": avg_present(row.avg("%nsp") for row in mp_rows),
    }


def lssrad_range_stats(
    placements: dict[int, CpuPlacement], mpstat: dict[int, MpstatCpu]
) -> dict[str, dict[str, float | int | None]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for cpu, placement in placements.items():
        grouped[placement.lssrad_range_label].append(cpu)
    return {label: summarize_mpstat_rows(cpus, mpstat) for label, cpus in grouped.items()}


def lssrad_range_mapping(placements: dict[int, CpuPlacement]) -> list[dict[str, object]]:
    grouped: dict[tuple[int, str], dict[str, object]] = {}
    for placement in placements.values():
        key = (placement.lssrad_range_index, placement.lssrad_range_label)
        row = grouped.setdefault(
            key,
            {
                "lssrad_range_index": placement.lssrad_range_index,
                "lssrad_range_label": placement.lssrad_range_label,
                "ranges": set(),
            },
        )
        row["ranges"].add(
            f"REF {placement.ref if placement.ref is not None else '-'} / SRAD {placement.srad}: {placement.lssrad_cpu_range}"
        )
    return [
        {
            "lssrad_range_index": row["lssrad_range_index"],
            "lssrad_range_label": row["lssrad_range_label"],
            "ranges": sorted(row["ranges"]),
        }
        for _, row in sorted(grouped.items())
    ]


def trace_cpu_counts(trace_by_pid: dict[int, TraceThread]) -> Counter[int]:
    counts: Counter[int] = Counter()
    for trace in trace_by_pid.values():
        counts.update(trace.cpus)
    return counts


def smt_position_stats(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    trace_by_pid: dict[int, TraceThread],
    smt_width: int | None,
) -> list[dict[str, object]]:
    if smt_width is None:
        return []
    trace_counts = trace_cpu_counts(trace_by_pid)
    total_trace_samples = sum(trace_counts.values())
    rows: list[dict[str, object]] = []
    for position in range(smt_width):
        cpus = sorted(cpu for cpu, placement in placements.items() if placement.smt_position == position)
        samples = sum(trace_counts.get(cpu, 0) for cpu in cpus)
        stats = summarize_mpstat_rows(cpus, mpstat)
        rows.append(
            {
                "smt_position": position,
                "smt_class": smt_class_label(position),
                "lcpus": cpus,
                "active_lcpu_count": sum(1 for cpu in cpus if trace_counts.get(cpu, 0) > 0),
                "trace_samples_total": samples,
                "trace_samples_percent": (samples / total_trace_samples * 100.0) if total_trace_samples else 0.0,
                "average_samples_per_lcpu": (samples / len(cpus)) if cpus else 0.0,
                "rq_total": stats["rq"],
                "bound_total": stats["bound"],
                "nsp_avg": stats["nsp"],
                "s2rd": stats["s2rd"],
                "s3rd": stats["s3rd"],
                "s3hrd": stats["s3hrd"],
                "s4hrd": stats["s4hrd"],
                "s5hrd": stats["s5hrd"],
            }
        )
    return rows


def global_smt_summary(trace_by_pid: dict[int, TraceThread], smt_width: int | None) -> dict[str, object]:
    if smt_width is None:
        return {
            "known": False,
            "total_samples": sum(trace.samples for trace in trace_by_pid.values()),
            "classes": {},
            "deeper_thread_samples": None,
            "deeper_thread_percent": None,
        }
    counts: Counter[str] = Counter()
    for trace in trace_by_pid.values():
        counts.update(trace.smt_classes)
    total = sum(counts.values())
    class_rows = {}
    for label in smt_class_labels(smt_width):
        samples = counts.get(label, 0)
        class_rows[label] = {
            "samples": samples,
            "percent": (samples / total * 100.0) if total else 0.0,
        }
    deeper = sum(counts.get(label, 0) for label in smt_class_labels(smt_width)[1:])
    return {
        "known": True,
        "total_samples": total,
        "classes": class_rows,
        "deeper_thread_samples": deeper,
        "deeper_thread_percent": (deeper / total * 100.0) if total else 0.0,
    }


def physical_core_stats(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    trace_by_pid: dict[int, TraceThread],
    smt_width: int | None,
) -> list[dict[str, object]]:
    if smt_width is None:
        return []
    trace_counts = trace_cpu_counts(trace_by_pid)
    by_core: dict[int, list[CpuPlacement]] = defaultdict(list)
    for placement in placements.values():
        if placement.physical_core_id is not None:
            by_core[placement.physical_core_id].append(placement)

    rows: list[dict[str, object]] = []
    for core_id, core_placements in sorted(by_core.items()):
        lcpus_by_class: dict[str, int | None] = {label: None for label in smt_class_labels(smt_width)}
        samples_by_class: dict[str, int] = {label: 0 for label in smt_class_labels(smt_width)}
        srads = sorted({placement.srad for placement in core_placements})
        refs = sorted({placement.ref for placement in core_placements if placement.ref is not None})
        for placement in core_placements:
            lcpus_by_class[placement.smt_class_label] = placement.lcpu
            samples_by_class[placement.smt_class_label] = trace_counts.get(placement.lcpu, 0)
        lcpus = [placement.lcpu for placement in core_placements]
        stats = summarize_mpstat_rows(lcpus, mpstat)
        rows.append(
            {
                "physical_core_id": core_id,
                "ref": ",".join(str(ref) for ref in refs) if refs else "-",
                "srad": ",".join(str(srad) for srad in srads),
                "lcpus_by_smt_class": lcpus_by_class,
                "samples_by_smt_class": samples_by_class,
                "trace_samples": sum(samples_by_class.values()),
                "active_threads": sum(1 for samples in samples_by_class.values() if samples > 0),
                "available_threads": len(core_placements),
                "rq_total": stats["rq"],
                "bound_total": stats["bound"],
                "nsp_avg": stats["nsp"],
            }
        )
    return sorted(rows, key=lambda row: (int(row["trace_samples"]), float(row["rq_total"] or 0.0)), reverse=True)


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
                "lssrad_ranges": Counter(),
                "smt_classes": Counter(),
                "smt_positions": Counter(),
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
            row["lssrad_ranges"].update(trace.lssrad_ranges)
            row["smt_classes"].update(trace.smt_classes)
            row["smt_positions"].update(trace.smt_positions)
    return sorted(grouped.values(), key=lambda row: float(row["cpu"]), reverse=True)


def sum_stat(stats: dict[str, dict[str, float | int | None]], key: str) -> float:
    return sum(float(values.get(key) or 0.0) for values in stats.values())


def build_findings(
    stats: dict[str, dict[str, float | int | None]],
    events: list[dict[str, str]],
    processes: dict[int, OracleProcess],
    topology: dict[str, object],
    remote_rd_threshold: float,
    rq_threshold: float,
) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []
    for warning in topology.get("warnings", []):
        findings.append(("warning", "SMT topology warning", str(warning)))

    total_rq = sum_stat(stats, "rq")
    total_bound = sum_stat(stats, "bound")
    if total_rq >= rq_threshold or total_bound >= rq_threshold:
        findings.append(
            (
                "critical",
                "System appears CPU-bound",
                f"mpstat shows LCPU pressure with total average run queue {total_rq:.1f} and bound {total_bound:.1f}; "
                f"the run-queue heuristic threshold is {rq_threshold:.1f}.",
            )
        )

    high_remote = []
    for label, values in stats.items():
        s3rd = values.get("s3rd")
        s3hrd = values.get("s3hrd")
        if (s3rd is not None and float(s3rd) >= remote_rd_threshold) or (
            s3hrd is not None and float(s3hrd) < 85.0
        ):
            high_remote.append((label, values))
    for label, values in high_remote:
        findings.append(
            (
                "warning",
                f"Elevated remote dispatch/readiness on {label}",
                f"{label}: S3rd={fmt(values.get('s3rd'))}%, S3hrd={fmt(values.get('s3hrd'))}%. "
                "Missing mpstat columns are treated as n/a and do not trigger this finding.",
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
                f"oratop reports CPU Runqueue for SPID: {pids}. This corroborates CPU pressure visible in mpstat and trace.",
            )
        )

    log_file_sync = next(
        (event for event in summarize_events(events) if "log file sync" in str(event.get("event", "")).lower()),
        None,
    )
    if log_file_sync:
        findings.append(
            (
                "info",
                "Commit/log file sync latency is visible",
                f"log file sync accounts for {float(log_file_sync.get('dbt_sum', 0.0)):.1f}% total DB time across oratop samples, "
                f"last avg={log_file_sync.get('last_avg')}. CPU pressure can amplify this, but LGWR/storage remain separate suspects.",
            )
        )

    if not findings:
        findings.append(("ok", "No strong heuristic anomalies", "No alert thresholds were detected in the supplied files."))
    return findings


def diagnose_vpm_throughput_mode(
    stats: dict[str, dict[str, float | int | None]],
    events: list[dict[str, str]],
    processes: dict[int, OracleProcess],
    trace_by_pid: dict[int, TraceThread],
    topology: dict[str, object],
    mp_config: dict[str, str],
    rq_threshold: float,
) -> dict[str, object]:
    total_rq = sum_stat(stats, "rq")
    total_bound = sum_stat(stats, "bound")
    mode = mp_config.get("mode", "unknown")
    ent = mp_config.get("ent", "unknown")
    capped = mode.lower() == "capped"
    cpu_bound = total_rq >= rq_threshold or total_bound >= rq_threshold
    oracle_cpu_wait = any(
        proc.wait_class == "CPU" and "Runqueue" in proc.event and (proc.oratop_cpu or 0) > 0
        for proc in processes.values()
    )
    smt_summary = global_smt_summary(trace_by_pid, topology.get("smt_width"))
    deeper_percent = smt_summary.get("deeper_thread_percent")
    deep_smt = deeper_percent is not None and float(deeper_percent) >= 25.0
    primary_percent = 0.0
    if smt_summary.get("known"):
        primary_percent = float(smt_summary["classes"].get("primary", {}).get("percent", 0.0))

    summarized = summarize_events(events)
    cpu_event_dbt = sum(
        float(event.get("dbt_sum", 0.0))
        for event in summarized
        if str(event.get("class", "")).upper() == "CPU" or "runqueue" in str(event.get("event", "")).lower()
    )

    evidence = [
        f"mpstat total rq={total_rq:.1f}, total bound={total_bound:.1f}; CPU-bound={yes_no(cpu_bound)}; threshold rq={rq_threshold:.1f}.",
        f"LPAR mode={mode}, entitlement={ent}.",
        f"Oracle CPU Runqueue waits={yes_no(oracle_cpu_wait)}, aggregated CPU wait DB time={cpu_event_dbt:.1f}%.",
    ]
    if smt_summary.get("known"):
        class_bits = [
            f"{label}={row['percent']:.1f}%/{row['samples']}"
            for label, row in smt_summary["classes"].items()
        ]
        evidence.append(
            "Oracle trace SMT distribution: "
            + ", ".join(class_bits)
            + f"; deeper SMT share={float(deeper_percent or 0.0):.1f}%."
        )
    else:
        evidence.append("SMT width is unknown, so vpm diagnosis cannot use primary/secondary/tertiary trace distribution.")
    if capped:
        evidence.append("LPAR is capped; vpm_throughput_mode can change VP unfolding behavior but cannot exceed entitlement.")

    commands = {
        "show_current": "schedo -o vpm_throughput_mode",
        "test_raw_runtime": "schedo -o vpm_throughput_mode=1",
        "test_scaled_2_runtime": "schedo -o vpm_throughput_mode=2",
        "test_scaled_4_runtime": "schedo -o vpm_throughput_mode=4",
        "test_scaled_8_runtime": "schedo -o vpm_throughput_mode=8",
        "rollback_runtime": "schedo -o vpm_throughput_mode=0",
    }

    if cpu_bound and (oracle_cpu_wait or cpu_event_dbt > 0.0) and deep_smt:
        level = "critical"
        title = "vpm_throughput_mode is worth a controlled test"
        recommended_value = 1
        action = (
            "Test raw throughput mode first, then compare scaled throughput 2 or 4 if power/packing behavior matters."
        )
        body = (
            "Oracle samples are materially present on secondary or deeper SMT threads while the workload is CPU-bound. "
            "That pattern supports testing earlier VP unfolding so work reaches additional physical cores before filling deep SMT siblings."
        )
    elif cpu_bound and primary_percent >= 80.0 and not deep_smt:
        level = "info"
        title = "SMT trace samples are mostly primary"
        recommended_value = 0
        action = (
            "Keep mode 0 unless other evidence shows virtual processors remain folded; inspect entitlement and VP configuration."
        )
        body = (
            "The trace does not show heavy use of deeper SMT siblings. If CPU queues still exist, the next question is whether VP count, entitlement, "
            "or capped mode is limiting dispatch rather than SMT depth."
        )
    elif cpu_bound:
        level = "warning"
        title = "vpm_throughput_mode may help, evidence is partial"
        recommended_value = 2 if topology.get("smt_width") in {4, 8} else 1
        action = (
            f"Test vpm_throughput_mode={recommended_value}; compare with raw throughput mode 1 during the same workload pattern."
        )
        body = (
            "CPU pressure is visible, but the SMT distribution or Oracle CPU-wait evidence is incomplete. A controlled A/B test is reasonable."
        )
    else:
        level = "ok"
        title = "vpm_throughput_mode is not indicated by this capture"
        recommended_value = 0
        action = "Keep vpm_throughput_mode=0 unless a separate workload test proves a benefit."
        body = "The supplied files do not show enough CPU pressure or Oracle CPU-wait evidence to make VP unfolding the main recommendation."

    commands["set_runtime"] = f"schedo -o vpm_throughput_mode={recommended_value}"
    commands["set_persistent"] = f"schedo -p -o vpm_throughput_mode={recommended_value}"
    commands["rollback_persistent"] = "schedo -p -o vpm_throughput_mode=0"

    return {
        "level": level,
        "title": title,
        "recommended_value": recommended_value,
        "supported_values": {
            "0": "default / raise utilization / power-saving; later VP unfolding",
            "1": "raw throughput; less folding and faster unfolding",
            "2": "scaled throughput; unfold another VP after about 2 SMT threads per core",
            "4": "scaled throughput; unfold another VP after about 4 SMT threads per core",
            "8": "scaled throughput; unfold another VP after about 8 SMT threads per core",
        },
        "recommended_action": action,
        "commands": commands,
        "evidence": evidence,
        "interpretation": body,
    }


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def fmt(value: float | int | object | None, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def esc(value: object) -> str:
    return html.escape(str(value))


def pct(counter: Counter, labels: list[str]) -> dict[str, tuple[int, float]]:
    total = sum(counter.values())
    return {
        label: (counter.get(label, 0), (counter.get(label, 0) / total * 100.0) if total else 0.0)
        for label in labels
    }


def top_counter(counter: Counter, limit: int = 5) -> str:
    if not counter:
        return "-"
    return ", ".join(f"{key}:{value}" for key, value in counter.most_common(limit))


def render_findings(findings: list[tuple[str, str, str]]) -> str:
    return "\n".join(
        f'<div class="finding {esc(level)}"><strong>{esc(title)}</strong><p>{esc(body)}</p></div>'
        for level, title, body in findings
    )


def render_topology_note(topology: dict[str, object]) -> str:
    warnings = topology.get("warnings", [])
    warning_html = "".join(f"<br><strong>Warning:</strong> {esc(warning)}" for warning in warnings)
    smtctl_info = topology.get("smtctl", {})
    mixed = " yes" if smtctl_info.get("smt_width_mixed") else " no"
    return (
        '<p class="note">'
        f"SMT width=<strong>{esc(topology.get('smt_width', 'unknown'))}</strong>; "
        f"source=<strong>{esc(topology.get('smt_width_source', 'unknown'))}</strong>; "
        f"classes={esc(', '.join(topology.get('smt_classes', [])) or 'unknown')}; "
        f"smtctl mixed width={esc(mixed.strip())}."
        f"{warning_html}</p>"
    )


def render_lssrad_range_table(stats: dict[str, dict[str, float | int | None]]) -> str:
    rows = []
    for label in sorted(stats, key=lambda value: int(value.split("-")[-1])):
        values = stats[label]
        rows.append(
            "<tr>"
            f"<td>{esc(label)}</td>"
            f"<td>{fmt(values.get('cpus'), 0)}</td>"
            f"<td>{fmt(values.get('rq'))}</td>"
            f"<td>{fmt(values.get('bound'))}</td>"
            f"<td>{fmt(values.get('s0rd'))}%</td>"
            f"<td>{fmt(values.get('s1rd'))}%</td>"
            f"<td>{fmt(values.get('s2rd'))}%</td>"
            f"<td>{fmt(values.get('s3rd'))}%</td>"
            f"<td>{fmt(values.get('s3hrd'))}%</td>"
            f"<td>{fmt(values.get('nsp'))}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>LSSRAD CPU range</th><th>LCPU</th><th>rq</th><th>bound</th>"
        "<th>S0rd</th><th>S1rd</th><th>S2rd</th><th>S3rd</th><th>S3hrd</th><th>%nsp</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_lssrad_range_mapping_table(rows_data: list[dict[str, object]]) -> str:
    rows = []
    for row in rows_data:
        rows.append(
            "<tr>"
            f"<td>{esc(row['lssrad_range_label'])}</td>"
            f"<td>{esc(row['lssrad_range_index'])}</td>"
            f"<td>{esc('; '.join(row['ranges']))}</td>"
            "</tr>"
        )
    return (
        "<h3>LSSRAD CPU Range Mapping</h3>"
        '<p class="note">These labels are neutral positions of CPU ranges listed by <code>lssrad -av</code>. '
        "They are not SMT classes.</p>"
        "<table><thead><tr><th>LSSRAD CPU range</th><th>Range order</th><th>CPU ranges by REF/SRAD</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_cpu_table(placements: dict[int, CpuPlacement], mpstat: dict[int, MpstatCpu]) -> str:
    rows = []
    for cpu in sorted(placements):
        placement = placements[cpu]
        mp = mpstat.get(cpu)
        rows.append(
            "<tr>"
            f"<td>{cpu}</td>"
            f"<td>{esc(placement.ref if placement.ref is not None else '-')}</td>"
            f"<td>{placement.srad}</td>"
            f"<td>{esc(placement.lssrad_range_label)}</td>"
            f"<td>{esc(placement.lssrad_cpu_range)}</td>"
            f"<td>{fmt(placement.physical_core_id, 0)}</td>"
            f"<td>{fmt(placement.smt_position, 0)}</td>"
            f"<td>{esc(placement.smt_class_label)}</td>"
            f"<td>{fmt(mp.avg('rq') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('cs') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('ics') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('S0rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S1rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S2rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3hrd') if mp else None)}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>LCPU</th><th>REF</th><th>SRAD</th><th>LSSRAD CPU range</th><th>Range</th>"
        "<th>Physical core</th><th>SMT position</th><th>SMT class</th>"
        "<th>rq</th><th>cs</th><th>ics</th><th>S0rd</th><th>S1rd</th><th>S2rd</th><th>S3rd</th><th>S3hrd</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_global_smt_summary(summary: dict[str, object]) -> str:
    if not summary.get("known"):
        return '<p class="note">SMT width is unknown, so Oracle SMT class distribution is not calculated.</p>'
    rows = []
    for label, values in summary["classes"].items():
        rows.append(
            "<tr>"
            f"<td>{esc(label)}</td>"
            f"<td>{esc(values['samples'])}</td>"
            f"<td>{fmt(float(values['percent']))}%</td>"
            "</tr>"
        )
    interpretation = (
        "A high share on secondary/tertiary/quaternary during CPU-bound windows means Oracle is filling deeper SMT siblings. "
        "That is direct evidence for testing raw throughput mode or a lower scaled-throughput threshold."
    )
    return (
        f'<p class="note">{esc(interpretation)} Deeper SMT share: '
        f"<strong>{fmt(summary.get('deeper_thread_percent'))}%</strong>.</p>"
        "<table><thead><tr><th>SMT class</th><th>Oracle trace samples</th><th>Share</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_physical_core_table(rows_data: list[dict[str, object]], smt_width: int | None) -> str:
    if smt_width is None:
        return '<p class="note">Physical core view requires known SMT width.</p>'
    labels = smt_class_labels(smt_width)
    header = "".join(f"<th>{esc(label)} LCPU</th><th>{esc(label)} samples</th>" for label in labels)
    rows = []
    for row in rows_data:
        dynamic = "".join(
            f"<td>{esc(row['lcpus_by_smt_class'].get(label) if row['lcpus_by_smt_class'].get(label) is not None else '-')}</td>"
            f"<td>{esc(row['samples_by_smt_class'].get(label, 0))}</td>"
            for label in labels
        )
        rows.append(
            "<tr>"
            f"<td>{esc(row['physical_core_id'])}</td>"
            f"<td>{esc(row['ref'])}</td>"
            f"<td>{esc(row['srad'])}</td>"
            f"{dynamic}"
            f"<td>{esc(row['active_threads'])}/{esc(row['available_threads'])}</td>"
            f"<td>{esc(row['trace_samples'])}</td>"
            f"<td>{fmt(row['rq_total'])}</td>"
            f"<td>{fmt(row['bound_total'])}</td>"
            f"<td>{fmt(row['nsp_avg'])}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Physical core</th><th>REF</th><th>SRAD</th>"
        + header
        + "<th>Active SMT threads</th><th>Trace samples</th><th>rq total</th><th>bound total</th><th>avg %nsp</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_smt_position_table(rows_data: list[dict[str, object]]) -> str:
    rows = []
    for row in rows_data:
        rows.append(
            "<tr>"
            f"<td>{esc(row['smt_position'])}</td>"
            f"<td>{esc(row['smt_class'])}</td>"
            f"<td>{esc(', '.join(str(cpu) for cpu in row['lcpus']))}</td>"
            f"<td>{esc(row['active_lcpu_count'])}</td>"
            f"<td>{esc(row['trace_samples_total'])}</td>"
            f"<td>{fmt(float(row['trace_samples_percent']))}%</td>"
            f"<td>{fmt(float(row['average_samples_per_lcpu']))}</td>"
            f"<td>{fmt(row['rq_total'])}</td>"
            f"<td>{fmt(row['bound_total'])}</td>"
            f"<td>{fmt(row['nsp_avg'])}%</td>"
            f"<td>{fmt(row['s2rd'])}%</td>"
            f"<td>{fmt(row['s3rd'])}%</td>"
            f"<td>{fmt(row['s3hrd'])}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>SMT position</th><th>SMT class</th><th>LCPU list</th><th>Active LCPU count</th>"
        "<th>Trace samples total</th><th>Trace samples %</th><th>Average samples per LCPU</th>"
        "<th>rq total</th><th>bound total</th><th>avg %nsp</th><th>S2rd</th><th>S3rd</th><th>S3hrd</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_smt_class_cells(counter: Counter[str], labels: list[str]) -> str:
    return "".join(
        f"<td>{samples}</td><td>{fmt(percent)}%</td>"
        for samples, percent in pct(counter, labels).values()
    )


def render_smt_class_headers(labels: list[str]) -> str:
    return "".join(f"<th>{esc(label)} samples</th><th>{esc(label)} %</th>" for label in labels)


def render_process_table(
    processes: list[OracleProcess],
    trace_by_pid: dict[int, TraceThread],
    smt_width: int | None,
) -> str:
    labels = smt_class_labels(smt_width)
    rows = []
    for proc in processes:
        trace = trace_by_pid.get(proc.pid)
        trace_samples = trace.samples if trace else 0
        cpus = top_counter(trace.cpus if trace else Counter(), 8)
        dynamic = render_smt_class_cells(trace.smt_classes if trace else Counter(), labels)
        rows.append(
            "<tr>"
            f"<td>{proc.pid}</td>"
            f"<td>{esc(proc.name or '-')}</td>"
            f"<td>{esc(proc.sid or '-')}</td>"
            f"<td>{esc(proc.username or '-')}</td>"
            f"<td>{esc(proc.sql_id or '-')}</td>"
            f"<td>{fmt(proc.oratop_cpu)}%</td>"
            f"<td>{trace_samples}</td>"
            f"{dynamic}"
            f"<td>{esc(cpus)}</td>"
            f"<td>{esc(top_counter(trace.lssrad_ranges if trace else Counter(), 5))}</td>"
            f"<td>{esc(proc.status or '-')} {esc(proc.state or '')}</td>"
            f"<td>{esc(proc.wait_class or '-')}</td>"
            f"<td>{esc(proc.event or '-')}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>PID/SPID</th><th>Name</th><th>SID</th><th>User</th><th>SQL_ID</th><th>oratop %CPU</th>"
        "<th>trace samples</th>"
        + render_smt_class_headers(labels)
        + "<th>Top LCPU</th><th>LSSRAD CPU range</th><th>Status</th><th>Wait class</th><th>Event</th></tr></thead><tbody>"
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
            f"<td>{esc(top_counter(trace.lssrad_ranges, 5))}</td>"
            f"<td>{esc(top_counter(trace.smt_classes, 8))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>PID</th><th>Name</th><th>trace samples</th><th>CPU</th><th>LSSRAD CPU range</th><th>SMT class</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_sql_table(rows_data: list[dict[str, object]], smt_width: int | None) -> str:
    labels = smt_class_labels(smt_width)
    rows = []
    for row in rows_data[:100]:
        pids = sorted(row["pids"])
        dynamic = render_smt_class_cells(row["smt_classes"], labels)
        rows.append(
            "<tr>"
            f"<td>{esc(row['sql_id'])}</td>"
            f"<td>{fmt(float(row['cpu']))}%</td>"
            f"<td>{len(pids)}</td>"
            f"<td>{esc(', '.join(str(pid) for pid in pids[:12]))}</td>"
            f"{dynamic}"
            f"<td>{esc(top_counter(row['cpus'], 12))}</td>"
            f"<td>{esc(top_counter(row['lssrad_ranges'], 5))}</td>"
            f"<td>{esc(top_counter(row['users'], 5))}</td>"
            f"<td>{esc(top_counter(row['waits'], 5))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>SQL_ID</th><th>sum %CPU</th><th>PIDs</th><th>PID list</th>"
        + render_smt_class_headers(labels)
        + "<th>Top LCPU</th><th>LSSRAD CPU range</th><th>Users</th><th>Wait classes</th></tr></thead><tbody>"
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


def render_vpm_diagnosis(diagnosis: dict[str, object]) -> str:
    commands = diagnosis.get("commands", {})
    command_lines = "".join(
        f"<li><strong>{esc(label.replace('_', ' ').title())}:</strong> <code>{esc(command)}</code></li>"
        for label, command in commands.items()
    )
    evidence_lines = "".join(f"<li>{esc(line)}</li>" for line in diagnosis.get("evidence", []))
    supported = "".join(
        f"<li><code>{esc(value)}</code>: {esc(text)}</li>"
        for value, text in diagnosis.get("supported_values", {}).items()
    )
    return (
        f'<div class="finding {esc(diagnosis.get("level", "info"))}">'
        f'<strong>{esc(diagnosis.get("title", ""))}</strong>'
        f'<p><strong>Recommended value:</strong> <code>{esc(diagnosis.get("recommended_value", "-"))}</code>. '
        f'{esc(diagnosis.get("recommended_action", ""))}</p>'
        f'<p>{esc(diagnosis.get("interpretation", ""))}</p>'
        f"<p><strong>Supported values</strong></p><ul>{supported}</ul>"
        f"<p><strong>AIX commands</strong></p><ul>{command_lines}</ul>"
        f"<p><strong>Evidence</strong></p><ul>{evidence_lines}</ul>"
        "</div>"
    )


def render_report(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    mp_config: dict[str, str],
    mp_columns: set[str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
    topology: dict[str, object],
    remote_rd_threshold: float,
    rq_threshold: float,
    out_path: Path,
) -> None:
    stats = lssrad_range_stats(placements, mpstat)
    findings = build_findings(stats, events, processes, topology, remote_rd_threshold, rq_threshold)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid, topology, mp_config, rq_threshold)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)
    smt_width = topology.get("smt_width")
    core_stats = physical_core_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_stats = smt_position_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_summary = global_smt_summary(trace_by_pid, smt_width)
    range_mapping = lssrad_range_mapping(placements)
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
h3 {{ margin: 20px 0 10px; font-size: 16px; }}
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
<div class="card"><div class="label">SMT Width</div><div class="value">{esc(smt_width if smt_width is not None else "unknown")}</div></div>
<div class="card"><div class="label">SMT Source</div><div class="value">{esc(topology.get("smt_width_source", "unknown"))}</div></div>
<div class="card"><div class="label">Oracle PIDs in trace</div><div class="value">{len(trace_by_pid)}</div></div>
</section>

<h2>Findings</h2>
{render_findings(findings)}

<h2>SMT Topology</h2>
{render_topology_note(topology)}

<h2>Oracle on SMT Threads</h2>
{render_global_smt_summary(smt_summary)}

<h3>Per Oracle Process</h3>
{render_process_table(top_processes, trace_by_pid, smt_width)}

<h3>Per SQL_ID</h3>
{render_sql_table(top_sql, smt_width)}

<h2>SMT Position Summary</h2>
{render_smt_position_table(smt_stats)}

<h2>Physical Cores</h2>
<p class="note">Physical core ID is calculated as <code>lcpu // smt_width</code>; SMT class is <code>lcpu % smt_width</code>.</p>
{render_physical_core_table(core_stats, smt_width)}

<h2>LSSRAD CPU Range Summary</h2>
<p class="note">LSSRAD CPU range labels are only the order of CPU ranges inside <code>lssrad -av</code>. They are NUMA/topology inventory, not SMT primary/secondary classes.</p>
{render_lssrad_range_table(stats)}
{render_lssrad_range_mapping_table(range_mapping)}

<h2>LCPU Map</h2>
{render_cpu_table(placements, mpstat)}

<h2>Trace Processes by CPU</h2>
{render_trace_table(trace_by_pid)}

<h2>Top Wait Events from oratop</h2>
{render_events_table(summarized_events)}

<h2>mpstat Columns</h2>
<p class="note">Parsed dynamically from the mpstat header. Available columns: {esc(", ".join(sorted(mp_columns)))}.</p>

<h2>vpm_throughput_mode Diagnosis</h2>
{render_vpm_diagnosis(vpm_diagnosis)}
</main>
<script>
document.querySelectorAll('table').forEach((table) => {{
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


def counter_to_dict(counter: Counter) -> dict[str, int]:
    return {str(key): int(value) for key, value in counter.items()}


def build_json_report(
    placements: dict[int, CpuPlacement],
    mpstat: dict[int, MpstatCpu],
    mp_config: dict[str, str],
    mp_columns: set[str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
    topology: dict[str, object],
    remote_rd_threshold: float,
    rq_threshold: float,
) -> dict[str, object]:
    stats = lssrad_range_stats(placements, mpstat)
    findings = build_findings(stats, events, processes, topology, remote_rd_threshold, rq_threshold)
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid, topology, mp_config, rq_threshold)
    smt_width = topology.get("smt_width")
    core_stats = physical_core_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_stats = smt_position_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_summary = global_smt_summary(trace_by_pid, smt_width)

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "mpstat_config": mp_config,
        "mpstat_columns": sorted(mp_columns),
        "smt_topology": topology,
        "summary": {
            "lcpu": mp_config.get("lcpu", len(placements)),
            "entitlement": mp_config.get("ent", "-"),
            "mode": mp_config.get("mode", "-"),
            "oracle_pids_in_trace": len(trace_by_pid),
            "smt_width": smt_width,
            "smt_width_source": topology.get("smt_width_source"),
        },
        "findings": [{"level": level, "title": title, "details": details} for level, title, details in findings],
        "vpm_throughput_mode": vpm_diagnosis,
        "oracle_smt_summary": smt_summary,
        "lssrad_cpu_range_mapping": lssrad_range_mapping(placements),
        "lssrad_cpu_range_stats": stats,
        "physical_core_stats": core_stats,
        "smt_position_summary": smt_stats,
        "lcpu_map": [
            {
                "lcpu": cpu,
                "ref": placement.ref,
                "srad": placement.srad,
                "lssrad_range_index": placement.lssrad_range_index,
                "lssrad_range_label": placement.lssrad_range_label,
                "lssrad_cpu_range": placement.lssrad_cpu_range,
                "smt_width": placement.smt_width,
                "smt_position": placement.smt_position,
                "smt_class_label": placement.smt_class_label,
                "physical_core_id": placement.physical_core_id,
                "mpstat": {
                    "rq": mpstat[cpu].avg("rq") if cpu in mpstat else None,
                    "cs": mpstat[cpu].avg("cs") if cpu in mpstat else None,
                    "ics": mpstat[cpu].avg("ics") if cpu in mpstat else None,
                    "S0rd": mpstat[cpu].avg("S0rd") if cpu in mpstat else None,
                    "S1rd": mpstat[cpu].avg("S1rd") if cpu in mpstat else None,
                    "S2rd": mpstat[cpu].avg("S2rd") if cpu in mpstat else None,
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
                    "lssrad_ranges": counter_to_dict(trace_by_pid[proc.pid].lssrad_ranges) if proc.pid in trace_by_pid else {},
                    "smt_classes": counter_to_dict(trace_by_pid[proc.pid].smt_classes) if proc.pid in trace_by_pid else {},
                    "smt_positions": counter_to_dict(trace_by_pid[proc.pid].smt_positions) if proc.pid in trace_by_pid else {},
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
                "lssrad_ranges": counter_to_dict(trace.lssrad_ranges),
                "smt_classes": counter_to_dict(trace.smt_classes),
                "smt_positions": counter_to_dict(trace.smt_positions),
            }
            for trace in sorted(trace_by_pid.values(), key=lambda row: row.samples, reverse=True)
        ],
        "top_sql_ids": [
            {
                "sql_id": row["sql_id"],
                "sum_cpu": row["cpu"],
                "pids": sorted(row["pids"]),
                "cpus": counter_to_dict(row["cpus"]),
                "lssrad_ranges": counter_to_dict(row["lssrad_ranges"]),
                "smt_classes": counter_to_dict(row["smt_classes"]),
                "smt_positions": counter_to_dict(row["smt_positions"]),
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
    mp_columns: set[str],
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    events: list[dict[str, str]],
    topology: dict[str, object],
    remote_rd_threshold: float,
    rq_threshold: float,
    out_path: Path,
) -> None:
    data = build_json_report(
        placements,
        mpstat,
        mp_config,
        mp_columns,
        trace_by_pid,
        processes,
        events,
        topology,
        remote_rd_threshold,
        rq_threshold,
    )
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def assert_equal(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def run_selftests() -> None:
    placements = {lcpu: CpuPlacement(lcpu, None, 0, 1, "range-1", "0-7") for lcpu in range(8)}
    apply_smt_topology(placements, 4)
    assert_equal((placements[0].smt_class_label, placements[0].physical_core_id), ("primary", 0), "SMT-4 LCPU 0")
    assert_equal((placements[1].smt_class_label, placements[1].physical_core_id), ("secondary", 0), "SMT-4 LCPU 1")
    assert_equal((placements[4].smt_class_label, placements[4].physical_core_id), ("primary", 1), "SMT-4 LCPU 4")
    assert_equal((placements[7].smt_class_label, placements[7].physical_core_id), ("quaternary", 1), "SMT-4 LCPU 7")
    apply_smt_topology(placements, 2)
    assert_equal((placements[5].smt_class_label, placements[5].physical_core_id), ("secondary", 2), "SMT-2 LCPU 5")

    smt4 = parse_smtctl(
        """
This system is SMT capable.
SMT is currently enabled.
proc0 has 4 SMT threads.
proc1 has 4 SMT threads.
"""
    )
    assert_equal(smt4["smt_width"], 4, "smtctl SMT-4")

    smt8 = parse_smtctl(
        """
SMT boot mode is set to enabled.
Processor proc0 is in SMT mode 8.
SMT threads: 8
"""
    )
    assert_equal(smt8["smt_width"], 8, "smtctl SMT-8")

    disabled = parse_smtctl("This system is SMT capable.\nSMT is currently disabled.\nproc0 has 4 SMT threads.\n")
    assert_equal(disabled["smt_width"], 1, "smtctl disabled")

    mixed = parse_smtctl("proc0 has 4 SMT threads.\nproc1 has 8 SMT threads.\nproc2 has 8 SMT threads.\n")
    assert_equal(mixed["smt_width"], 8, "smtctl mixed mode")
    assert_equal(mixed["smt_width_mixed"], True, "smtctl mixed flag")

    mp_text = """System configuration: lcpu=2 ent=2.00 mode=uncapped
cpu min maj mpcs ics cs rq migrations S0rd S1rd
0 0 0 0 0 0 0 0 1.0 2.0
1 0 0 0 0 0 0 0 1.0 2.0
"""
    mpstat, config, columns = parse_mpstat(mp_text)
    stats = lssrad_range_stats(placements, mpstat)
    findings = build_findings(stats, [], {}, {"warnings": []}, remote_rd_threshold=5.0, rq_threshold=8.0)
    assert not any("Elevated remote" in title for _, title, _ in findings), "missing S3hrd must not trigger remote finding"
    assert "S3hrd" not in columns, "S3hrd should be absent from dynamic columns"

    lssrad = parse_lssrad("REF1   SRAD        MEM      CPU\n0\n          0   1.00      0-3 32-35\n")
    smtctl_info = parse_smtctl("proc0 has 8 SMT threads.\n")
    assert_equal(resolve_smt_topology(4, smtctl_info, lssrad)["smt_width_source"], "cli", "CLI source wins")
    assert_equal(resolve_smt_topology(None, smtctl_info, lssrad)["smt_width_source"], "smtctl", "smtctl source wins")
    assert_equal(resolve_smt_topology(None, None, lssrad)["smt_width_source"], "inferred", "inferred source used")

    oratop_text = """ID   SID SPID USERNAME PROGRAM SERVER SERVICE SQLID ELAP %CPU PGA STATUS STATE EVENT
 1  3803 53084826 SYSADM   JDBC Thin DED szpital SEL gn3gtqxvucbj8 1.0s  1.2  0.7  37M ACT RUN            On CPU                3u
"""
    processes, _ = parse_oratop(oratop_text)
    proc = processes[53084826]
    assert_equal(proc.name, "JDBC Thin", "oratop process name")
    assert_equal(proc.sql_id, "gn3gtqxvucbj8", "oratop SQL_ID")
    assert_equal(proc.status, "ACT", "oratop status")
    assert_equal(proc.state, "RUN", "oratop state")
    assert_equal(proc.wait_class, "CPU", "oratop On CPU wait class")
    assert_equal(proc.event, "On CPU 3u", "oratop On CPU event")

    repeated_oratop_text = """ID   SID SPID USERNAME PROGRAM SERVER SERVICE SQLID ELAP %CPU PGA STATUS STATE EVENT
 1  3803 53084826 SYSADM   JDBC Thin DED szpital SEL gn3gtqxvucbj8 1.0s  1.2  0.7  37M ACT RUN            On CPU                3u
 2  3803 53084826 SYSADM   JDBC Thin DED szpital SEL gn3gtqxvucbj8 1.0s  0.1  0.7  37M INA WAI            Idle                  SQL*Net message from client
"""
    repeated_processes, _ = parse_oratop(repeated_oratop_text)
    repeated_proc = repeated_processes[53084826]
    assert_equal(repeated_proc.wait_class, "CPU", "oratop keeps active CPU state over later idle sample")
    assert_equal(repeated_proc.event, "On CPU 3u", "oratop keeps active CPU event over later idle sample")
    assert_equal(repeated_proc.oratop_cpu, 1.2, "oratop keeps max CPU across repeated samples")


def parse_args() -> argparse.Namespace:
    epilog = """Commands to collect input data on AIX:

  smtctl > /tmp/smtctl.out
  oratop -b -n 10 -f -r / as sysdba > /tmp/oratop.out
  trace -a -o /tmp/trace.out
  trcstop
  trcrpt /tmp/trace.out > /tmp/trace.trcrpt
  lssrad -av > /tmp/lssrad_av.out
  mpstat -d 1 60 > /tmp/mpstat_d.out

The --trace argument accepts either the raw /tmp/trace.out file when the tool is run on AIX
with trcrpt available, or the pre-decoded /tmp/trace.trcrpt text file.

Example:

  python3 oraix_report.py \\
    --oratop /tmp/oratop.out \\
    --trace /tmp/trace.trcrpt \\
    --lssrad /tmp/lssrad_av.out \\
    --mpstat /tmp/mpstat_d.out \\
    --smtctl /tmp/smtctl.out \\
    --output /tmp/oraix_report.html
"""
    parser = argparse.ArgumentParser(
        description="Build an HTML AIX Oracle CPU/LCPU/SRAD/SMT report from oratop, trace, lssrad, smtctl, and mpstat.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--oratop", help="File generated by: oratop -b -n 10 -f -r / as sysdba")
    parser.add_argument("--trace", help="Raw AIX trace.out file or text output from trcrpt")
    parser.add_argument("--lssrad", help="File generated by: lssrad -av")
    parser.add_argument("--mpstat", help="File generated by: mpstat -d 1 60")
    parser.add_argument("--smtctl", help="Optional file generated by: smtctl")
    parser.add_argument("--smt-width", type=int, choices=SMT_WIDTH_CHOICES, help="Authoritative SMT width override: 1, 2, 4, or 8")
    parser.add_argument("--remote-rd-threshold", type=float, default=5.0, help="Heuristic threshold for S3rd remote dispatch percent finding")
    parser.add_argument("--rq-threshold", type=float, default=8.0, help="Heuristic threshold for total mpstat rq/bound CPU pressure finding")
    parser.add_argument("--format", choices=("html", "json", "auto"), default="auto", help="Output format. With auto, .json selects JSON; otherwise HTML.")
    parser.add_argument("--output", "-o", default="oraix_report.html", help="Output report path")
    parser.add_argument("--selftest", action="store_true", help="Run built-in parser and SMT topology self-tests")
    return parser.parse_args()


def validate_required_args(args: argparse.Namespace) -> None:
    missing = [name for name in ("oratop", "trace", "lssrad", "mpstat") if not getattr(args, name)]
    if missing:
        raise SystemExit("Missing required arguments: " + ", ".join(f"--{name}" for name in missing))


def main() -> None:
    args = parse_args()
    if args.selftest:
        run_selftests()
        print("Self-tests passed")
        if not any(getattr(args, name) for name in ("oratop", "trace", "lssrad", "mpstat")):
            return

    validate_required_args(args)
    placements = parse_lssrad(read_text(args.lssrad))
    smtctl_info = parse_smtctl(read_text(args.smtctl)) if args.smtctl else None
    topology = resolve_smt_topology(args.smt_width, smtctl_info, placements)
    apply_smt_topology(placements, topology.get("smt_width"))

    mpstat, mp_config, mp_columns = parse_mpstat(read_text(args.mpstat))
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
        write_json_report(
            placements,
            mpstat,
            mp_config,
            mp_columns,
            trace_by_pid,
            processes,
            events,
            topology,
            args.remote_rd_threshold,
            args.rq_threshold,
            output,
        )
    else:
        render_report(
            placements,
            mpstat,
            mp_config,
            mp_columns,
            trace_by_pid,
            processes,
            events,
            topology,
            args.remote_rd_threshold,
            args.rq_threshold,
            output,
        )
    print(f"{output_format.upper()} report written to {output}")


if __name__ == "__main__":
    main()
