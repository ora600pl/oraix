#!/usr/bin/env python3
"""
Build an HTML/JSON report from AIX Oracle CPU placement diagnostics.

The tool expects outputs from:
  smtctl
  oratop -b -n 10 -f -r / as sysdba
  trace -a -o /tmp/trace.out, decoded with trcrpt when not running on AIX
  lssrad -av
  mpstat -d 1 60
  optional AIX tuning/memory context:
    mpstat -v 1 60
    vmstat -v
    vmstat -s
    vmstat 1 60
    TERM=vt100 topas -i 1
    nmon -F /tmp/nmon.nmon -s 1 -c 60 -t
    vmo -F -a
    schedo -a
    lparstat -i
    asoo -a
    lssrc -s aso
    svmon -P <pmon_pid> -O mpss=on
"""

from __future__ import annotations

import argparse
import csv
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
    srad_memory_mb: float | None = None
    smt_width: int | None = None
    smt_position: int | None = None
    physical_core_id: int | None = None
    smt_class_label: str = "unknown"
    smt_mapping_source: str = "unknown"


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

        parts = stripped.split()
        if (
            len(parts) >= 4
            and re.fullmatch(r"\d+", parts[0])
            and re.fullmatch(r"\d+", parts[1])
            and parse_number(parts[2]) is not None
        ):
            current_ref = int(parts[0])
            srad = int(parts[1])
            memory_mb = parse_number(parts[2])
            ranges = parts[3:]
        else:
            match = re.match(r"^\s*(\d+)\s+([\d.]+)\s+(.+?)\s*$", line)
            if not match:
                continue
            # SRAD-only lines inherit the latest REF, including one set by a combined REF/SRAD/MEM/ranges line.
            srad = int(match.group(1))
            memory_mb = parse_number(match.group(2))
            ranges = match.group(3).split()
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
                    srad_memory_mb=memory_mb,
                )
    return placements


def apply_smt_topology(
    placements: dict[int, CpuPlacement],
    smt_width: int | None,
    smtctl_info: dict[str, object] | None = None,
) -> None:
    lcpu_to_core = smtctl_info.get("lcpu_to_core", {}) if smtctl_info else {}
    lcpu_to_position = smtctl_info.get("lcpu_to_position", {}) if smtctl_info else {}
    has_bindmap = bool(smtctl_info and smtctl_info.get("has_bindmap"))
    for placement in placements.values():
        placement.smt_width = smt_width
        if has_bindmap and placement.lcpu in lcpu_to_core and placement.lcpu in lcpu_to_position:
            placement.smt_position = int(lcpu_to_position[placement.lcpu])
            placement.physical_core_id = int(lcpu_to_core[placement.lcpu])
            placement.smt_class_label = smt_class_label(placement.smt_position)
            placement.smt_mapping_source = "smtctl-bindmap"
        elif smt_width is None:
            placement.smt_position = None
            placement.physical_core_id = None
            placement.smt_class_label = "unknown"
            placement.smt_mapping_source = "unknown"
        else:
            placement.smt_position = placement.lcpu % smt_width
            placement.physical_core_id = placement.lcpu // smt_width
            placement.smt_class_label = smt_class_label(placement.smt_position)
            placement.smt_mapping_source = "heuristic"


def parse_smtctl(text: str) -> dict[str, object]:
    enabled: bool | None = None
    capable: bool | None = None
    widths: list[int] = []
    per_proc: dict[str, int] = {}
    lcpu_to_proc: dict[int, str] = {}
    proc_threads: dict[str, list[int]] = defaultdict(list)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()

        if re.search(r"\bnot\s+smt\s+capable\b|\bsmt\s+capable\s*:\s*no\b", lower):
            capable = False
        elif re.search(r"\bsmt\s+capable\b", lower):
            capable = True

        if "boot mode" not in lower:
            if re.search(r"\bsmt\s+is\s+currently\s+(disabled|off)\b|\bsmt\s+mode\s*:\s*(disabled|off)\b", lower):
                enabled = False
            elif re.search(r"\bsmt\s+is\s+currently\s+(enabled|on)\b|\bsmt\s+mode\s*:\s*(enabled|on)\b", lower):
                enabled = True

        bind_match = re.search(r"\bBind\s+processor\s+(\d+)\s+is\s+bound\s+with\s+(proc\d+)\b", line, re.IGNORECASE)
        if bind_match:
            lcpu = int(bind_match.group(1))
            proc = bind_match.group(2).lower()
            lcpu_to_proc[lcpu] = proc
            proc_threads[proc].append(lcpu)

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

    sorted_proc_threads = {proc: sorted(set(lcpus)) for proc, lcpus in proc_threads.items()}
    sorted_procs = sorted(
        sorted_proc_threads,
        key=lambda proc: (min(sorted_proc_threads[proc]), int(proc[4:]) if proc[4:].isdigit() else proc),
    )
    proc_to_core = {proc: core_id for core_id, proc in enumerate(sorted_procs)}
    lcpu_to_core: dict[int, int] = {}
    lcpu_to_position: dict[int, int] = {}
    for proc, threads in sorted_proc_threads.items():
        for position, lcpu in enumerate(threads):
            lcpu_to_core[lcpu] = proc_to_core[proc]
            lcpu_to_position[lcpu] = position

    mixed = len(set(per_proc.values())) > 1 if per_proc else len(set(widths)) > 1
    return {
        "smt_width": smt_width,
        "smt_enabled": enabled,
        "smt_capable": capable,
        "smt_width_per_proc": per_proc,
        "smt_width_mixed": mixed,
        "raw_widths": widths,
        "lcpu_to_proc": lcpu_to_proc,
        "proc_threads": sorted_proc_threads,
        "lcpu_to_core": lcpu_to_core,
        "lcpu_to_position": lcpu_to_position,
        "has_bindmap": bool(lcpu_to_proc),
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

    has_bindmap = bool(smtctl_info and smtctl_info.get("has_bindmap"))
    bindmap_lcpus = set((smtctl_info or {}).get("lcpu_to_core", {}).keys())
    placement_lcpus = set(placements)
    any_heuristic_mapping = bool(width is not None and placement_lcpus and (not has_bindmap or not placement_lcpus <= bindmap_lcpus))
    if has_bindmap and placement_lcpus and placement_lcpus <= bindmap_lcpus:
        smt_mapping_source = "smtctl-bindmap"
    elif width is not None:
        smt_mapping_source = "heuristic"
    else:
        smt_mapping_source = "unknown"
    if any_heuristic_mapping:
        warnings.append(
            "LCPU->core mapping is heuristic and may be wrong when smtctl bind-map is unavailable or LCPU numbering is non-contiguous"
        )

    return {
        "smt_width": width,
        "smt_width_source": source,
        "smt_mapping_source": smt_mapping_source,
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


def parse_size_to_mb(token: str) -> float | None:
    cleaned = token.strip().replace(",", "")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgtp]?)(?:b)?", cleaned, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2).lower()
    multiplier = {
        "": 1.0,
        "k": 1.0 / 1024.0,
        "m": 1.0,
        "g": 1024.0,
        "t": 1024.0 * 1024.0,
        "p": 1024.0 * 1024.0 * 1024.0,
    }[unit]
    return value * multiplier


def as_float(value: object | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return parse_number(str(value))


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


def parse_tunables(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "Command not found" in line:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().split()[0] if value.strip() else ""
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            values[key.lower()] = value
    return values


def parse_lparstat(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line or line.startswith("#"):
            continue
        key, value = line.split(":", 1)
        normalized = re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")
        values[normalized] = value.strip()
    return values


def parse_vmstat_v(text: str) -> dict[str, float | int | str]:
    patterns = {
        "memory_pools": r"(\d+)\s+memory\s+pools?",
        "numperm_percent": r"([0-9.]+)\s+numperm\s+percentage",
        "minperm_percent": r"([0-9.]+)\s+minperm\s+percentage",
        "maxperm_percent": r"([0-9.]+)\s+maxperm\s+percentage",
        "client_percent": r"([0-9.]+)\s+client\s+percentage",
        "maxclient_percent": r"([0-9.]+)\s+maxclient\s+percentage",
        "compressed_percent": r"([0-9.]+)\s+compressed\s+percentage",
    }
    values: dict[str, float | int | str] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            number = parse_number(match.group(1))
            if number is not None:
                values[key] = int(number) if number.is_integer() else number
    return values


def parse_vmstat_s(text: str) -> dict[str, int]:
    patterns = {
        "free_frame_waits": r"(\d+)\s+free\s+frame\s+waits",
        "pages_paged_in": r"(\d+)\s+pages\s+paged\s+in",
        "pages_paged_out": r"(\d+)\s+pages\s+paged\s+out",
        "paging_space_page_ins": r"(\d+)\s+paging\s+space\s+page\s+ins",
        "paging_space_page_outs": r"(\d+)\s+paging\s+space\s+page\s+outs",
        "revolutions_of_clock_hand": r"(\d+)\s+revolutions\s+of\s+the\s+clock\s+hand",
        "page_steals": r"(\d+)\s+page\s+steals",
    }
    values: dict[str, int] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            values[key] = int(match.group(1))
    return values


def parse_vmstat_interval(text: str) -> dict[str, float | None]:
    header: list[str] = []
    rows: list[dict[str, float | None]] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if {"fre", "pi", "po"}.issubset(set(parts)):
            header = parts
            continue
        if not header or len(parts) != len(header):
            continue
        if not all(re.fullmatch(r"-?\d+(?:\.\d+)?", part) for part in parts):
            continue
        rows.append({key: parse_number(value) for key, value in zip(header, parts)})

    result: dict[str, float | None] = {}
    for key in ("fre", "pi", "po", "sr", "r", "b"):
        values = [row[key] for row in rows if row.get(key) is not None]
        if values:
            result[f"{key}_avg"] = mean(values)
            result[f"{key}_max"] = max(values)
    return result


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def parse_capture_number(value: str | object | None) -> float | None:
    if value is None:
        return None
    cleaned = str(value).strip().replace(",", "").replace("%", "")
    cleaned = cleaned.strip("<>")
    if cleaned in {"", "-", "n/a", "N/A"}:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def capture_status(text: str) -> dict[str, object]:
    stripped = text.strip()
    lower = stripped.lower()
    command_not_found = "command not found" in lower
    terminal_error = bool(re.search(r"\bterminal\s+\S+\s+is\s+unknown\b", lower))
    command_failed = (
        "command failed" in lower
        or terminal_error
        or ("usage:" in lower and ("topas" in lower or "nmon" in lower))
    )
    return {
        "raw_available": bool(stripped) and not command_not_found and not command_failed,
        "command_not_found": command_not_found,
        "command_failed": command_failed,
        "terminal_error": terminal_error,
    }


def summarize_numeric_rows(rows: list[dict[str, float | None]]) -> dict[str, dict[str, float | int | None]]:
    summaries: dict[str, dict[str, float | int | None]] = {}
    keys = sorted({key for row in rows for key in row})
    for key in keys:
        values = [row.get(key) for row in rows if row.get(key) is not None]
        numeric_values = [float(value) for value in values if value is not None]
        if not numeric_values:
            continue
        summaries[key] = {
            "samples": len(numeric_values),
            "avg": mean(numeric_values),
            "min": min(numeric_values),
            "max": max(numeric_values),
            "last": numeric_values[-1],
        }
    return summaries


def metric_stat(
    summary: dict[str, dict[str, float | int | None]], key_candidates: Iterable[str], stat: str
) -> float | None:
    for key in key_candidates:
        value = summary.get(key, {}).get(stat)
        number = as_float(value)
        if number is not None:
            return number
    return None


def parse_nmon_summary(text: str) -> dict[str, object]:
    status = capture_status(text)
    headers: dict[str, list[str]] = {}
    section_rows: dict[str, list[dict[str, float | None]]] = defaultdict(list)
    timestamps: list[str] = []
    top_processes: dict[tuple[str, str], dict[str, object]] = {}

    for row in csv.reader(text.splitlines()):
        if not row:
            continue
        section = row[0].strip()
        if not section or section.startswith("#"):
            continue
        if section == "ZZZZ" and len(row) >= 2:
            timestamps.append(row[1].strip())
            continue
        if len(row) < 2:
            continue

        marker = row[1].strip()
        if re.fullmatch(r"T\d+", marker) and section in headers:
            header = headers[section]
            values = row[2:]
            numeric_row = {
                header[index]: parse_capture_number(values[index])
                for index in range(min(len(header), len(values)))
            }
            section_rows[section].append(numeric_row)

            if section.upper().startswith("TOP"):
                raw_values = {
                    header[index]: values[index].strip()
                    for index in range(min(len(header), len(values)))
                }
                pid = next(
                    (raw_values.get(key, "") for key in ("pid", "process_id", "p_id") if raw_values.get(key, "")),
                    "",
                )
                command = next(
                    (
                        raw_values.get(key, "")
                        for key in ("command", "command_name", "name", "process", "program")
                        if raw_values.get(key, "")
                    ),
                    "",
                )
                cpu = metric_stat({key: {"last": value} for key, value in numeric_row.items()}, ("cpu", "cpu_", "cpu_percent"), "last")
                if not pid and raw_values:
                    first_value = next(iter(raw_values.values()))
                    if re.fullmatch(r"\d+", first_value):
                        pid = first_value
                if pid or command:
                    key = (pid, command)
                    proc = top_processes.setdefault(
                        key,
                        {"pid": pid, "command": command, "samples": 0, "cpu_avg": None, "cpu_max": None},
                    )
                    proc["samples"] = int(proc["samples"]) + 1
                    if cpu is not None:
                        current_total = float(proc.get("_cpu_total", 0.0)) + cpu
                        proc["_cpu_total"] = current_total
                        proc["cpu_avg"] = current_total / int(proc["samples"])
                        proc["cpu_max"] = max(as_float(proc.get("cpu_max")) or 0.0, cpu)
            continue

        if len(row) >= 3 and not re.fullmatch(r"T\d+", marker):
            marker_key = normalize_key(marker)
            header_values = row[1:] if section.upper().startswith("TOP") and "pid" in marker_key else row[2:]
            header = [normalize_key(value) for value in header_values]
            if header:
                headers[section] = header

    cpu_all = summarize_numeric_rows(section_rows.get("CPU_ALL", []))
    memory = summarize_numeric_rows(section_rows.get("MEM", []))
    paging = summarize_numeric_rows(section_rows.get("PAGE", []) + section_rows.get("PAGING", []))
    processes = summarize_numeric_rows(section_rows.get("PROC", []))
    top_rows = []
    for proc in top_processes.values():
        proc.pop("_cpu_total", None)
        top_rows.append(proc)

    return {
        **status,
        "sample_count": len(timestamps) or max((len(rows) for rows in section_rows.values()), default=0),
        "sections": sorted(section_rows.keys()),
        "cpu_all": cpu_all,
        "memory": memory,
        "paging": paging,
        "processes": processes,
        "top_processes": sorted(top_rows, key=lambda row: as_float(row.get("cpu_max")) or 0.0, reverse=True)[:20],
    }


def parse_topas_summary(text: str) -> dict[str, object]:
    status = capture_status(text)
    cpu_rows: list[dict[str, float | None]] = []
    process_rows: dict[tuple[str, str], dict[str, object]] = {}
    cpu_header: list[str] = []
    process_header: list[str] = []
    sample_count = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        parts = line.split()
        if "topas" in lower and ("monitor" in lower or "interval" in lower):
            sample_count += 1

        normalized_parts = [normalize_key(part) for part in parts]
        if {"user", "idle"}.issubset(set(normalized_parts)) or {"user", "user_"}.intersection(normalized_parts) and "idle" in normalized_parts:
            cpu_header = normalized_parts[1:] if normalized_parts and normalized_parts[0] in {"cpu", "processor"} else normalized_parts
            process_header = []
            continue
        if len(parts) >= 3 and "pid" in normalized_parts and any(token.startswith("cpu") for token in normalized_parts):
            process_header = normalized_parts
            cpu_header = []
            continue

        if cpu_header and parts and (parts[0].upper() == "ALL" or parts[0].isdigit()):
            values = parts[1:] if len(parts) == len(cpu_header) + 1 else parts
            cpu_rows.append(
                {
                    cpu_header[index]: parse_capture_number(values[index])
                    for index in range(min(len(cpu_header), len(values)))
                }
            )
            continue

        if process_header and len(parts) >= len(process_header):
            pid_index = process_header.index("pid") if "pid" in process_header else None
            cpu_index = next((index for index, token in enumerate(process_header) if token.startswith("cpu")), None)
            name_index = next((index for index, token in enumerate(process_header) if token in {"name", "command"}), 0)
            if pid_index is None or cpu_index is None or pid_index >= len(parts) or cpu_index >= len(parts):
                continue
            pid = parts[pid_index]
            cpu = parse_capture_number(parts[cpu_index])
            if not re.fullmatch(r"\d+", pid) or cpu is None:
                continue
            name = parts[name_index] if name_index < len(parts) else ""
            key = (pid, name)
            proc = process_rows.setdefault(
                key,
                {"pid": pid, "name": name, "samples": 0, "cpu_avg": None, "cpu_max": None},
            )
            proc["samples"] = int(proc["samples"]) + 1
            total = float(proc.get("_cpu_total", 0.0)) + cpu
            proc["_cpu_total"] = total
            proc["cpu_avg"] = total / int(proc["samples"])
            proc["cpu_max"] = max(as_float(proc.get("cpu_max")) or 0.0, cpu)

    top_rows = []
    for proc in process_rows.values():
        proc.pop("_cpu_total", None)
        top_rows.append(proc)

    return {
        **status,
        "sample_count": sample_count or len(cpu_rows),
        "cpu": summarize_numeric_rows(cpu_rows),
        "top_processes": sorted(top_rows, key=lambda row: as_float(row.get("cpu_max")) or 0.0, reverse=True)[:20],
    }


def parse_oratop_summary(text: str) -> dict[str, object]:
    summary: dict[str, object] = {}
    for line in text.splitlines():
        if "Oracle " in line and " sga" in line.lower():
            sga_match = re.search(r"\b([0-9.]+[KMGTPE]?)(?:B)?\s+sga\b", line, re.IGNORECASE)
            if sga_match:
                summary["sga_mb"] = parse_size_to_mb(sga_match.group(1))
                summary["sga_text"] = sga_match.group(1)
            db_match = re.search(r"\b([0-9.]+[KMGTPE]?)(?:B)?\s+sz\b", line, re.IGNORECASE)
            if db_match:
                summary["database_size_mb"] = parse_size_to_mb(db_match.group(1))
                summary["database_size_text"] = db_match.group(1)
            dbt_match = re.search(r"\b([0-9.]+)%db\b", line, re.IGNORECASE)
            if dbt_match:
                summary["db_time_percent"] = parse_number(dbt_match.group(1))
            summary["database_header"] = line.strip()
            continue
        if re.match(r"^\s*\d+\s+\d+\s+", line):
            parts = line.split()
            # oratop database summary row: ID CPU %CPU LOAD AAS ...
            if len(parts) > 18:
                summary.update(
                    {
                        "logical_cpu_count": parse_number(parts[1]),
                        "summary_cpu_percent": parse_number(parts[2]),
                        "load": parse_number(parts[3]),
                        "aas": parse_number(parts[4]),
                        "pga_text": parts[18],
                        "pga_mb": parse_size_to_mb(parts[18]),
                    }
                )
                break
    return summary


def parse_oracle_params(text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.lower().startswith(("name", "---")):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        else:
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            key = parts[0]
            value = parts[-1]
        key = key.strip().lower()
        if re.fullmatch(r"[a-z][a-z0-9_$#]*", key):
            params[key] = value.strip()
    return params


def parse_svmon_summary(text: str) -> dict[str, object]:
    sizes = Counter()
    for match in re.finditer(r"\b(4K|64K|16M|16G)\b", text, re.IGNORECASE):
        sizes[match.group(1).upper()] += 1
    return {
        "page_size_mentions": counter_to_dict(sizes),
        "mpss_visible": "mpss" in text.lower(),
        "large_page_visible": bool(re.search(r"\b16M\b|\b16G\b|\bL\b", text, re.IGNORECASE)),
        "raw_available": bool(text.strip()) and "PMON PID was not provided" not in text,
    }


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
                "s4rd": stats["s4rd"],
                "s5rd": stats["s5rd"],
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
        mapping_sources = sorted({placement.smt_mapping_source for placement in core_placements})
        for placement in core_placements:
            lcpus_by_class[placement.smt_class_label] = placement.lcpu
            samples_by_class[placement.smt_class_label] = trace_counts.get(placement.lcpu, 0)
        lcpus = [placement.lcpu for placement in core_placements]
        stats = summarize_mpstat_rows(lcpus, mpstat)
        rows.append(
            {
                "physical_core_id": core_id,
                "smt_mapping_source": ",".join(mapping_sources),
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


def memory_topology_summary(
    placements: dict[int, CpuPlacement],
    smt_width: int | None,
) -> dict[str, object]:
    grouped: dict[tuple[int | None, int], dict[str, object]] = {}
    for placement in placements.values():
        key = (placement.ref, placement.srad)
        row = grouped.setdefault(
            key,
            {
                "ref": placement.ref,
                "srad": placement.srad,
                "memory_mb": placement.srad_memory_mb,
                "lcpus": set(),
                "ranges": set(),
                "physical_cores": set(),
            },
        )
        row["lcpus"].add(placement.lcpu)
        row["ranges"].add(placement.lssrad_cpu_range)
        if placement.physical_core_id is not None:
            row["physical_cores"].add(placement.physical_core_id)

    rows = []
    for row in grouped.values():
        lcpus = sorted(row["lcpus"])
        cores = sorted(row["physical_cores"])
        memory_mb = as_float(row["memory_mb"])
        rows.append(
            {
                "ref": row["ref"],
                "srad": row["srad"],
                "memory_mb": memory_mb,
                "memory_gb": (memory_mb / 1024.0) if memory_mb is not None else None,
                "lcpu_count": len(lcpus),
                "physical_core_count": len(cores) if cores else (len(lcpus) / smt_width if smt_width else None),
                "memory_mb_per_lcpu": (memory_mb / len(lcpus)) if memory_mb is not None and lcpus else None,
                "memory_mb_per_physical_core": (
                    memory_mb / len(cores)
                    if memory_mb is not None and cores
                    else (memory_mb / (len(lcpus) / smt_width) if memory_mb is not None and smt_width and lcpus else None)
                ),
                "lcpus": lcpus,
                "ranges": sorted(row["ranges"]),
            }
        )

    memory_values = [float(row["memory_mb"]) for row in rows if row.get("memory_mb") is not None]
    ratio = (max(memory_values) / min(memory_values)) if memory_values and min(memory_values) > 0 else None
    level = "ok"
    title = "SRAD memory appears balanced"
    interpretation = "lssrad reports memory attached to each SRAD. Balance is evaluated across SRAD memory sizes."
    if not memory_values:
        level = "info"
        title = "SRAD memory was not available"
        interpretation = "The lssrad parser did not find memory values, so only CPU topology can be interpreted."
    elif ratio is not None and ratio >= 1.25:
        level = "warning"
        title = "SRAD memory allocation is uneven"
        interpretation = (
            f"Maximum SRAD memory is {ratio:.2f}x the minimum. Oracle SGA is typically striped across available LPAR memory; "
            "uneven CPU/memory topology can amplify local/near/far memory effects."
        )

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "imbalance_ratio": ratio,
        "rows": sorted(rows, key=lambda row: (row["ref"] if row["ref"] is not None else -1, row["srad"])),
    }


def diagnose_affinity(
    stats: dict[str, dict[str, float | int | None]],
    smt_stats: list[dict[str, object]],
    remote_rd_threshold: float,
    local_hrd_threshold: float,
) -> dict[str, object]:
    range_rows = []
    for label, values in stats.items():
        s3rd = as_float(values.get("s3rd"))
        s4rd = as_float(values.get("s4rd"))
        s5rd = as_float(values.get("s5rd"))
        s3hrd = as_float(values.get("s3hrd"))
        s4hrd = as_float(values.get("s4hrd"))
        s5hrd = as_float(values.get("s5hrd"))
        remote_redispatch = none_sum((s4rd, s5rd))
        non_local_memory = none_sum((s4hrd, s5hrd))
        if non_local_memory is None and s3hrd is not None:
            non_local_memory = max(0.0, 100.0 - s3hrd)
        score = 100.0
        if remote_redispatch is not None:
            score -= min(40.0, remote_redispatch * 2.0)
        if s3hrd is not None:
            score -= max(0.0, local_hrd_threshold - s3hrd)
        elif non_local_memory is not None:
            score -= min(30.0, non_local_memory)
        range_rows.append(
            {
                "lssrad_range_label": label,
                "s3rd": s3rd,
                "s4rd": s4rd,
                "s5rd": s5rd,
                "s3hrd": s3hrd,
                "s4hrd": s4hrd,
                "s5hrd": s5hrd,
                "remote_redispatch": remote_redispatch,
                "non_local_memory": non_local_memory,
                "s0rd": as_float(values.get("s0rd")),
                "s1rd": as_float(values.get("s1rd")),
                "nsp": as_float(values.get("nsp")),
                "affinity_score": max(0.0, min(100.0, score)),
            }
        )

    elevated = [
        row
        for row in range_rows
        if (row["remote_redispatch"] is not None and row["remote_redispatch"] >= remote_rd_threshold)
        or (row["s3hrd"] is not None and row["s3hrd"] < local_hrd_threshold)
        or (row["s5hrd"] is not None and row["s5hrd"] >= max(0.0, 100.0 - local_hrd_threshold))
    ]
    level = "ok" if not elevated else "warning"
    title = "CPU/memory affinity looks acceptable" if not elevated else "Remote redispatch or non-local memory is visible"
    interpretation = (
        "mpstat -d S3rd is same-chip redispatch and is not penalized. Scores use S4rd+S5rd for remote redispatch "
        "and S3hrd/S4hrd/S5hrd for local/near/far home-SRAD dispatch."
    )
    if elevated:
        worst = sorted(elevated, key=lambda row: (row["affinity_score"], -(row["remote_redispatch"] or 0.0)))[0]
        interpretation = (
            f"{worst['lssrad_range_label']} has the weakest affinity score ({worst['affinity_score']:.1f}). "
            "Review S4rd+S5rd for remote redispatch and S3hrd/S4hrd/S5hrd for local/near/far home-SRAD dispatch."
        )

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "range_rows": sorted(range_rows, key=lambda row: row["affinity_score"]),
        "smt_rows": smt_stats,
    }


def diagnose_memory_pressure(
    vmstat_v: dict[str, float | int | str],
    vmstat_s: dict[str, int],
    vmstat_interval: dict[str, float | None],
    vmo: dict[str, str],
    placements: dict[int, CpuPlacement],
) -> dict[str, object]:
    free_frame_waits = vmstat_s.get("free_frame_waits", 0)
    paging_outs = vmstat_s.get("paging_space_page_outs", 0) or vmstat_s.get("pages_paged_out", 0)
    pi_avg = as_float(vmstat_interval.get("pi_avg"))
    po_avg = as_float(vmstat_interval.get("po_avg"))
    fre_avg = as_float(vmstat_interval.get("fre_avg"))
    pools = as_float(vmstat_v.get("memory_pools"))
    minfree = as_float(vmo.get("minfree"))
    maxfree = as_float(vmo.get("maxfree"))
    maxpgahead = as_float(vmo.get("maxpgahead"))
    j2_read_ahead = as_float(vmo.get("j2_maxpagereadahead") or vmo.get("j2_maxPageReadAhead"))
    lcpu = len(placements)

    expected_minfree = None
    expected_maxfree = None
    if pools and pools > 0:
        expected_minfree = max(960.0, 120.0 * lcpu) / pools
        read_ahead = max(value for value in (maxpgahead or 0.0, j2_read_ahead or 0.0, 0.0))
        expected_maxfree = expected_minfree + (read_ahead * lcpu) / pools if read_ahead else None

    evidence = []
    if vmstat_s:
        evidence.append(f"vmstat -s: free frame waits={free_frame_waits}, paging-space/page outs={paging_outs}.")
    if vmstat_interval:
        evidence.append(
            f"vmstat interval averages: fre={fmt(fre_avg)}, pi={fmt(pi_avg)}, po={fmt(po_avg)}."
        )
    if pools:
        evidence.append(f"vmstat -v reports {fmt(pools, 0)} memory pools.")
    if minfree is not None or maxfree is not None:
        evidence.append(f"vmo minfree={fmt(minfree, 0)}, maxfree={fmt(maxfree, 0)}.")
    if expected_minfree is not None:
        evidence.append(
            f"Oracle starting-point heuristic from the IBM deck: minfree about {expected_minfree:.0f}"
            + (f", maxfree about {expected_maxfree:.0f}." if expected_maxfree is not None else ".")
        )

    level = "ok"
    title = "No AIX memory pressure signal in supplied optional files"
    interpretation = "The supplied vmstat/vmo files do not show paging-space pressure or free-frame waits."
    if not vmstat_s and not vmstat_interval and not vmstat_v and not vmo:
        level = "info"
        title = "Memory pressure context was not supplied"
        interpretation = "Provide vmstat -v, vmstat -s, vmstat interval, and vmo output to assess VMM/lrud pressure."
    elif free_frame_waits > 0 or paging_outs > 0 or (po_avg is not None and po_avg > 0):
        level = "critical"
        title = "AIX memory pressure or paging is visible"
        interpretation = (
            "Oracle database LPARs should treat paging-space activity as a problem signal. "
            "Check SGA/PGA sizing, pinned memory, and free page thresholds before accepting sustained paging."
        )
    elif minfree is not None and expected_minfree is not None and minfree < expected_minfree * 0.75:
        level = "warning"
        title = "minfree is below the Oracle-oriented starting point"
        interpretation = "The configured minfree is materially below the slide-deck heuristic for this LCPU/pool count."

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "evidence": evidence,
        "vmstat_v": vmstat_v,
        "vmstat_s": vmstat_s,
        "vmstat_interval": vmstat_interval,
        "vmo_subset": {key: vmo.get(key) for key in ("minfree", "maxfree", "maxpgahead", "lgpg_regions", "lgpg_size", "v_pinshm", "vmm_klock_mode")},
        "expected_minfree": expected_minfree,
        "expected_maxfree": expected_maxfree,
    }


def diagnose_oracle_memory_pages(
    oratop_summary: dict[str, object],
    oracle_params: dict[str, str],
    vmo: dict[str, str],
    asoo: dict[str, str],
    aso_status_text: str,
    svmon: dict[str, object],
) -> dict[str, object]:
    sga_mb = as_float(oratop_summary.get("sga_mb"))
    lgpg_regions = as_float(vmo.get("lgpg_regions"))
    lgpg_size = as_float(vmo.get("lgpg_size"))
    v_pinshm = vmo.get("v_pinshm")
    klock = vmo.get("vmm_klock_mode")
    aso_active = asoo.get("aso_active")
    large_page_utilization = asoo.get("large_page_utilization")
    base_large_pages = int((sga_mb - 1) // 16) + 1 if sga_mb and sga_mb > 0 else None
    lock_sga_large_pages = base_large_pages + 3 if base_large_pages is not None else None
    needed_large_pages = lock_sga_large_pages
    lock_sga = oracle_params.get("lock_sga")
    sga_max_size = oracle_params.get("sga_max_size")
    sga_target = oracle_params.get("sga_target")
    memory_target = oracle_params.get("memory_target")
    memory_max_target = oracle_params.get("memory_max_target")

    evidence = []
    if sga_mb is not None:
        evidence.append(f"oratop reports SGA={fmt(sga_mb / 1024.0)} GB.")
    if lgpg_regions is not None or lgpg_size is not None:
        evidence.append(f"vmo lgpg_regions={fmt(lgpg_regions, 0)}, lgpg_size={fmt(lgpg_size, 0)}.")
    if needed_large_pages is not None:
        evidence.append(
            "16MB large-page sizing: "
            f"base INT[(SGA-1)/16MB]+1 = {base_large_pages} regions; "
            f"LOCK_SGA recommendation adds 3 = {lock_sga_large_pages} regions."
        )
    if v_pinshm is not None:
        evidence.append(f"vmo v_pinshm={v_pinshm}.")
    if klock is not None:
        evidence.append(f"vmo vmm_klock_mode={klock}.")
    if aso_active is not None or large_page_utilization is not None:
        evidence.append(f"asoo aso_active={aso_active or 'n/a'}, large_page_utilization={large_page_utilization or 'n/a'}.")
    if svmon.get("raw_available"):
        evidence.append(f"svmon page-size mentions: {svmon.get('page_size_mentions', {})}.")
    if aso_status_text.strip():
        evidence.append("aso subsystem status was supplied.")
    if oracle_params:
        evidence.append(
            "Oracle params: "
            + ", ".join(
                f"{key}={value}"
                for key, value in (
                    ("lock_sga", lock_sga),
                    ("sga_max_size", sga_max_size),
                    ("sga_target", sga_target),
                    ("memory_target", memory_target),
                    ("memory_max_target", memory_max_target),
                )
                if value is not None
            )
        )

    level = "info"
    title = "Oracle SGA page-size context is partial"
    interpretation = "Provide vmo/asoo/svmon and Oracle parameter output for a complete large-page interpretation."
    page_context_supplied = bool(vmo or asoo or oracle_params or svmon.get("raw_available"))
    if (
        page_context_supplied
        and sga_mb is not None
        and sga_mb >= 100 * 1024
        and not svmon.get("large_page_visible")
        and not lgpg_regions
    ):
        level = "warning"
        title = "Large SGA without visible 16MB page evidence"
        interpretation = (
            "The IBM guidance recommends evaluating 16MB pages for SGA larger than about 100GB. "
            "No 16MB large-page evidence was visible in the supplied optional files."
        )
    elif lgpg_regions and needed_large_pages and lgpg_regions < needed_large_pages:
        level = "warning"
        title = "Configured large-page regions appear below SGA sizing rule"
        interpretation = "Configured lgpg_regions is lower than the 16MB-page rule of thumb for the reported SGA."
    elif svmon.get("large_page_visible") or lgpg_regions:
        level = "ok"
        title = "Large-page/SGA evidence is present"
        interpretation = "The optional files contain 16MB/large-page evidence; verify it maps to the Oracle SGA segments."

    if lock_sga and lock_sga.lower() == "true" and sga_max_size and not lgpg_regions and not svmon.get("large_page_visible"):
        level = "warning"
        title = "LOCK_SGA is true without visible large-page evidence"
        interpretation = (
            "LOCK_SGA=true pre-allocates/pins SGA memory. The IBM guidance strongly prefers explicit page-size planning, "
            "especially for large SGAs."
        )
    amm_values = [value for value in (memory_target, memory_max_target) if value is not None]
    if any(value not in {"0", "0.0"} for value in amm_values):
        evidence.append("AMM is configured; size 16MB large pages against MEMORY_MAX_TARGET rather than only SGA.")

    kernel_level = "ok"
    if klock is not None and str(klock) != "2" and (lgpg_regions or svmon.get("large_page_visible")):
        kernel_level = "warning"
        evidence.append("Pinned or large SGA evidence exists while vmm_klock_mode is not 2.")

    dso_level = "info"
    if aso_active == "1":
        dso_level = "ok"
    elif aso_active is not None:
        dso_level = "warning"
        evidence.append("DSO/ASO is not active; MPSS conversion benefits may be unavailable.")

    return {
        "level": "warning" if kernel_level == "warning" or dso_level == "warning" else level,
        "title": title,
        "interpretation": interpretation,
        "kernel_pinning_level": kernel_level,
        "dso_level": dso_level,
        "evidence": evidence,
        "oratop_summary": oratop_summary,
        "oracle_params": oracle_params,
        "needed_16mb_large_pages": needed_large_pages,
        "base_16mb_large_pages": base_large_pages,
        "lock_sga_16mb_large_pages": lock_sga_large_pages,
        "vmo_subset": {
            "lgpg_regions": vmo.get("lgpg_regions"),
            "lgpg_size": vmo.get("lgpg_size"),
            "v_pinshm": v_pinshm,
            "vmm_klock_mode": klock,
        },
        "asoo_subset": {
            "aso_active": aso_active,
            "large_page_utilization": large_page_utilization,
        },
        "svmon": svmon,
    }


def diagnose_lpar_sizing(
    mp_config: dict[str, str],
    lparstat: dict[str, str],
    smt_width: int | None,
    placements: dict[int, CpuPlacement],
) -> dict[str, object]:
    entitlement = as_float(mp_config.get("ent")) or as_float(lparstat.get("entitled_capacity"))
    lcpu = as_float(mp_config.get("lcpu")) or float(len(placements) or 0)
    virtual_processors = as_float(lparstat.get("online_virtual_cpus")) or as_float(lparstat.get("maximum_virtual_cpus"))
    if virtual_processors is None and smt_width:
        virtual_processors = lcpu / smt_width
    ratio = (virtual_processors / entitlement) if virtual_processors and entitlement else None

    evidence = [
        f"lcpu={fmt(lcpu, 0)}, smt_width={fmt(smt_width, 0)}, entitlement={fmt(entitlement)}, virtual_processors={fmt(virtual_processors)}."
    ]
    mode = mp_config.get("mode") or lparstat.get("type")
    if mode:
        evidence.append(f"LPAR mode/type={mode}.")

    level = "ok"
    title = "LPAR VP entitlement ratio is within the common Oracle guideline"
    interpretation = "The IBM guidance suggests keeping configured virtual processors close to entitlement, commonly not above about 1.5x-2x."
    if ratio is None:
        level = "info"
        title = "LPAR sizing context is partial"
        interpretation = "Provide lparstat -i or reliable mpstat configuration to evaluate VP/entitlement ratio."
    elif ratio > 2.0:
        level = "warning"
        title = "Virtual processors are high relative to entitlement"
        interpretation = f"VP/entitlement ratio is {ratio:.2f}; this is above the 2x upper guideline and can make folding/dispatch behavior harder to reason about."
    elif ratio > 1.5:
        level = "info"
        title = "Virtual processors are above 1.5x entitlement"
        interpretation = f"VP/entitlement ratio is {ratio:.2f}; this may be acceptable, but it deserves review for Oracle CPU placement."

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "evidence": evidence,
        "vp_to_entitlement_ratio": ratio,
        "lparstat": lparstat,
    }


def diagnose_extended_vpm(
    base_diagnosis: dict[str, object],
    schedo: dict[str, str],
    mpstat_v_text: str,
    lpar_sizing: dict[str, object],
) -> dict[str, object]:
    evidence = list(base_diagnosis.get("evidence", []))
    for key in ("vpm_xvcpus", "vpm_fold_policy", "vpm_throughput_mode", "vpm_throughput_core_threshold"):
        if key in schedo:
            evidence.append(f"schedo {key}={schedo[key]}.")
    if mpstat_v_text.strip():
        evidence.append("mpstat -v was supplied for virtual processor dispatch/activity review.")

    level = str(base_diagnosis.get("level", "info"))
    title = str(base_diagnosis.get("title", "Extended VP folding context"))
    interpretation = str(base_diagnosis.get("interpretation", ""))
    vpm_xvcpus = schedo.get("vpm_xvcpus")
    core_threshold = schedo.get("vpm_throughput_core_threshold")

    if vpm_xvcpus == "-1":
        level = "warning"
        title = "VP folding appears disabled"
        interpretation = "vpm_xvcpus=-1 disables folding. The IBM guidance prefers folding active for Oracle DB LPARs except during controlled tests."
    elif vpm_xvcpus is not None and as_float(vpm_xvcpus) is not None and as_float(vpm_xvcpus) < 2:
        level = "info"
        title = "vpm_xvcpus is below the common Oracle/RAC floor"
        interpretation = "For RAC, the IBM guidance calls out vpm_xvcpus=2 as a minimum. For non-RAC, keep this as context rather than a hard finding."
    elif core_threshold == "0":
        title = "vpm_throughput_core_threshold=0 is configured"
        interpretation = (
            "This special case can speed unfolding up to the configured raw-throughput threshold. "
            "Review alongside shared-pool competition and entitlement."
        )

    ratio = as_float(lpar_sizing.get("vp_to_entitlement_ratio"))
    if ratio is not None and ratio > 2.0:
        evidence.append("VP/entitlement ratio is above 2x, which can interact with folding decisions.")

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "recommended_value": base_diagnosis.get("recommended_value"),
        "commands": base_diagnosis.get("commands", {}),
        "evidence": evidence,
        "schedo_subset": {key: schedo.get(key) for key in ("vpm_xvcpus", "vpm_fold_policy", "vpm_throughput_mode", "vpm_throughput_core_threshold")},
    }


def diagnose_thread_constraints(
    trace_by_pid: dict[int, TraceThread],
    processes: dict[int, OracleProcess],
    placements: dict[int, CpuPlacement],
    smt_width: int | None,
) -> dict[str, object]:
    rows = []
    for pid, trace in trace_by_pid.items():
        if trace.samples < 10 or not trace.cpus:
            continue
        top_cpu, top_cpu_samples = trace.cpus.most_common(1)[0]
        top_lcpu_percent = top_cpu_samples / trace.samples * 100.0
        core_counts: Counter[int] = Counter()
        for cpu, samples in trace.cpus.items():
            placement = placements.get(cpu)
            if placement and placement.physical_core_id is not None:
                core_counts[placement.physical_core_id] += samples
        top_core_percent = 0.0
        top_core = None
        if core_counts:
            top_core, top_core_samples = core_counts.most_common(1)[0]
            top_core_percent = top_core_samples / trace.samples * 100.0
        if top_lcpu_percent >= 80.0 or top_core_percent >= 90.0:
            proc = processes.get(pid, OracleProcess(pid=pid))
            rows.append(
                {
                    "pid": pid,
                    "name": proc.name or trace.name,
                    "sql_id": proc.sql_id,
                    "samples": trace.samples,
                    "top_lcpu": top_cpu,
                    "top_lcpu_percent": top_lcpu_percent,
                    "top_physical_core": top_core,
                    "top_physical_core_percent": top_core_percent,
                    "oratop_cpu": proc.oratop_cpu,
                    "wait_class": proc.wait_class,
                    "event": proc.event,
                }
            )

    level = "ok"
    title = "No strong single-thread concentration detected"
    interpretation = (
        "Oracle trace samples are not dominated by a single LCPU/core for the sampled processes. "
        "This does not rule out SQL-level serialization, but no obvious thread-constraint signature was found."
    )
    if rows:
        level = "info"
        title = "Possible process/thread constraint candidates"
        interpretation = (
            "Some Oracle processes have trace samples concentrated on one LCPU or one physical core. "
            "On SMT systems, a process can be thread-constrained even when tool-reported CPU is well below 100%."
        )
    if smt_width and smt_width >= 4 and len(rows) >= 5:
        level = "warning"

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "rows": sorted(rows, key=lambda row: (row["top_lcpu_percent"], row["samples"]), reverse=True)[:50],
    }


def diagnose_batch_captures(
    topas: dict[str, object],
    nmon: dict[str, object],
    stats: dict[str, dict[str, float | int | None]],
    rq_threshold: float,
) -> dict[str, object]:
    topas_available = bool(topas.get("raw_available"))
    nmon_available = bool(nmon.get("raw_available"))
    total_rq = sum_stat(stats, "rq")
    total_bound = sum_stat(stats, "bound")

    topas_cpu = topas.get("cpu", {}) if isinstance(topas.get("cpu"), dict) else {}
    nmon_cpu = nmon.get("cpu_all", {}) if isinstance(nmon.get("cpu_all"), dict) else {}
    topas_idle_avg = metric_stat(topas_cpu, ("idle", "idle_"), "avg")
    topas_wait_avg = metric_stat(topas_cpu, ("wait", "wait_"), "avg")
    nmon_idle_avg = metric_stat(nmon_cpu, ("idle", "idle_"), "avg")
    nmon_wait_avg = metric_stat(nmon_cpu, ("wait", "wait_", "iowait"), "avg")
    nmon_user_avg = metric_stat(nmon_cpu, ("user", "user_"), "avg")
    nmon_sys_avg = metric_stat(nmon_cpu, ("sys", "system", "kern", "kernel"), "avg")

    topas_busy_avg = 100.0 - topas_idle_avg if topas_idle_avg is not None else None
    nmon_busy_avg = 100.0 - nmon_idle_avg if nmon_idle_avg is not None else none_sum((nmon_user_avg, nmon_sys_avg))

    rows = [
        {
            "source": "topas",
            "available": topas_available,
            "samples": topas.get("sample_count", 0),
            "cpu_busy_avg": topas_busy_avg,
            "cpu_wait_avg": topas_wait_avg,
            "top_processes": topas.get("top_processes", []),
        },
        {
            "source": "nmon",
            "available": nmon_available,
            "samples": nmon.get("sample_count", 0),
            "cpu_busy_avg": nmon_busy_avg,
            "cpu_wait_avg": nmon_wait_avg,
            "top_processes": nmon.get("top_processes", []),
        },
    ]

    evidence = [
        f"mpstat total rq={total_rq:.1f}, total bound={total_bound:.1f}; threshold={rq_threshold:.1f}."
    ]
    if topas_available:
        evidence.append(
            f"topas samples={topas.get('sample_count', 0)}, CPU busy avg={fmt(topas_busy_avg)}%, wait avg={fmt(topas_wait_avg)}%."
        )
    elif topas.get("command_not_found"):
        evidence.append("topas was not found during collection.")
    elif topas.get("command_failed"):
        evidence.append("topas collection failed or produced only an error/usage message.")
    if nmon_available:
        evidence.append(
            f"nmon samples={nmon.get('sample_count', 0)}, CPU busy avg={fmt(nmon_busy_avg)}%, wait avg={fmt(nmon_wait_avg)}%."
        )
    elif nmon.get("command_not_found"):
        evidence.append("nmon was not found during collection.")
    elif nmon.get("command_failed"):
        evidence.append("nmon collection failed or produced only an error/usage message.")

    level = "ok"
    title = "topas/nmon batch captures do not add a stronger pressure signal"
    interpretation = (
        "Batch topas/nmon data is available as supporting context. The primary LCPU placement diagnosis still comes from mpstat, trace, and oratop."
    )
    if not topas_available and not nmon_available:
        level = "info"
        title = "topas/nmon batch context was not supplied"
        interpretation = "Provide --topas and/or --nmon output to add a batch-monitor cross-check to the report."
    elif total_rq >= rq_threshold or total_bound >= rq_threshold:
        level = "warning"
        title = "Batch monitors should be reviewed alongside mpstat CPU pressure"
        interpretation = (
            "mpstat already shows CPU queueing pressure. Use topas/nmon to sanity-check whole-system busy/wait levels and top process mix for the same window."
        )
    elif any((as_float(row.get("cpu_busy_avg")) or 0.0) >= 85.0 for row in rows if row.get("available")):
        level = "warning"
        title = "Batch monitors show high average CPU busy"
        interpretation = "topas or nmon reports high average CPU busy even though the mpstat run-queue threshold was not crossed."
    elif any((as_float(row.get("cpu_wait_avg")) or 0.0) >= 10.0 for row in rows if row.get("available")):
        level = "warning"
        title = "Batch monitors show notable CPU wait"
        interpretation = "topas or nmon reports notable wait time. Review disk, paging, and storage sections before treating the issue as pure CPU saturation."

    return {
        "level": level,
        "title": title,
        "interpretation": interpretation,
        "evidence": evidence,
        "rows": rows,
        "topas": topas,
        "nmon": nmon,
    }


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
    local_hrd_threshold: float,
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
        s4rd = as_float(values.get("s4rd"))
        s5rd = as_float(values.get("s5rd"))
        s3hrd = as_float(values.get("s3hrd"))
        s5hrd = as_float(values.get("s5hrd"))
        remote_redispatch = none_sum((s4rd, s5rd))
        if (
            (remote_redispatch is not None and remote_redispatch >= remote_rd_threshold)
            or (s3hrd is not None and s3hrd < local_hrd_threshold)
            or (s5hrd is not None and s5hrd >= max(0.0, 100.0 - local_hrd_threshold))
        ):
            high_remote.append((label, values, remote_redispatch))
    for label, values, remote_redispatch in high_remote:
        findings.append(
            (
                "warning",
                f"Elevated remote redispatch or non-local memory on {label}",
                f"{label}: S4rd+S5rd={fmt(remote_redispatch)}%, S3hrd={fmt(values.get('s3hrd'))}%, "
                f"S5hrd={fmt(values.get('s5hrd'))}%. "
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
        f"LCPU->core mapping=<strong>{esc(topology.get('smt_mapping_source', 'unknown'))}</strong>; "
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
            f"<td>{fmt(values.get('s4rd'))}%</td>"
            f"<td>{fmt(values.get('s5rd'))}%</td>"
            f"<td>{fmt(values.get('s3hrd'))}%</td>"
            f"<td>{fmt(values.get('s4hrd'))}%</td>"
            f"<td>{fmt(values.get('s5hrd'))}%</td>"
            f"<td>{fmt(values.get('nsp'))}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>LSSRAD CPU range</th><th>LCPU</th><th>rq</th><th>bound</th>"
        "<th>S0rd</th><th>S1rd</th><th>S2rd</th><th>S3rd</th><th>S4rd</th><th>S5rd</th>"
        "<th>S3hrd</th><th>S4hrd</th><th>S5hrd</th><th>%nsp</th></tr></thead><tbody>"
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
            f"<td>{esc(placement.smt_mapping_source)}</td>"
            f"<td>{fmt(mp.avg('rq') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('cs') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('ics') if mp else None)}</td>"
            f"<td>{fmt(mp.avg('S0rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S1rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S2rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S4rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S5rd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S3hrd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S4hrd') if mp else None)}%</td>"
            f"<td>{fmt(mp.avg('S5hrd') if mp else None)}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>LCPU</th><th>REF</th><th>SRAD</th><th>LSSRAD CPU range</th><th>Range</th>"
        "<th>Physical core</th><th>SMT position</th><th>SMT class</th><th>SMT mapping source</th>"
        "<th>rq</th><th>cs</th><th>ics</th><th>S0rd</th><th>S1rd</th><th>S2rd</th><th>S3rd</th>"
        "<th>S4rd</th><th>S5rd</th><th>S3hrd</th><th>S4hrd</th><th>S5hrd</th></tr></thead><tbody>"
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
            f"<td>{esc(row.get('smt_mapping_source', 'unknown'))}</td>"
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
        "<table><thead><tr><th>Physical core</th><th>SMT mapping source</th><th>REF</th><th>SRAD</th>"
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
            f"<td>{fmt(row['s4rd'])}%</td>"
            f"<td>{fmt(row['s5rd'])}%</td>"
            f"<td>{fmt(row['s3hrd'])}%</td>"
            f"<td>{fmt(row['s4hrd'])}%</td>"
            f"<td>{fmt(row['s5hrd'])}%</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>SMT position</th><th>SMT class</th><th>LCPU list</th><th>Active LCPU count</th>"
        "<th>Trace samples total</th><th>Trace samples %</th><th>Average samples per LCPU</th>"
        "<th>rq total</th><th>bound total</th><th>avg %nsp</th><th>S2rd</th><th>S3rd</th><th>S4rd</th><th>S5rd</th>"
        "<th>S3hrd</th><th>S4hrd</th><th>S5hrd</th>"
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


def render_diagnostic_box(diagnosis: dict[str, object]) -> str:
    evidence = diagnosis.get("evidence", [])
    evidence_html = ""
    if evidence:
        evidence_html = "<ul>" + "".join(f"<li>{esc(line)}</li>" for line in evidence) + "</ul>"
    return (
        f'<div class="finding {esc(diagnosis.get("level", "info"))}">'
        f"<strong>{esc(diagnosis.get('title', ''))}</strong>"
        f"<p>{esc(diagnosis.get('interpretation', ''))}</p>"
        f"{evidence_html}"
        "</div>"
    )


def render_memory_topology_table(summary: dict[str, object]) -> str:
    rows = []
    for row in summary.get("rows", []):
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('ref') if row.get('ref') is not None else '-')}</td>"
            f"<td>{esc(row.get('srad'))}</td>"
            f"<td>{fmt(row.get('memory_gb'))}</td>"
            f"<td>{esc(row.get('lcpu_count'))}</td>"
            f"<td>{fmt(row.get('physical_core_count'))}</td>"
            f"<td>{fmt(row.get('memory_mb_per_lcpu'))}</td>"
            f"<td>{fmt(row.get('memory_mb_per_physical_core'))}</td>"
            f"<td>{esc(', '.join(str(cpu) for cpu in row.get('lcpus', [])))}</td>"
            f"<td>{esc(', '.join(str(cpu_range) for cpu_range in row.get('ranges', [])))}</td>"
            "</tr>"
        )
    return (
        render_diagnostic_box(summary)
        + "<table><thead><tr><th>REF</th><th>SRAD</th><th>Memory GB</th><th>LCPU</th><th>Physical cores</th>"
        "<th>MB/LCPU</th><th>MB/core</th><th>LCPU list</th><th>CPU ranges</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_affinity_diagnosis(diagnosis: dict[str, object]) -> str:
    rows = []
    for row in diagnosis.get("range_rows", []):
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('lssrad_range_label'))}</td>"
            f"<td>{fmt(row.get('affinity_score'))}</td>"
            f"<td>{fmt(row.get('remote_redispatch'))}%</td>"
            f"<td>{fmt(row.get('non_local_memory'))}%</td>"
            f"<td>{fmt(row.get('s0rd'))}%</td>"
            f"<td>{fmt(row.get('s1rd'))}%</td>"
            f"<td>{fmt(row.get('s3rd'))}%</td>"
            f"<td>{fmt(row.get('s4rd'))}%</td>"
            f"<td>{fmt(row.get('s5rd'))}%</td>"
            f"<td>{fmt(row.get('s3hrd'))}%</td>"
            f"<td>{fmt(row.get('s4hrd'))}%</td>"
            f"<td>{fmt(row.get('s5hrd'))}%</td>"
            f"<td>{fmt(row.get('nsp'))}%</td>"
            "</tr>"
        )
    return (
        render_diagnostic_box(diagnosis)
        + "<table><thead><tr><th>LSSRAD CPU range</th><th>Affinity score</th><th>S4rd+S5rd</th><th>Non-local hrd</th>"
        "<th>S0rd</th><th>S1rd</th><th>S3rd</th><th>S4rd</th><th>S5rd</th>"
        "<th>S3hrd</th><th>S4hrd</th><th>S5hrd</th><th>%nsp</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_thread_constraint_table(diagnosis: dict[str, object]) -> str:
    rows = []
    for row in diagnosis.get("rows", []):
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('pid'))}</td>"
            f"<td>{esc(row.get('name') or '-')}</td>"
            f"<td>{esc(row.get('sql_id') or '-')}</td>"
            f"<td>{esc(row.get('samples'))}</td>"
            f"<td>{esc(row.get('top_lcpu'))}</td>"
            f"<td>{fmt(row.get('top_lcpu_percent'))}%</td>"
            f"<td>{esc(row.get('top_physical_core') if row.get('top_physical_core') is not None else '-')}</td>"
            f"<td>{fmt(row.get('top_physical_core_percent'))}%</td>"
            f"<td>{fmt(row.get('oratop_cpu'))}%</td>"
            f"<td>{esc(row.get('wait_class') or '-')}</td>"
            f"<td>{esc(row.get('event') or '-')}</td>"
            "</tr>"
        )
    return (
        render_diagnostic_box(diagnosis)
        + "<table><thead><tr><th>PID/SPID</th><th>Name</th><th>SQL_ID</th><th>Trace samples</th>"
        "<th>Top LCPU</th><th>Top LCPU %</th><th>Top core</th><th>Top core %</th>"
        "<th>oratop %CPU</th><th>Wait class</th><th>Event</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def render_batch_process_table(source: str, processes: list[dict[str, object]]) -> str:
    rows = []
    for row in processes[:20]:
        rows.append(
            "<tr>"
            f"<td>{esc(source)}</td>"
            f"<td>{esc(row.get('pid', '-'))}</td>"
            f"<td>{esc(row.get('name') or row.get('command') or '-')}</td>"
            f"<td>{fmt(row.get('cpu_avg'))}%</td>"
            f"<td>{fmt(row.get('cpu_max'))}%</td>"
            f"<td>{esc(row.get('samples', 0))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_batch_capture_diagnosis(diagnosis: dict[str, object]) -> str:
    rows = []
    process_rows = []
    for row in diagnosis.get("rows", []):
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('source', '-'))}</td>"
            f"<td>{esc(yes_no(bool(row.get('available'))))}</td>"
            f"<td>{esc(row.get('samples', 0))}</td>"
            f"<td>{fmt(row.get('cpu_busy_avg'))}%</td>"
            f"<td>{fmt(row.get('cpu_wait_avg'))}%</td>"
            "</tr>"
        )
        process_rows.append(render_batch_process_table(str(row.get("source", "-")), row.get("top_processes", [])))

    process_html = "".join(process_rows)
    process_table = (
        "<h3>Top Processes from Batch Monitors</h3>"
        "<table><thead><tr><th>Source</th><th>PID</th><th>Name/command</th><th>avg CPU</th><th>max CPU</th><th>Samples</th></tr></thead><tbody>"
        + process_html
        + "</tbody></table>"
        if process_html
        else '<p class="note">No top process rows were parsed from topas/nmon batch data.</p>'
    )
    return (
        render_diagnostic_box(diagnosis)
        + "<table><thead><tr><th>Source</th><th>Available</th><th>Samples</th><th>avg CPU busy</th><th>avg CPU wait</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
        + process_table
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
    optional_context: dict[str, object],
    remote_rd_threshold: float,
    local_hrd_threshold: float,
    rq_threshold: float,
    out_path: Path,
) -> None:
    stats = lssrad_range_stats(placements, mpstat)
    findings = build_findings(stats, events, processes, topology, remote_rd_threshold, local_hrd_threshold, rq_threshold)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid, topology, mp_config, rq_threshold)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)
    smt_width = topology.get("smt_width")
    core_stats = physical_core_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_stats = smt_position_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_summary = global_smt_summary(trace_by_pid, smt_width)
    range_mapping = lssrad_range_mapping(placements)
    memory_topology = memory_topology_summary(placements, smt_width)
    affinity = diagnose_affinity(stats, smt_stats, remote_rd_threshold, local_hrd_threshold)
    memory_pressure = diagnose_memory_pressure(
        optional_context.get("vmstat_v", {}),
        optional_context.get("vmstat_s", {}),
        optional_context.get("vmstat_interval", {}),
        optional_context.get("vmo", {}),
        placements,
    )
    oracle_memory_pages = diagnose_oracle_memory_pages(
        optional_context.get("oratop_summary", {}),
        optional_context.get("oracle_params", {}),
        optional_context.get("vmo", {}),
        optional_context.get("asoo", {}),
        str(optional_context.get("aso_status_text", "")),
        optional_context.get("svmon", {}),
    )
    lpar_sizing = diagnose_lpar_sizing(mp_config, optional_context.get("lparstat", {}), smt_width, placements)
    extended_vpm = diagnose_extended_vpm(
        vpm_diagnosis,
        optional_context.get("schedo", {}),
        str(optional_context.get("mpstat_v_text", "")),
        lpar_sizing,
    )
    thread_constraints = diagnose_thread_constraints(trace_by_pid, processes, placements, smt_width)
    batch_capture = diagnose_batch_captures(
        optional_context.get("topas", {}),
        optional_context.get("nmon", {}),
        stats,
        rq_threshold,
    )
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
<div class="card"><div class="label">SMT Mapping</div><div class="value">{esc(topology.get("smt_mapping_source", "unknown"))}</div></div>
<div class="card"><div class="label">Oracle PIDs in trace</div><div class="value">{len(trace_by_pid)}</div></div>
</section>

<h2>Findings</h2>
{render_findings(findings)}

<h2>SMT Topology</h2>
{render_topology_note(topology)}

<h2>Oracle on SMT Threads</h2>
{render_global_smt_summary(smt_summary)}

<h2>Memory Topology</h2>
{render_memory_topology_table(memory_topology)}

<h2>CPU and Memory Affinity</h2>
{render_affinity_diagnosis(affinity)}

<h2>AIX Memory Pressure</h2>
{render_diagnostic_box(memory_pressure)}

<h2>Oracle SGA Page Size, Kernel Pinning, and DSO</h2>
{render_diagnostic_box(oracle_memory_pages)}

<h2>LPAR Sizing</h2>
{render_diagnostic_box(lpar_sizing)}

<h2>Extended VP Folding</h2>
{render_diagnostic_box(extended_vpm)}

<h2>Process Thread Constraints</h2>
{render_thread_constraint_table(thread_constraints)}

<h2>topas/nmon Batch Capture</h2>
{render_batch_capture_diagnosis(batch_capture)}

<h3>Per Oracle Process</h3>
{render_process_table(top_processes, trace_by_pid, smt_width)}

<h3>Per SQL_ID</h3>
{render_sql_table(top_sql, smt_width)}

<h2>SMT Position Summary</h2>
{render_smt_position_table(smt_stats)}

<h2>Physical Cores</h2>
<p class="note">Physical core ID and SMT class use smtctl bind-map data when available; otherwise the report falls back to an LCPU arithmetic heuristic.</p>
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
    optional_context: dict[str, object],
    remote_rd_threshold: float,
    local_hrd_threshold: float,
    rq_threshold: float,
) -> dict[str, object]:
    stats = lssrad_range_stats(placements, mpstat)
    findings = build_findings(stats, events, processes, topology, remote_rd_threshold, local_hrd_threshold, rq_threshold)
    summarized_events = summarize_events(events)
    top_sql = summarize_sql_ids(processes, trace_by_pid)
    vpm_diagnosis = diagnose_vpm_throughput_mode(stats, events, processes, trace_by_pid, topology, mp_config, rq_threshold)
    smt_width = topology.get("smt_width")
    core_stats = physical_core_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_stats = smt_position_stats(placements, mpstat, trace_by_pid, smt_width)
    smt_summary = global_smt_summary(trace_by_pid, smt_width)
    memory_topology = memory_topology_summary(placements, smt_width)
    affinity = diagnose_affinity(stats, smt_stats, remote_rd_threshold, local_hrd_threshold)
    memory_pressure = diagnose_memory_pressure(
        optional_context.get("vmstat_v", {}),
        optional_context.get("vmstat_s", {}),
        optional_context.get("vmstat_interval", {}),
        optional_context.get("vmo", {}),
        placements,
    )
    oracle_memory_pages = diagnose_oracle_memory_pages(
        optional_context.get("oratop_summary", {}),
        optional_context.get("oracle_params", {}),
        optional_context.get("vmo", {}),
        optional_context.get("asoo", {}),
        str(optional_context.get("aso_status_text", "")),
        optional_context.get("svmon", {}),
    )
    lpar_sizing = diagnose_lpar_sizing(mp_config, optional_context.get("lparstat", {}), smt_width, placements)
    extended_vpm = diagnose_extended_vpm(
        vpm_diagnosis,
        optional_context.get("schedo", {}),
        str(optional_context.get("mpstat_v_text", "")),
        lpar_sizing,
    )
    thread_constraints = diagnose_thread_constraints(trace_by_pid, processes, placements, smt_width)
    batch_capture = diagnose_batch_captures(
        optional_context.get("topas", {}),
        optional_context.get("nmon", {}),
        stats,
        rq_threshold,
    )

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
            "smt_mapping_source": topology.get("smt_mapping_source"),
        },
        "findings": [{"level": level, "title": title, "details": details} for level, title, details in findings],
        "vpm_throughput_mode": vpm_diagnosis,
        "memory_topology": memory_topology,
        "cpu_memory_affinity": affinity,
        "aix_memory_pressure": memory_pressure,
        "oracle_memory_pages": oracle_memory_pages,
        "lpar_sizing": lpar_sizing,
        "extended_vp_folding": extended_vpm,
        "thread_constraints": thread_constraints,
        "batch_capture_crosscheck": batch_capture,
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
                "srad_memory_mb": placement.srad_memory_mb,
                "smt_width": placement.smt_width,
                "smt_position": placement.smt_position,
                "smt_class_label": placement.smt_class_label,
                "smt_mapping_source": placement.smt_mapping_source,
                "physical_core_id": placement.physical_core_id,
                "mpstat": {
                    "rq": mpstat[cpu].avg("rq") if cpu in mpstat else None,
                    "cs": mpstat[cpu].avg("cs") if cpu in mpstat else None,
                    "ics": mpstat[cpu].avg("ics") if cpu in mpstat else None,
                    "S0rd": mpstat[cpu].avg("S0rd") if cpu in mpstat else None,
                    "S1rd": mpstat[cpu].avg("S1rd") if cpu in mpstat else None,
                    "S2rd": mpstat[cpu].avg("S2rd") if cpu in mpstat else None,
                    "S3rd": mpstat[cpu].avg("S3rd") if cpu in mpstat else None,
                    "S4rd": mpstat[cpu].avg("S4rd") if cpu in mpstat else None,
                    "S5rd": mpstat[cpu].avg("S5rd") if cpu in mpstat else None,
                    "S3hrd": mpstat[cpu].avg("S3hrd") if cpu in mpstat else None,
                    "S4hrd": mpstat[cpu].avg("S4hrd") if cpu in mpstat else None,
                    "S5hrd": mpstat[cpu].avg("S5hrd") if cpu in mpstat else None,
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
    optional_context: dict[str, object],
    remote_rd_threshold: float,
    local_hrd_threshold: float,
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
        optional_context,
        remote_rd_threshold,
        local_hrd_threshold,
        rq_threshold,
    )
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def assert_equal(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def run_selftests() -> None:
    placements = {lcpu: CpuPlacement(lcpu, None, 0, 1, "range-1", "0-7") for lcpu in range(8)}
    smt_bind_sample = """proc0 has 4 SMT threads.
Bind processor 0 is bound with proc0
Bind processor 1 is bound with proc0
Bind processor 2 is bound with proc0
Bind processor 3 is bound with proc0
proc8 has 4 SMT threads.
Bind processor 4 is bound with proc8
Bind processor 5 is bound with proc8
Bind processor 6 is bound with proc8
Bind processor 7 is bound with proc8
"""
    smt_bind = parse_smtctl(smt_bind_sample)
    assert_equal(smt_bind["proc_threads"]["proc0"], [0, 1, 2, 3], "smtctl proc0 threads")
    assert_equal(smt_bind["proc_threads"]["proc8"], [4, 5, 6, 7], "smtctl proc8 threads")
    assert_equal([smt_bind["lcpu_to_core"][cpu] for cpu in range(8)], [0, 0, 0, 0, 1, 1, 1, 1], "smtctl core IDs")
    assert_equal([smt_bind["lcpu_to_position"][cpu] for cpu in range(8)], [0, 1, 2, 3, 0, 1, 2, 3], "smtctl positions")
    apply_smt_topology(placements, 4, smt_bind)
    assert_equal((placements[4].physical_core_id, placements[4].smt_position), (1, 0), "bind-map proc8 starts core 1")
    assert_equal((placements[7].smt_class_label, placements[7].smt_mapping_source), ("quaternary", "smtctl-bindmap"), "bind-map source")

    heuristic_info = parse_smtctl("proc0 has 4 SMT threads.\nproc8 has 4 SMT threads.\n")
    heuristic_topology = resolve_smt_topology(None, heuristic_info, placements)
    apply_smt_topology(placements, heuristic_topology.get("smt_width"), heuristic_info)
    assert_equal(placements[7].smt_mapping_source, "heuristic", "heuristic fallback source")
    assert_equal(heuristic_topology["smt_mapping_source"], "heuristic", "heuristic topology source")
    assert any("LCPU->core mapping is heuristic" in warning for warning in heuristic_topology["warnings"]), "heuristic warning"

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

    boot_disabled = parse_smtctl("SMT is currently enabled.\nSMT boot mode is set to disabled.\nproc0 has 4 SMT threads.\n")
    assert_equal(boot_disabled["smt_enabled"], True, "smtctl boot mode does not override runtime enabled")
    assert_equal(boot_disabled["smt_width"], 4, "smtctl boot mode disabled keeps runtime width")

    disabled = parse_smtctl("This system is SMT capable.\nSMT is currently disabled.\nproc0 has 4 SMT threads.\n")
    assert_equal(disabled["smt_width"], 1, "smtctl disabled")

    mixed = parse_smtctl("proc0 has 4 SMT threads.\nproc1 has 8 SMT threads.\nproc2 has 8 SMT threads.\n")
    assert_equal(mixed["smt_width"], 8, "smtctl mixed mode")
    assert_equal(mixed["smt_width_mixed"], True, "smtctl mixed flag")

    mp_text = """System configuration: lcpu=3 ent=2.00 mode=uncapped
cpu min maj mpcs ics cs rq migrations S0rd S1rd S2rd S3rd S4rd S5rd S3hrd S4hrd S5hrd
0 0 0 0 0 0 0 0 1.0 2.0 0.0 95.0 0.0 0.0 99.0 1.0 0.0
1 0 0 0 0 0 0 0 1.0 2.0 0.0 0.0 4.0 2.0 99.0 1.0 0.0
2 0 0 0 0 0 0 0 1.0 2.0 0.0 0.0 0.0 0.0 80.0 20.0 0.0
"""
    mpstat, config, columns = parse_mpstat(mp_text)
    affinity_placements = {
        0: CpuPlacement(0, None, 0, 1, "range-1", "0"),
        1: CpuPlacement(1, None, 0, 2, "range-2", "1"),
        2: CpuPlacement(2, None, 0, 3, "range-3", "2"),
    }
    stats = lssrad_range_stats(affinity_placements, mpstat)
    findings = build_findings(stats, [], {}, {"warnings": []}, remote_rd_threshold=5.0, local_hrd_threshold=85.0, rq_threshold=8.0)
    assert not any("range-1" in details for _, _, details in findings), "high S3rd alone must not trigger"
    assert any("range-2" in details for _, _, details in findings), "S4rd+S5rd must trigger"
    assert any("range-3" in details for _, _, details in findings), "low S3hrd must trigger"
    assert "S4rd" in columns and "S5hrd" in columns, "remote and hrd columns should be parsed"

    lssrad = parse_lssrad("REF1   SRAD        MEM      CPU\n0\n          0   1.00      0-3 32-35\n")
    assert_equal(lssrad[0].srad_memory_mb, 1.0, "lssrad memory is retained")
    combined_lssrad = parse_lssrad(
        """REF1   SRAD        MEM      CPU
0  0  19456.00  0-11 16-19 28-31
1  13145.38  12-15 24-27
"""
    )
    assert_equal(combined_lssrad[0].ref, 0, "combined lssrad ref")
    assert_equal(combined_lssrad[0].srad, 0, "combined lssrad srad")
    assert_equal(combined_lssrad[0].srad_memory_mb, 19456.00, "combined lssrad memory")
    assert_equal(combined_lssrad[0].lssrad_cpu_range, "0-11", "combined lssrad range")
    assert_equal(combined_lssrad[12].ref, 0, "following lssrad line keeps ref")
    assert_equal(combined_lssrad[12].srad, 1, "following lssrad line srad")
    assert_equal(combined_lssrad[12].srad_memory_mb, 13145.38, "following lssrad line memory")
    smtctl_info = parse_smtctl("proc0 has 8 SMT threads.\n")
    assert_equal(resolve_smt_topology(4, smtctl_info, lssrad)["smt_width_source"], "cli", "CLI source wins")
    assert_equal(resolve_smt_topology(None, smtctl_info, lssrad)["smt_width_source"], "smtctl", "smtctl source wins")
    assert_equal(resolve_smt_topology(None, None, lssrad)["smt_width_source"], "inferred", "inferred source used")

    large_pages = diagnose_oracle_memory_pages({"sga_mb": 102400.0}, {}, {}, {}, "", {})
    assert_equal(large_pages["base_16mb_large_pages"], 6400, "base 16MB large-page count")
    assert_equal(large_pages["lock_sga_16mb_large_pages"], 6403, "LOCK_SGA 16MB large-page count")

    maxfree_placements = {lcpu: CpuPlacement(lcpu, None, 0, 1, "range-1", "0-19") for lcpu in range(20)}
    memory_pressure = diagnose_memory_pressure(
        {"memory_pools": 2},
        {},
        {},
        {"maxpgahead": "8", "j2_maxpagereadahead": "128"},
        maxfree_placements,
    )
    assert_equal(memory_pressure["expected_minfree"], 1200.0, "IBM maxfree example minfree")
    assert_equal(memory_pressure["expected_maxfree"], 2480.0, "IBM maxfree example maxfree")

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

    tunables = parse_tunables("minfree = 1200\nmaxfree 2024\nvpm_xvcpus = 2\n")
    assert_equal(tunables["minfree"], "1200", "parse vmo style tunable")
    assert_equal(tunables["maxfree"], "2024", "parse column tunable")
    assert_equal(tunables["vpm_xvcpus"], "2", "parse schedo style tunable")

    vmstat_s = parse_vmstat_s("123 free frame waits\n9 paging space page outs\n")
    assert_equal(vmstat_s["free_frame_waits"], 123, "parse vmstat -s free frame waits")
    assert_equal(vmstat_s["paging_space_page_outs"], 9, "parse vmstat -s paging outs")

    vmstat_interval = parse_vmstat_interval(
        """
kthr     memory             page              faults        cpu
----- ----------- ------------------------ ------------ -----------
 r  b   avm   fre  re  pi  po  fr   sr  cy  in   sy  cs us sy id wa
 1  0  1000   500   0   2   0   0    0   0 100  200 300 10  5 85  0
 2  1  1000   300   0   4   1   0    0   0 100  200 300 20  5 75  0
"""
    )
    assert_equal(vmstat_interval["pi_avg"], 3.0, "parse vmstat interval pi avg")
    assert_equal(vmstat_interval["po_max"], 1.0, "parse vmstat interval po max")

    lparstat = parse_lparstat("Online Virtual CPUs : 10\nEntitled Capacity : 5.00\n")
    assert_equal(lparstat["online_virtual_cpus"], "10", "parse lparstat online VPs")

    topas_summary = parse_topas_summary(
        """
Topas Monitor for host1 Interval: 1
CPU User% Kern% Wait% Idle%
ALL 10.0 5.0 0.0 85.0
Name PID CPU% PgSp Owner
oracle 1234 12.5 100M oracle
"""
    )
    assert_equal(topas_summary["sample_count"], 1, "parse topas sample count")
    assert_equal(topas_summary["cpu"]["idle"]["avg"], 85.0, "parse topas idle")
    assert_equal(topas_summary["top_processes"][0]["pid"], "1234", "parse topas top process pid")
    topas_terminal_error = parse_topas_summary("# Command: TERM=dumb topas -i 1\nTerminal dumb is unknown.\n")
    assert_equal(topas_terminal_error["raw_available"], False, "topas terminal errors are not valid captures")
    assert_equal(topas_terminal_error["terminal_error"], True, "topas terminal error is detected")

    nmon_summary = parse_nmon_summary(
        """
AAA,progname,nmon
ZZZZ,T0001,12:00:00,01-JAN-2026
CPU_ALL,CPU Total,User%,Sys%,Wait%,Idle%
CPU_ALL,T0001,10.0,5.0,0.0,85.0
CPU_ALL,T0002,20.0,10.0,1.0,69.0
TOP,Top Processes,PID,CPU%,Command
TOP,T0001,1234,12.5,oracle
TOP,T0002,1234,7.5,oracle
"""
    )
    assert_equal(nmon_summary["sample_count"], 1, "parse nmon timestamp count")
    assert_equal(nmon_summary["cpu_all"]["idle"]["avg"], 77.0, "parse nmon CPU_ALL idle avg")
    assert_equal(nmon_summary["top_processes"][0]["cpu_avg"], 10.0, "parse nmon top process CPU avg")

    nmon_alt_top = parse_nmon_summary(
        """
ZZZZ,T0001,12:00:00,01-JAN-2026
TOP,+PID,CPU%,Command
TOP,T0001,4321,6.5,ora_dbw0
"""
    )
    assert_equal(nmon_alt_top["top_processes"][0]["pid"], "4321", "parse nmon TOP +PID header")


def parse_args() -> argparse.Namespace:
    epilog = """Commands to collect input data on AIX:

  smtctl > /tmp/smtctl.out
  oratop -b -n 10 -f -r / as sysdba > /tmp/oratop.out
  trace -a -o /tmp/trace.out
  trcstop
  trcrpt /tmp/trace.out > /tmp/trace.trcrpt
  lssrad -av > /tmp/lssrad_av.out
  mpstat -d 1 60 > /tmp/mpstat_d.out
  mpstat -v 1 60 > /tmp/mpstat_v.out
  vmstat -v > /tmp/vmstat_v.out
  vmstat -s > /tmp/vmstat_s.out
  vmstat 1 60 > /tmp/vmstat.out
  TERM=vt100 topas -i 1 > /tmp/topas.out
  nmon -F /tmp/nmon.nmon -s 1 -c 60 -t
  vmo -F -a > /tmp/vmo_a.out
  schedo -a > /tmp/schedo_a.out
  lparstat -i > /tmp/lparstat_i.out
  asoo -a > /tmp/asoo_a.out
  lssrc -s aso > /tmp/aso_status.out
  svmon -P <pmon_pid> -O mpss=on > /tmp/svmon_pmon.out
  sqlplus -s / as sysdba <<'SQL' > /tmp/oracle_params.out
  set pages 200 lines 220 trimspool on
  show parameter lock_sga
  show parameter sga_target
  show parameter sga_max_size
  show parameter memory_target
  show parameter memory_max_target
  show parameter pga_aggregate_target
  show parameter pga_aggregate_limit
  show parameter cpu_count
  show parameter parallel_threads_per_cpu
  SQL

The --trace argument accepts either the raw /tmp/trace.out file when the tool is run on AIX
with trcrpt available, or the pre-decoded /tmp/trace.trcrpt text file.

Example:

  python3 oraix_report.py \\
    --oratop /tmp/oratop.out \\
    --trace /tmp/trace.trcrpt \\
    --lssrad /tmp/lssrad_av.out \\
    --mpstat /tmp/mpstat_d.out \\
    --smtctl /tmp/smtctl.out \\
    --mpstat-v /tmp/mpstat_v.out \\
    --vmstat-v /tmp/vmstat_v.out \\
    --vmstat-s /tmp/vmstat_s.out \\
    --vmstat /tmp/vmstat.out \\
    --topas /tmp/topas.out \\
    --nmon /tmp/nmon.nmon \\
    --vmo /tmp/vmo_a.out \\
    --schedo /tmp/schedo_a.out \\
    --lparstat /tmp/lparstat_i.out \\
    --asoo /tmp/asoo_a.out \\
    --aso-status /tmp/aso_status.out \\
    --svmon-pmon /tmp/svmon_pmon.out \\
    --oracle-params /tmp/oracle_params.out \\
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
    parser.add_argument("--mpstat-v", help="Optional file generated by: mpstat -v 1 60")
    parser.add_argument("--vmstat-v", help="Optional file generated by: vmstat -v")
    parser.add_argument("--vmstat-s", help="Optional file generated by: vmstat -s")
    parser.add_argument("--vmstat", help="Optional file generated by: vmstat 1 60")
    parser.add_argument("--topas", help="Optional batch file generated by: TERM=vt100 topas -i 1")
    parser.add_argument("--nmon", help="Optional capture file generated by: nmon -F /tmp/nmon.nmon -s 1 -c 60 -t")
    parser.add_argument("--vmo", help="Optional file generated by: vmo -F -a")
    parser.add_argument("--schedo", help="Optional file generated by: schedo -a")
    parser.add_argument("--lparstat", help="Optional file generated by: lparstat -i")
    parser.add_argument("--asoo", help="Optional file generated by: asoo -a")
    parser.add_argument("--aso-status", help="Optional file generated by: lssrc -s aso")
    parser.add_argument("--svmon-pmon", help="Optional file generated by: svmon -P <pmon_pid> -O mpss=on")
    parser.add_argument("--oracle-params", help="Optional Oracle parameter dump, for example: show parameter output")
    parser.add_argument("--smt-width", type=int, choices=SMT_WIDTH_CHOICES, help="Authoritative SMT width override: 1, 2, 4, or 8")
    parser.add_argument("--remote-rd-threshold", type=float, default=5.0, help="Heuristic threshold for S4rd+S5rd remote redispatch percent finding")
    parser.add_argument("--local-hrd-threshold", type=float, default=85.0, help="Heuristic threshold for S3hrd local home-SRAD dispatch percent finding")
    parser.add_argument("--rq-threshold", type=float, default=8.0, help="Heuristic threshold for total mpstat rq/bound CPU pressure finding")
    parser.add_argument("--format", choices=("html", "json", "auto"), default="auto", help="Output format. With auto, .json selects JSON; otherwise HTML.")
    parser.add_argument("--output", "-o", default="oraix_report.html", help="Output report path")
    parser.add_argument("--selftest", action="store_true", help="Run built-in parser and SMT topology self-tests")
    return parser.parse_args()


def validate_required_args(args: argparse.Namespace) -> None:
    missing = [name for name in ("oratop", "trace", "lssrad", "mpstat") if not getattr(args, name)]
    if missing:
        raise SystemExit("Missing required arguments: " + ", ".join(f"--{name}" for name in missing))


def read_optional_text(path: str | None) -> str:
    return read_text(path) if path else ""


def build_optional_context(args: argparse.Namespace, oratop_text: str) -> dict[str, object]:
    vmstat_v_text = read_optional_text(args.vmstat_v)
    vmstat_s_text = read_optional_text(args.vmstat_s)
    vmstat_text = read_optional_text(args.vmstat)
    vmo_text = read_optional_text(args.vmo)
    schedo_text = read_optional_text(args.schedo)
    lparstat_text = read_optional_text(args.lparstat)
    asoo_text = read_optional_text(args.asoo)
    aso_status_text = read_optional_text(args.aso_status)
    svmon_text = read_optional_text(args.svmon_pmon)
    oracle_params_text = read_optional_text(args.oracle_params)
    mpstat_v_text = read_optional_text(args.mpstat_v)
    topas_text = read_optional_text(args.topas)
    nmon_text = read_optional_text(args.nmon)

    return {
        "vmstat_v": parse_vmstat_v(vmstat_v_text),
        "vmstat_s": parse_vmstat_s(vmstat_s_text),
        "vmstat_interval": parse_vmstat_interval(vmstat_text),
        "vmo": parse_tunables(vmo_text),
        "schedo": parse_tunables(schedo_text),
        "lparstat": parse_lparstat(lparstat_text),
        "asoo": parse_tunables(asoo_text),
        "aso_status_text": aso_status_text,
        "svmon": parse_svmon_summary(svmon_text),
        "oracle_params": parse_oracle_params(oracle_params_text),
        "oratop_summary": parse_oratop_summary(oratop_text),
        "mpstat_v_text": mpstat_v_text,
        "topas": parse_topas_summary(topas_text),
        "nmon": parse_nmon_summary(nmon_text),
    }


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
    apply_smt_topology(placements, topology.get("smt_width"), smtctl_info)

    mpstat, mp_config, mp_columns = parse_mpstat(read_text(args.mpstat))
    trace_report = load_trace_report(args.trace)
    trace_threads = parse_trace_report(trace_report, placements)
    trace_by_pid = merge_trace_by_pid(trace_threads)
    oratop_text = read_text(args.oratop)
    optional_context = build_optional_context(args, oratop_text)
    oratop_processes, events = parse_oratop(oratop_text)
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
            optional_context,
            args.remote_rd_threshold,
            args.local_hrd_threshold,
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
            optional_context,
            args.remote_rd_threshold,
            args.local_hrd_threshold,
            args.rq_threshold,
            output,
        )
    print(f"{output_format.upper()} report written to {output}")


if __name__ == "__main__":
    main()
