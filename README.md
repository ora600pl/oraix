# ORAIX Oracle LCPU Report

ORAIX Oracle LCPU Report is a small AIX-focused diagnostic toolkit for Oracle workloads running on IBM Power systems. It collects and correlates `oratop`, AIX trace, `lssrad`, and `mpstat` output to show where Oracle processes actually ran across LCPUs, LSSRAD CPU range groups, and inferred SMT positions.

The generated report helps answer practical performance questions:

- Which Oracle processes and SQL IDs ran on which CPUs?
- Are Oracle foreground/background processes concentrated in one LSSRAD CPU range group?
- Is Oracle work mostly running on lower SMT positions or deeper SMT sibling positions?
- Is the system CPU-bound during the captured workload window?
- Are there signs of folding or slow virtual processor unfolding?
- Would `vpm_throughput_mode` be worth testing?

## Contents

- `oraix_report.py` - parser and report generator.
- `collect_oraix_stats.sh` - AIX collection helper for `lssrad`, trace, `mpstat`, `trcstop`, and `trcrpt`.

## Requirements

Collection must run on AIX with the standard AIX tools available:

- `lssrad`
- `trace`
- `trcstop`
- `trcrpt`
- `mpstat`
- `oratop`

Report generation requires Python 3. It can run on AIX, Linux, or macOS when the trace input is already decoded with `trcrpt`. If you pass a binary AIX trace file, run the report generator on AIX so it can call `trcrpt`.

## Collect Data

Run `oratop` during the same workload window as the AIX collection:

```sh
oratop -b -n 10 -f -r / as sysdba > /tmp/oratop.out
```

Collect AIX CPU placement data:

```sh
./collect_oraix_stats.sh -o /tmp/oraix_capture -i 60
```

The script writes:

- `/tmp/oraix_capture/lssrad_av.out`
- `/tmp/oraix_capture/trace.bin`
- `/tmp/oraix_capture/trace.out`
- `/tmp/oraix_capture/mpstat_d.out`

Equivalent manual collection:

```sh
lssrad -av > /tmp/oraix_capture/lssrad_av.out
trace -a -o /tmp/oraix_capture/trace.bin
mpstat -d 1 60 > /tmp/oraix_capture/mpstat_d.out
trcstop
trcrpt /tmp/oraix_capture/trace.bin > /tmp/oraix_capture/trace.out
```

## Generate an HTML Report

```sh
python3 oraix_report.py \
  --oratop /tmp/oratop.out \
  --trace /tmp/oraix_capture/trace.out \
  --lssrad /tmp/oraix_capture/lssrad_av.out \
  --mpstat /tmp/oraix_capture/mpstat_d.out \
  --output /tmp/oraix_capture/oraix_report.html
```

The HTML report includes sortable and filterable tables for:

- Findings
- LSSRAD group summary
- LCPU map
- Topology by SMT position
- SMT-position summary
- Oracle processes
- Trace processes by CPU
- Top SQL IDs from `oratop`
- Top wait events from `oratop`
- `vpm_throughput_mode` diagnosis

## Generate JSON

```sh
python3 oraix_report.py \
  --oratop /tmp/oratop.out \
  --trace /tmp/oraix_capture/trace.out \
  --lssrad /tmp/oraix_capture/lssrad_av.out \
  --mpstat /tmp/oraix_capture/mpstat_d.out \
  --format json \
  --output /tmp/oraix_capture/oraix_report.json
```

With `--format auto`, a `.json` output path selects JSON automatically. Other extensions produce HTML.

## vpm_throughput_mode

The report computes a recommendation for `vpm_throughput_mode` from the same capture window. It considers:

- total `mpstat` run queue and bound values,
- LSSRAD group run queue skew,
- Oracle CPU Runqueue waits from `oratop`,
- decoded AIX trace samples by LSSRAD group and SMT position,
- remote dispatch/readiness signals.

When the report recommends a controlled throughput test, it shows commands such as:

```sh
schedo -o vpm_throughput_mode
schedo -o vpm_throughput_mode=1
schedo -p -o vpm_throughput_mode=1
```

Rollback commands are also shown in the report:

```sh
schedo -o vpm_throughput_mode=0
schedo -p -o vpm_throughput_mode=0
```

Use runtime changes first for a controlled test window. Apply persistent changes only after the workload benefit is confirmed.

## LCPU and Physical Core Utilization

The report uses two complementary data sources:

- `mpstat -d` describes per-LCPU pressure and dispatch behavior. Important columns include `rq`, `bound`, `cs`, `ics`, `%nsp`, `S0rd`, `S1rd`, `S3rd`, and `S3hrd`.
- decoded AIX trace shows where Oracle processes actually ran. The report counts trace samples per LCPU, per LSSRAD group, and per inferred SMT position.

LSSRAD group labels are neutral names derived from CPU range order inside each `lssrad -av` SRAD row. They do not represent SMT primary/secondary/tertiary thread classes.

The `Topology by SMT Position` table groups LCPUs by REF, SRAD, and inferred SMT position. For example, when a row contains `0-3 32-35 96-99`, SMT position `0` groups LCPUs `0`, `32`, and `96`; SMT position `1` groups `1`, `33`, and `97`.

The `Active %` column is not a classic CPU busy percentage. It is Oracle trace coverage for a REF/SRAD/SMT position:

```text
active LCPU threads with Oracle trace samples / available LCPU threads for that REF/SRAD/SMT position
```

The `SMT-Position Summary` table aggregates trace samples and scheduler statistics by SMT position. This makes it easier to see whether Oracle work stayed mostly on lower SMT positions or spread into deeper SMT sibling positions during the capture window.

## Notes

- Keep `oratop`, trace, and `mpstat` in the same workload window.
- Prefer decoded `trcrpt` text as `--trace` when generating reports outside AIX.
- The `test_files` directory, if present locally, may contain environment-specific diagnostic captures and should not be published without review.
