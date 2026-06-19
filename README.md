# ORAIX Oracle LCPU Report

ORAIX Oracle LCPU Report is a small AIX-focused diagnostic toolkit for Oracle workloads running on IBM Power systems. It collects and correlates `smtctl`, `oratop`, AIX trace, `lssrad`, `mpstat`, and optional `topas`/`nmon` batch output to show where Oracle processes actually ran across LCPUs, SRADs, physical cores, and SMT thread classes.

The generated report helps answer practical performance questions:

- Which Oracle processes and SQL IDs ran on which CPUs?
- Are Oracle foreground/background processes concentrated in one SRAD or LSSRAD CPU range?
- Is Oracle work running mostly on SMT primary threads, or spilling into secondary/tertiary/quaternary threads?
- Is the system CPU-bound during the captured workload window?
- Are there signs of folding or slow virtual processor unfolding?
- Would `vpm_throughput_mode` be worth testing?

## Contents

- `oraix_report.py` - parser and report generator.
- `collect_oraix_stats.sh` - AIX collection helper for `lssrad`, trace, `mpstat`, `topas`, `nmon`, `trcstop`, and `trcrpt`.

## Requirements

Collection must run on AIX with the standard AIX tools available:

- `lssrad`
- `trace`
- `trcstop`
- `trcrpt`
- `mpstat`
- `topas`
- `nmon`
- `oratop`
- `smtctl`

Report generation requires Python 3. It can run on AIX, Linux, or macOS when the trace input is already decoded with `trcrpt`. If you pass a binary AIX trace file, run the report generator on AIX so it can call `trcrpt`.

## Collect Data

Run `oratop` during the same workload window as the AIX collection:

```sh
smtctl > /tmp/smtctl.out
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
- `/tmp/oraix_capture/topas.out`
- `/tmp/oraix_capture/nmon.nmon`

Equivalent manual collection:

```sh
smtctl > /tmp/oraix_capture/smtctl.out
lssrad -av > /tmp/oraix_capture/lssrad_av.out
trace -a -o /tmp/oraix_capture/trace.bin
mpstat -d 1 60 > /tmp/oraix_capture/mpstat_d.out
TERM=vt100 topas -i 1 > /tmp/oraix_capture/topas.out
nmon -F /tmp/oraix_capture/nmon.nmon -s 1 -c 60 -t
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
  --smtctl /tmp/oraix_capture/smtctl.out \
  --topas /tmp/oraix_capture/topas.out \
  --nmon /tmp/oraix_capture/nmon.nmon \
  --output /tmp/oraix_capture/oraix_report.html
```

The HTML report includes sortable and filterable tables for:

- Findings
- SMT topology
- Oracle on SMT threads
- LCPU map
- Physical cores
- LSSRAD CPU range summary
- SMT-position summary
- Oracle processes
- Trace processes by CPU
- Top SQL IDs from `oratop`
- Top wait events from `oratop`
- `topas`/`nmon` batch capture cross-check
- `vpm_throughput_mode` diagnosis

## Generate JSON

```sh
python3 oraix_report.py \
  --oratop /tmp/oratop.out \
  --trace /tmp/oraix_capture/trace.out \
  --lssrad /tmp/oraix_capture/lssrad_av.out \
  --mpstat /tmp/oraix_capture/mpstat_d.out \
  --smtctl /tmp/oraix_capture/smtctl.out \
  --topas /tmp/oraix_capture/topas.out \
  --nmon /tmp/oraix_capture/nmon.nmon \
  --format json \
  --output /tmp/oraix_capture/oraix_report.json
```

With `--format auto`, a `.json` output path selects JSON automatically. Other extensions produce HTML.

## vpm_throughput_mode

The report computes a recommendation for `vpm_throughput_mode` from the same capture window. It considers:

- total `mpstat` run queue and bound values,
- Oracle trace distribution across primary/secondary/tertiary/quaternary SMT classes,
- capped/uncapped mode and entitlement from `mpstat`,
- Oracle CPU Runqueue waits from `oratop`,
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

The report uses three complementary data sources:

- `mpstat -d` describes per-LCPU pressure and dispatch behavior. Important columns include `rq`, `bound`, `cs`, `ics`, `%nsp`, `S0rd`, `S1rd`, `S3rd`, and `S3hrd`.
- decoded AIX trace shows where Oracle processes actually ran. The report counts trace samples per LCPU, per physical core, and per SMT class.
- `smtctl` supplies the SMT width. You can override it with `--smt-width {1,2,4,8}`.

SMT class calculation follows POWER/AIX LCPU numbering:

```text
smt_position = lcpu % smt_width
physical_core_id = lcpu // smt_width
```

`lssrad -av` CPU range labels are neutral names derived from CPU range order inside each SRAD row. They do not represent SMT primary/secondary/tertiary thread classes.

Process and SQL tables show dynamic columns for SMT classes, for example primary, secondary, tertiary, and quaternary for SMT-4. The JSON output includes the same counters under `smt_classes`.

Use `LSSRAD CPU Range Mapping` to translate neutral range labels into actual CPU ranges for the host. Use `Oracle on SMT Threads`, process, SQL, and `SMT-Position Summary` sections to reason about lower versus deeper SMT sibling positions.

The `Active %` column is not a classic CPU busy percentage. It is Oracle trace coverage for a REF/SRAD/SMT position:

```text
active LCPU threads with Oracle trace samples / available LCPU threads for that REF/SRAD/SMT position
```

The `SMT-Position Summary` table aggregates trace samples and scheduler statistics by SMT position. This makes it easier to see whether Oracle work stayed mostly on primary SMT positions or spread into deeper SMT sibling positions during the capture window.

## Notes

- Keep `oratop`, trace, and `mpstat` in the same workload window.
- Prefer decoded `trcrpt` text as `--trace` when generating reports outside AIX.
- The `test_files` directory, if present locally, may contain environment-specific diagnostic captures and should not be published without review.
