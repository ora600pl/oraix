# ORAIX Oracle LCPU Report

ORAIX Oracle LCPU Report is a small AIX-focused diagnostic toolkit for Oracle workloads running on IBM Power systems. It collects and correlates `oratop`, AIX trace, `lssrad`, and `mpstat` output to show where Oracle processes actually ran across primary, secondary, and tertiary LCPUs.

The generated report helps answer practical performance questions:

- Which Oracle processes and SQL IDs ran on which CPUs?
- Are Oracle foreground/background processes concentrated on primary LCPUs?
- Are secondary or tertiary LCPUs being used effectively?
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
- Primary, secondary, and tertiary LCPU summary
- LCPU map
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
- primary versus secondary/tertiary run queue skew,
- Oracle CPU Runqueue waits from `oratop`,
- decoded AIX trace samples by LCPU tier,
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

## Notes

- Keep `oratop`, trace, and `mpstat` in the same workload window.
- Prefer decoded `trcrpt` text as `--trace` when generating reports outside AIX.
- The `test_files` directory, if present locally, may contain environment-specific diagnostic captures and should not be published without review.

