#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  collect_oraix_stats.sh -o OUTPUT_DIR -i SECONDS [-p PMON_PID]

Collect AIX CPU placement diagnostics for oraix_report.py.

Options:
  -o OUTPUT_DIR  Directory where output files will be written.
  -i SECONDS     Collection duration for mpstat, in seconds.
  -p PMON_PID    Optional Oracle PMON PID for svmon SGA/page-size detail.

Output files:
  lssrad_av.out
  smtctl.out
  trace.bin
  trace.out
  mpstat_d.out
  mpstat_v.out
  vmstat_v.out
  vmstat_s.out
  vmstat.out
  vmo_a.out
  schedo_a.out
  lparstat_i.out
  asoo_a.out
  aso_status.out
  svmon_pmon.out

Example:
  ./collect_oraix_stats.sh -o /tmp/oraix_capture -i 60
EOF
}

out_dir=""
interval=""
pmon_pid=""
trace_running=0

while getopts "o:i:p:h" opt; do
  case "$opt" in
    o) out_dir=$OPTARG ;;
    i) interval=$OPTARG ;;
    p) pmon_pid=$OPTARG ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$out_dir" ] || [ -z "$interval" ]; then
  usage >&2
  exit 2
fi

case "$interval" in
  *[!0-9]*|"")
    echo "ERROR: -i must be a positive integer number of seconds." >&2
    exit 2
    ;;
esac

if [ "$interval" -le 0 ]; then
  echo "ERROR: -i must be greater than zero." >&2
  exit 2
fi

if [ -n "$pmon_pid" ]; then
  case "$pmon_pid" in
    *[!0-9]*|"")
      echo "ERROR: -p must be a numeric PMON PID." >&2
      exit 2
      ;;
  esac
fi

cleanup() {
  if [ "$trace_running" -eq 1 ]; then
    trcstop >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$out_dir"

lssrad_file="$out_dir/lssrad_av.out"
smtctl_file="$out_dir/smtctl.out"
trace_bin="$out_dir/trace.bin"
trace_report="$out_dir/trace.out"
mpstat_file="$out_dir/mpstat_d.out"
mpstat_v_file="$out_dir/mpstat_v.out"
vmstat_v_file="$out_dir/vmstat_v.out"
vmstat_s_file="$out_dir/vmstat_s.out"
vmstat_file="$out_dir/vmstat.out"
vmo_file="$out_dir/vmo_a.out"
schedo_file="$out_dir/schedo_a.out"
lparstat_file="$out_dir/lparstat_i.out"
asoo_file="$out_dir/asoo_a.out"
aso_status_file="$out_dir/aso_status.out"
svmon_pmon_file="$out_dir/svmon_pmon.out"

run_optional() {
  description=$1
  output_file=$2
  shift 2

  echo "Writing $description to $output_file"
  if command -v "$1" >/dev/null 2>&1; then
    {
      echo "# Command: $*"
      "$@"
    } > "$output_file" 2>&1 || {
      rc=$?
      {
        echo "# Command failed with exit code $rc: $*"
      } >> "$output_file"
      echo "WARNING: $description collection failed; see $output_file" >&2
    }
  else
    {
      echo "# Command not found: $1"
    } > "$output_file"
    echo "WARNING: command $1 not found; wrote placeholder $output_file" >&2
  fi
}

last_optional_pid=""
start_optional_bg() {
  description=$1
  output_file=$2
  shift 2

  last_optional_pid=""
  echo "Collecting $description into $output_file"
  if command -v "$1" >/dev/null 2>&1; then
    {
      echo "# Command: $*"
      "$@"
    } > "$output_file" 2>&1 &
    last_optional_pid=$!
  else
    {
      echo "# Command not found: $1"
    } > "$output_file"
    echo "WARNING: command $1 not found; wrote placeholder $output_file" >&2
  fi
}

echo "Writing lssrad data to $lssrad_file"
lssrad -av > "$lssrad_file"

echo "Writing smtctl data to $smtctl_file"
smtctl > "$smtctl_file"

echo "Starting AIX trace to $trace_bin"
trace -a -o "$trace_bin"
trace_running=1

echo "Collecting mpstat for $interval seconds into $mpstat_file"
mpstat -d 1 "$interval" > "$mpstat_file" &
mpstat_pid=$!

start_optional_bg "mpstat virtual processor data" "$mpstat_v_file" mpstat -v 1 "$interval"
mpstat_v_pid=$last_optional_pid
start_optional_bg "vmstat interval data" "$vmstat_file" vmstat 1 "$interval"
vmstat_pid=$last_optional_pid

wait "$mpstat_pid"
if [ -n "$mpstat_v_pid" ]; then
  wait "$mpstat_v_pid" || {
    rc=$?
    echo "# Command failed with exit code $rc: mpstat -v 1 $interval" >> "$mpstat_v_file"
    echo "WARNING: mpstat virtual processor data collection failed; see $mpstat_v_file" >&2
  }
fi
if [ -n "$vmstat_pid" ]; then
  wait "$vmstat_pid" || {
    rc=$?
    echo "# Command failed with exit code $rc: vmstat 1 $interval" >> "$vmstat_file"
    echo "WARNING: vmstat interval data collection failed; see $vmstat_file" >&2
  }
fi

echo "Stopping AIX trace"
trcstop
trace_running=0

echo "Decoding trace report to $trace_report"
trcrpt "$trace_bin" > "$trace_report"

run_optional "vmstat -v data" "$vmstat_v_file" vmstat -v
run_optional "vmstat -s data" "$vmstat_s_file" vmstat -s
run_optional "vmo tunables" "$vmo_file" vmo -F -a
run_optional "schedo tunables" "$schedo_file" schedo -a
run_optional "lparstat inventory" "$lparstat_file" lparstat -i
run_optional "asoo tunables" "$asoo_file" asoo -a
run_optional "aso subsystem status" "$aso_status_file" lssrc -s aso

if [ -n "$pmon_pid" ]; then
  run_optional "svmon PMON page-size data" "$svmon_pmon_file" svmon -P "$pmon_pid" -O mpss=on
else
  {
    echo "# PMON PID was not provided. Re-run with -p PMON_PID to collect svmon page-size data."
    echo "# Example PMON lookup: ps -ef | grep ora_pmon_ | grep -v grep"
  } > "$svmon_pmon_file"
fi

cat <<EOF
Collection complete.

Files:
  $lssrad_file
  $smtctl_file
  $trace_bin
  $trace_report
  $mpstat_file
  $mpstat_v_file
  $vmstat_v_file
  $vmstat_s_file
  $vmstat_file
  $vmo_file
  $schedo_file
  $lparstat_file
  $asoo_file
  $aso_status_file
  $svmon_pmon_file

Example report command:
  python3 oraix_report.py --oratop /tmp/oratop.out --trace "$trace_report" --lssrad "$lssrad_file" --mpstat "$mpstat_file" --smtctl "$smtctl_file" --mpstat-v "$mpstat_v_file" --vmstat-v "$vmstat_v_file" --vmstat-s "$vmstat_s_file" --vmstat "$vmstat_file" --vmo "$vmo_file" --schedo "$schedo_file" --lparstat "$lparstat_file" --asoo "$asoo_file" --aso-status "$aso_status_file" --svmon-pmon "$svmon_pmon_file" --output "$out_dir/oraix_report.html"
EOF
