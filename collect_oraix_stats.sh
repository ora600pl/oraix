#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  collect_oraix_stats.sh -o OUTPUT_DIR -i SECONDS

Collect AIX CPU placement diagnostics for oraix_report.py.

Options:
  -o OUTPUT_DIR  Directory where output files will be written.
  -i SECONDS     Collection duration for mpstat, in seconds.

Output files:
  lssrad_av.out
  smtctl.out
  trace.bin
  trace.out
  mpstat_d.out

Example:
  ./collect_oraix_stats.sh -o /tmp/oraix_capture -i 60
EOF
}

out_dir=""
interval=""
trace_running=0

while getopts "o:i:h" opt; do
  case "$opt" in
    o) out_dir=$OPTARG ;;
    i) interval=$OPTARG ;;
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

echo "Writing lssrad data to $lssrad_file"
lssrad -av > "$lssrad_file"

echo "Writing smtctl data to $smtctl_file"
smtctl > "$smtctl_file"

echo "Starting AIX trace to $trace_bin"
trace -a -o "$trace_bin"
trace_running=1

echo "Collecting mpstat for $interval seconds into $mpstat_file"
mpstat -d 1 "$interval" > "$mpstat_file"

echo "Stopping AIX trace"
trcstop
trace_running=0

echo "Decoding trace report to $trace_report"
trcrpt "$trace_bin" > "$trace_report"

cat <<EOF
Collection complete.

Files:
  $lssrad_file
  $smtctl_file
  $trace_bin
  $trace_report
  $mpstat_file

Example report command:
  python3 oraix_report.py --oratop /tmp/oratop.out --trace "$trace_report" --lssrad "$lssrad_file" --mpstat "$mpstat_file" --smtctl "$smtctl_file" --output "$out_dir/oraix_report.html"
EOF
