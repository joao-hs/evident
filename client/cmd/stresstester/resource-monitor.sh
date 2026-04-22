#!/usr/bin/env bash

PORT=5000
OUT="${1:-resources.jsonl}"
INTERVAL=0.1

# resolve PID once at startup
PID=$(lsof -ti TCP:$PORT -s TCP:LISTEN)

if [[ -z "$PID" ]]; then
  echo "error: no process listening on port $PORT" >&2
  exit 1
fi

echo "monitoring PID $PID on port $PORT -> $OUT" >&2

# number of clock ticks per second
CLK_TCK=$(getconf CLK_TCK)

# read cumulative CPU ticks for our PID
cpu_ticks() {
  awk '{print $14 + $15}' /proc/$PID/stat
}

prev_ticks=$(cpu_ticks)
prev_time=$(date +%s%3N)  # milliseconds

while true; do
  sleep $INTERVAL

  # bail out if the process has died
  if [[ ! -f /proc/$PID/stat ]]; then
    echo "error: PID $PID is gone" >&2
    exit 1
  fi

  curr_ticks=$(cpu_ticks)
  curr_time=$(date +%s%3N)

  elapsed_ms=$(( curr_time - prev_time ))
  delta_ticks=$(( curr_ticks - prev_ticks ))

  # cpu% = (delta_ticks / CLK_TCK) / (elapsed_ms / 1000) * 100
  # rearranged to stay in integer arithmetic until the final division
  cpu_pct=$(awk "BEGIN { printf \"%.2f\", ($delta_ticks / $CLK_TCK) / ($elapsed_ms / 1000) * 100 }")

  # RSS from /proc/PID/status, in kB -> MB
  mem_mb=$(awk '/VmRSS/ { printf "%.1f", $2 / 1024 }' /proc/$PID/status)

  ts=$(date +%s)

  printf '{"ts":%d,"cpu_pct":%s,"mem_mb":%s}\n' \
    "$ts" "$cpu_pct" "$mem_mb" \
    | tee -a "$OUT"

  prev_ticks=$curr_ticks
  prev_time=$curr_time
done
