{
  pkgs,
  ...
}:
let
  profiling_script = pkgs.writeShellScript "profile" ''
    #!/usr/bin/env bash
    # set -euo pipefail

    OUTDIR="$(mktemp -d)"
    DURATION=30
    FREQ=99
    SERVER_PORT=5000 # assuming
    SYNC_PORT=5005

    mkdir -p "$OUTDIR"

    TARGET_PID=$(${pkgs.lsof}/bin/lsof -t -i :$SERVER_PORT)
    if [ -z "$TARGET_PID" ]; then
      echo "No process is listening on port $SERVER_PORT"
      exit 1
    fi

    wait_for_signal() {
        echo "Waiting for client signal..."
        ${pkgs.netcat-openbsd}/bin/nc -l -p "$SYNC_PORT" -q 0 > /dev/null 2>&1
    }

    profile_state() {
        local name="$1"
        echo "=== Profiling: $name ==="
        ${pkgs.linuxPackages.perf}/bin/perf record -g -F $FREQ -o "$OUTDIR/perf_''${name}.data" -p $TARGET_PID -- sleep $DURATION
        ${pkgs.linuxPackages.perf}/bin/perf script -i "$OUTDIR/perf_''${name}.data" | ${pkgs.flamegraph}/bin/stackcollapse-perf.pl | ${pkgs.flamegraph}/bin/flamegraph.pl \
            --title "Flamegraph: $name" \
            --subtitle "Duration: ''${DURATION}s, Freq: ''${FREQ}Hz" \
            > "$OUTDIR/flamegraph_''${name}.svg"
    }

    echo "=== Profiling: idle ==="
    profile_state "idle"

    echo "=== Waiting for client to start RPC 1 load ==="
    wait_for_signal
    profile_state "GetAdditionalArtifacts"
    echo "Stabilizing for 60s..."
    sleep 60

    echo "=== Waiting for client to switch to RPC 2 load ==="
    wait_for_signal
    profile_state "GetEvidence"
    echo "Stabilizing for 60s..."
    sleep 60

    echo "=== Waiting for client to switch to mixed load ==="
    wait_for_signal
    profile_state "Concurrent"
    echo "Stabilizing for 60s..."
    sleep 60

    echo "=== Done. Results in $OUTDIR/ ==="
  '';
in
{
  boot.kernel.sysctl."kernel.perf_event_paranoid" = -1;

  environment.systemPackages = with pkgs; [
    linuxPackages.perf
    flamegraph
    cargo-flamegraph
    perf-tools
    binutils
    lsof
  ];

  systemd.services.profiling = {
    description = "Automated Profiling Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = profiling_script;
      Restart = "on-failure";
      RestartSec = 10;
    };
  };

  networking.firewall.allowedTCPPorts = [ 5005 ];
}
