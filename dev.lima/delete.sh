#!/bin/bash

set -euo pipefail

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source $SRCDIR/env.sh

limactl stop $VM_NAME || true # might be already stopped

limactl delete $VM_NAME