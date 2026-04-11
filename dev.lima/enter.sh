#!/bin/bash

set -euo pipefail

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source $SRCDIR/env.sh

limactl start $VM_NAME || true

limactl shell --workdir $LIMA_WORKDIR $VM_NAME
