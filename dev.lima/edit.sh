#!/bin/bash

set -euo pipefail

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source $SRCDIR/env.sh

limactl edit $VM_NAME
