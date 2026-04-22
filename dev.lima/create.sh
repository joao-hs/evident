#!/bin/bash

set -euo pipefail

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMA_YAML=$(realpath $SRCDIR/config/lima.yaml)
LIMA_YAML_TMPL=$(realpath $SRCDIR/config/lima.yaml.j2)

source $SRCDIR/env.sh

jinja2 $LIMA_YAML_TMPL -o $LIMA_YAML -D project="$(realpath $SRCDIR/..)" -D arch="$(uname -m)"
echo "Warning: provisioning scripts take around 10 minutes to complete"
limactl create --name $VM_NAME $LIMA_YAML
limactl start $VM_NAME

limactl shell --workdir $LIMA_WORKDIR $VM_NAME
