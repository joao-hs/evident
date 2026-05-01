#!/bin/bash

set -euo pipefail

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMA_YAML=$(realpath $SRCDIR/config/lima.yaml)
LIMA_YAML_TMPL=$(realpath $SRCDIR/config/lima.yaml.j2)

source $SRCDIR/env.sh

if ! command -v envsubst &> /dev/null
then
    echo "envsubst could not be found, please install it to continue"
    echo "On Debian/Ubuntu: sudo apt install gettext-base"
    exit
fi

PROJECT="$(realpath $SRCDIR/..)" ARCH="$(uname -m)" envsubst < "$LIMA_YAML_TMPL" > "$LIMA_YAML"
echo "Warning: provisioning scripts take around 10 minutes to complete"
limactl create --name $VM_NAME $LIMA_YAML
limactl start $VM_NAME

limactl shell --workdir $LIMA_WORKDIR $VM_NAME
