#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <where-to-download-ubuntu-iso-file>"
    exit 1
fi
DESTINATION=$(readlink -f $1)
if [ -d "$DESTINATION" ]; then
    DESTINATION="${DESTINATION%/}/ubuntu-24.04.2-live-server-amd64.iso"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

mkdir -p $(dirname $DESTINATION)

wget -P $DESTINATION https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso
if [ $? -ne 0 ]; then
    echo "Failed to download the Ubuntu ISO file!"
    exit 1
fi
