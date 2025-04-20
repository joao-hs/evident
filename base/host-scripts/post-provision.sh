#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REMOTE_HOST="127.0.0.1"
source $DIR/../config/local-vm-config.env

ssh -i $SSH_HOST_PRIVATE_KEY_PATH -p $SSH_FORWARDED_PORT "${REMOTE_USER}@${REMOTE_HOST}" bash -s << EOF
source ~/provision/activate
~/provision/post-provision.sh
EOF
