#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $DIR/../config/local-vm-config.env

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

LOCAL_DIR=$(realpath $DIR/../provision)
REMOTE_HOST="127.0.0.1"
REMOTE_DIR=/home/$REMOTE_USER/
SECRETS_DIR=$DIR/../provision/secrets

fill_secrets() {
    # reset
    rm -f $SECRETS_DIR/*
    touch $SECRETS_DIR/.gitkeep

    echo -n $LUKS_ENCRYPTION_KEY > $SECRETS_DIR/luks-encryption-key
    echo -n $REMOTE_USER_PASSWD > $SECRETS_DIR/passwd
}

ssh -i $SSH_HOST_PRIVATE_KEY_PATH -p $SSH_FORWARDED_PORT "${REMOTE_USER}@${REMOTE_HOST}" bash -s << EOF
srm -r ~/provision
mkdir ~/provision
EOF

fill_secrets

scp -i $SSH_HOST_PRIVATE_KEY_PATH -P $SSH_FORWARDED_PORT -r "$LOCAL_DIR" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"

ssh -i $SSH_HOST_PRIVATE_KEY_PATH -p $SSH_FORWARDED_PORT "${REMOTE_USER}@${REMOTE_HOST}" bash -s << EOF
bash -c 'find ~/provision -type f -name "*.sh" -exec chmod +x {} \;'
EOF
