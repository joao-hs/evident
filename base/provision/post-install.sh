#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SECRETS=$(realpath $DIR/secrets)
POST_INSTALL=$(realpath $DIR/post-install)

set -e

# sudo won't require password now
cat $SECRETS/passwd | sudo -S -v

source $DIR/activate

for script in $(ls $POST_INSTALL | sort); do
    if [[ -x "$POST_INSTALL/$script" ]]; then
        "$POST_INSTALL/$script"
    else
        echo "Skipping $script (not executable)"
    fi
done

source $DIR/deactivate
