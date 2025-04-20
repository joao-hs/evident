#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SECRETS=$(realpath $DIR/secrets)
POST_PROVISION=$(realpath $DIR/post-provision)

set -e

# sudo won't require password now
cat $SECRETS/passwd | sudo -S -v

source $DIR/activate

for script in $(ls $POST_PROVISION | sort); do
    if [[ -x "$POST_PROVISION/$script" ]]; then
        "$POST_PROVISION/$script"
    else
        echo "Skipping $script (not executable)"
    fi
done

source $DIR/deactivate
