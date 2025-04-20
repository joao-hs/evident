#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SECRETS=$(realpath $DIR/../secrets)

set -e

# sudo won't require password now
cat $SECRETS/passwd | sudo -S -v

cd ~
srm -r ~/provision
