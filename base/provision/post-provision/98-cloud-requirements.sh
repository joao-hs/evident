#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SECRETS=$(realpath $DIR/../secrets)

set -e

# sudo won't require password now
cat $SECRETS/passwd | sudo -S -v

echo -e "nvme\ngve" | sudo tee -a /etc/modules-load.d/modules.conf
sudo sed -i 's|GRUB_CMDLINE_LINUX_DEFAULT=""|GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0,38400n8d"|' /etc/default/grub
sudo update-grub
