#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SECRETS=$(realpath $DIR/../secrets)

set -e

# sudo won't require password now
cat $SECRETS/passwd | sudo -S -v

UNPRIVILEGED_USER=$USER
DEVICE=/dev/sda3
MAPPER_NAME=confidential
MOUNT_PATH=/home/$UNPRIVILEGED_USER/confidential
mkdir -p $MOUNT_PATH

# if it was mounted before (it shouldn't)
sudo umount $DEVICE || true
sudo cryptsetup -q -d $SECRETS/luks-encryption-key --type luks2 luksFormat $DEVICE
sudo cryptsetup -q -d $SECRETS/luks-encryption-key open $DEVICE $MAPPER_NAME
sudo mkfs.ext4 /dev/mapper/$MAPPER_NAME
sudo mount /dev/mapper/$MAPPER_NAME $MOUNT_PATH
# makes partition readable/writeable by the unprivileged user
sudo chown -R $UNPRIVILEGED_USER:$UNPRIVILEGED_USER $MOUNT_PATH

UUID=$(sudo blkid -s UUID -o value $DEVICE)

# key file:
#     none: will be provided on runtime
# options:
#     noauto: don't automount so that boot doesn't block prompting for decryption key

#     <target name> <source device> <key file> <options>
echo "$MAPPER_NAME UUID=$UUID none noauto" | sudo tee -a /etc/crypttab

# options: 
#     noauto: don't automount so that boot doesn't block prompting for decryption key;
#     nofail: device doesn't exist, don't report errors
# (source: man mount)
# dump: deprecated configuration, should always be 0
# pass: should be 2 for non-root-fs partitions
# (source: https://www.redhat.com/en/blog/etc-fstab)

#     <file system>        <mount point> <type> <options>  <dump> <pass>
echo "/dev/mapper/$MAPPER_NAME $MOUNT_PATH ext4 noauto,nofail 0 2" | sudo tee -a /etc/fstab
