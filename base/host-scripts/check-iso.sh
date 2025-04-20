#!/bin/bash

# based on https://ubuntu.com/tutorials/how-to-verify-ubuntu

################### SETUP

if [ $# -ne 1 ]; then
    echo "Usage: $0 [<path-to-ubuntu-iso>]"
    exit 1
fi
IMAGE_PATH=$1

# this script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TARGET_DIR="$(mkdir -p "${DIR}/tmp" && realpath "${DIR}/tmp")"

###################

# delete previous temporary files
rm -f $TARGET_DIR/*

# step 1: fetch the checksum file and the gpg signature
wget -q -P "${TARGET_DIR}" https://releases.ubuntu.com/24.04/SHA256SUMS
wget -q -P "${TARGET_DIR}" https://releases.ubuntu.com/24.04/SHA256SUMS.gpg

# step 2: retrieve the correct signature key 
# (using a disposable keyring so we don't pollute the default one)
# values got from https://ubuntu.com/tutorials/how-to-verify-ubuntu#4-retrieve-the-correct-signature-key
gpg --no-default-keyring --keyring $TARGET_DIR/keyring --keyid-format long --keyserver hkp://keyserver.ubuntu.com --recv-keys 0x46181433FBB75451 0xD94AA3F0EFE21092 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Failed to retrieve the Ubuntu's GPG keys!"
    exit 1
fi

# step 3: verify the signature
UBUNTU_CHECKSUM=$(grep "${IMAGE_PATH##*/}" $TARGET_DIR/SHA256SUMS | awk '{print $1}')
gpg --no-default-keyring --keyring $TARGET_DIR/keyring --keyid-format long --verify $TARGET_DIR/SHA256SUMS.gpg $TARGET_DIR/SHA256SUMS > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Signature verification of .iso files checksums failed!"
    exit 1
else
    echo "Signature verification of .iso files checksums succeeded!"
fi

# step 4: verify the checksum
IMAGE_CHECKSUM=$(sha256sum "${IMAGE_PATH}" | awk '{print $1}')
if [ "${IMAGE_CHECKSUM}" != "${UBUNTU_CHECKSUM}" ]; then
    echo "Checksum verification failed!"
    echo "(Ubuntu's endorsed checksum)  Expected: ${UBUNTU_CHECKSUM}"
    echo "(Local .iso file checksum)    Got:      ${IMAGE_CHECKSUM}"
    exit 1
else
    echo "Checksum verification succeeded!"
    echo "(Ubuntu's endorsed checksum)  Expected: ${UBUNTU_CHECKSUM}"
    echo "(Local .iso file checksum)    Got:      ${IMAGE_CHECKSUM}"
fi

# step 5: cleanup
rm -f $TARGET_DIR/*
