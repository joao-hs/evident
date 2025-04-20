#!/bin/bash

# This script is used to generate a password hash for the Packer user

echo "This password is to be used for the ubuntu user."

CRYPT_PASSWD=$(mkpasswd -s -m sha-512)

echo "Generated password hash: $CRYPT_PASSWD"

