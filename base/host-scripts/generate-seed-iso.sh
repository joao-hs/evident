#!/bin/bash

################### SETUP

if [ $# -ne 1 ]; then
    echo "Usage: $0 <path-to-autoinstall.yaml>"
    exit 1
fi

# this script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ARTIFACTS=$(realpath $DIR/../artifacts)

VENV=$DIR/../../.venv
source $VENV/bin/activate

AUTOINSTALL=$1
if [ ! -f "$AUTOINSTALL" ]; then
    echo "Error: autoinstall.yaml file '$AUTOINSTALL' does not exist."
    echo "Consider creating one using autoinstall-generator.py if you haven't."
    exit 1
fi
AUTOINSTALL=$(realpath $1)

python -c "import yaml, sys; yaml.safe_load(sys.stdin)" < $AUTOINSTALL > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: The $AUTOINSTALL file contains invalid YAML syntax."
    exit 1
fi

# TODO: check autoinstall schema with: https://github.com/canonical/subiquity.git, scripts/validate-autoinstall-user-data

###################

PREV_PWD=$(pwd)

cd $ARTIFACTS

rm -rf cidata

mkdir -p cidata
cd cidata
cp $AUTOINSTALL user-data
touch meta-data

cloud-localds $ARTIFACTS/seed.iso user-data meta-data

cd - > /dev/null 2>&1

rm -rf cidata

OUTPUT=$(realpath seed.iso)

cd $PREV_PWD

echo "The seed.iso file is located at $OUTPUT"
