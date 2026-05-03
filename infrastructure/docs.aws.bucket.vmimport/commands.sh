#!/bin/bash

# adapted from: https://docs.aws.amazon.com/vm-import/latest/userguide/required-permissions.html

echo "Substitute \$BUCKET_NAME in role-policy.json and with the name of your S3 bucket"
# prompt user to press enter
read -p "Press enter to continue"

aws iam create-role --role-name vmimport \
    --assume-role-policy-document "file://$PWD/trust-policy.json"
aws iam put-role-policy --role-name vmimport \
    --policy-name vmimport \
    --policy-document "file://$PWD/role-policy.json"
