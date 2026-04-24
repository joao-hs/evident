#!/bin/bash

IP_ADDRESS=$1 # example: "34.245.165.68"
CSP=$2 # "ec2" or "gce"
CPU_COUNT=$3 # example: 2
PCRS=$4 # example: /tmp/expected-pcrs.json

mkdir -p .evident-backup/logs
if [ -d ".evident/logs" ]; then
    mv .evident/logs/* .evident-backup/logs/
fi

for i in {1..100}; do
    # EC2 workflow uses github API, which rate limits at 60 requests per hour.
    if [ "$CSP" == "ec2" ] && [ $((i % 51)) -eq 0 ]; then
        echo "Sleeping for 1.5 hours to avoid hitting GitHub API rate limit..."
        sleep 5400
    fi
    evident attest $IP_ADDRESS snp $CSP --cpu-count $CPU_COUNT --expected-pcrs $PCRS
done

mkdir -p logs-$CSP
mv .evident/logs/* logs-$CSP/

./flamegraph.py logs-$CSP $CSP.json
