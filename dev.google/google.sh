#!/bin/bash

set -euo pipefail

RAW_DISK="disk.raw"
TAR_DISK="compressed-image.tar.gz"
TMP_BUCKET="cvm-image-tmp"
INSTANCE_NAME="${1:-cvm-test}"
MACHINE_TYPE="n2d-standard-2" # choose from https://cloud.google.com/compute/docs/general-purpose-machines#n2d_machine_types
REGION="europe-west3"
ZONE="europe-west3-a" # choose from https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations#supported-zones
IMAGE="${2:-cvm-nix}" # instructions in README.md (Section: Available VM images)
PROJECT="master-plane-281409"
FIREWALL_RULES_NAME="joaohsereno-cvm"
CVM_TAG="joaohsereno-evident-server"

yn_prompt() {
    local prompt="${1:-Are you sure? [y/N]} "
    local answer=""

    read -r -p "$prompt" answer || true

    local normalized="${answer,,}"

    if [[ "$normalized" =~ ^(y|yes|yy|yea|yeah)$ ]]; then
        return 0
    else
        return 1
    fi
}

if yn_prompt "Upload new image (disk.raw) as $IMAGE to Google? [y/N]"; then
    if [[ -f $TAR_DISK ]]; then
        rm $TAR_DISK
    fi

    tar --format=oldgnu -Sczf $TAR_DISK $RAW_DISK

    gcloud storage buckets create gs://$TMP_BUCKET --location="$REGION"

    gcloud storage cp $TAR_DISK gs://$TMP_BUCKET

    gcloud compute images create $IMAGE \
        --source-uri gs://$TMP_BUCKET/$TAR_DISK \
        --storage-location="$REGION" \
        --guest-os-features="GVNIC,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,SEV_SNP_CAPABLE"

    gcloud storage rm -r gs://$TMP_BUCKET
fi

gcloud compute --project=$PROJECT \
    firewall-rules create $FIREWALL_RULES_NAME \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:5000-5010,udp:5000-5010 \
    --source-ranges=0.0.0.0/0 \
    --target-tags="$CVM_TAG" || true

gcloud compute instances create $INSTANCE_NAME \
    --confidential-compute-type=SEV_SNP \
    --machine-type=$MACHINE_TYPE \
    --min-cpu-platform="AMD Milan" \
    --maintenance-policy="TERMINATE" \
    --zone=$ZONE \
    --image=$IMAGE \
    --project=$PROJECT \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --network-interface="network-tier=PREMIUM,nic-type=GVNIC,stack-type=IPV4_ONLY,subnet=default" \
    --tags="$CVM_TAG"

while true; do
    if yn_prompt "Don't forget to delete the resources! [y/N]"; then
        break
    fi
done

gcloud compute instances delete $INSTANCE_NAME --zone $ZONE

gcloud compute firewall-rules delete $FIREWALL_RULES_NAME || true

if yn_prompt "Delete the image ($IMAGE) too? [y/N]"; then
    gcloud compute images delete $IMAGE || true
fi
