#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $DIR/../config/local-vm-config.env

set -e

create_vm () {
    DISK_DIR=$(dirname $DISK_LOCATION)
    mkdir -p $DISK_DIR
    VBoxManage createvm \
        --name $VM_NAME \
        --basefolder $DISK_DIR \
        --register

    VBoxManage modifyvm "$VM_NAME" \
        --ostype Ubuntu_64 \
        --memory $MEMORY \
        --cpus $CPU_COUNT \
        --nic1 nat \
        --natpf1 "guestssh,tcp,,$SSH_FORWARDED_PORT,,22" \
        --graphicscontroller vmsvga \
        --firmware efi \
        --boot1 disk --boot2 disk --boot3 none

    if [ -f "$DISK_LOCATION" ]; then
        read -p "Disk '$DISK_LOCATION' already exists. Do you want to delete it? (y/n): " disk_choice
        if [[ "$disk_choice" == "y" || "$disk_choice" == "Y" ]]; then
            rm -f "$DISK_LOCATION"
            MEDIUM_UUID=$(VBoxManage showmediuminfo disk "$DISK_LOCATION" | grep "^UUID:" | awk '{print $2}')
            VBoxManage closemedium disk $MEDIUM_UUID --delete
            echo "Disk '$DISK_LOCATION' deleted."
        else
            echo "No changes made to disk '$DISK_LOCATION'."
            echo "Aborting VM creation."
            exit 1
        fi
    fi
    VBoxManage createhd \
        --filename $DISK_LOCATION \
        --size $DISK_SIZE \
        --format VDI

    SATA_CONTROLLER_NAME="SATA"
    VBoxManage storagectl $VM_NAME \
        --name $SATA_CONTROLLER_NAME \
        --add sata \
        --controller IntelAhci

    IDE_CONTROLLER_NAME="IDE"
    VBoxManage storagectl $VM_NAME \
        --name $IDE_CONTROLLER_NAME \
        --add ide

    VBoxManage storageattach $VM_NAME \
        --storagectl $SATA_CONTROLLER_NAME \
        --port 0 \
        --device 0 \
        --type hdd \
        --medium $DISK_LOCATION

    VBoxManage storageattach $VM_NAME \
        --storagectl $IDE_CONTROLLER_NAME \
        --port 0 \
        --device 0 \
        --type dvddrive \
        --medium $ISO_PATH

    VBoxManage storageattach $VM_NAME \
        --storagectl $IDE_CONTROLLER_NAME \
        --port 1 \
        --device 0 \
        --type dvddrive \
        --medium $SEED_ISO_PATH

    echo "VM '$VM_NAME' created successfully."
}

if ! VBoxManage list vms | grep -q "\"$VM_NAME\""; then
    echo "VirtualBox VM '$VM_NAME' does not exist. Creating it..."
    create_vm
else
    read -p "VirtualBox VM '$VM_NAME' already exists. Do you want to delete it? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        VBoxManage unregistervm "$VM_NAME" --delete

        echo "VM '$VM_NAME' deleted."
        create_vm
    else
        echo "No changes made to VM '$VM_NAME'."
    fi
fi
