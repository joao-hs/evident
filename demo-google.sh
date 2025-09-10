#!/bin/bash

# TODO: Make this script completely automated
echo "Do not execute this script! Follow instructions manually. Exiting..."
exit 1

cd base

# Download official ubuntu server image
./host-scripts/download-iso.sh artifacts

# Check if the downloaded .iso digest matches the ubuntu signed one 
./host-scripts/check-iso.sh artifacts/ubuntu-24.04.2-live-server-amd64.iso

# Generate sha512 of login password for VM to fill in the autoinstall-values.yaml and local-vm-config.env
./host-scripts/crypt-passwd.sh

# Manually fill the autoinstall-values.yaml and local-vm-config.env files with your customized options

# Generate the ubuntu autoinstall.yaml file with the installation image specification
python host-scripts/autoinstall-generator.py autoinstall.yaml.j2 config/autoinstall-values.yaml > artifacts/autoinstall.yaml

# Generate the seed.iso to be booted with the image 
./host-scripts/generate-seed-iso.sh artifacts/autoinstall.yaml

# Create the VM 
./host-scripts/create-vm.sh

# Start the VM
VBoxManage startvm ubuntu-server --type headless

# TODO: change the next step to be unnattended
# Option 1: go to VirtualBox within 30 seconds of the VM start up, edit (click `e`) and change make the following change:
# (...)
# linux          /casper/vmlinuz autoinstall ---  
# (...)
# then click Ctrl+x or F10

# Option 2: go to VirtualBox, wait until your prompted with yes/no question, and type `yes` and ENTER

# WAIT (takes a while)

# Prepare provision utilities to be sent to the VM
./host-scripts/provision-provision.sh

# Run post-installation provisioning scripts
./host-scripts/post-install.sh

# (Optional) Load your VM with any workload

# Run post-provisioning scripts to prepare the VM to be deployed (takes a minute)
./host-scripts/post-provision.sh

# Shutdown the VM
VBoxManage controlvm ubuntu-server acpipowerbutton

# Convert the VM image file to RAW
VBoxManage clonemedium \
    artifacts/external/ubuntu-server/disk.vdi \
    artifacts/external/disk.raw --format RAW

# Compress the raw image file (takes a while)
cd artifacts
tar --format=oldgnu -Sczf compressed-image.tar.gz disk.raw
cd ..

# Create temporary bucket to upload the compressed-image 
# (choose the location that the VM is going to be launched)
gcloud storage buckets create gs://cvm-image-tmp --location="europe-west3"

# Upload (might take a while - depending on your upload speed)
gcloud storage cp artifacts/compressed-image.tar.gz gs://cvm-image-tmp

# Create the compute image
gcloud compute images create cvm \
    --source-uri gs://cvm-image-tmp/compressed-image.tar.gz \
    --storage-location="europe-west3" \
    --guest-os-features="GVNIC,UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,SEV_SNP_CAPABLE"

# Delete temporary bucket
gcloud storage rm -r gs://cvm-image-tmp

# Launch the VM
gcloud compute instances create cvm-test \
    --confidential-compute-type=SEV_SNP \
    --machine-type=n2d-standard-2 \
    --min-cpu-platform="AMD Milan" \
    --maintenance-policy="TERMINATE" \
    --zone=europe-west3-a \
    --image=cvm \
    --project=master-plane-281409 \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --network-interface="network-tier=PREMIUM,nic-type=GVNIC,stack-type=IPV4_ONLY,subnet=default"

# it should output an EXTERNAL_IP

# SSH onto the machine (might take a minute)
ssh -i ~/.ssh/id_inesc_cluster_joaohsereno ubuntu@EXTERNAL_IP

## (1) Mounting the encrypted volume
##### [inside-vm]
# passphrase will be prompted
sudo cryptsetup -q open /dev/nvme0n1p3 confidential
sudo mount /dev/mapper/confidential /home/$USER/confidential/

## (2) Verifying VM's firmware
##### [inside-vm]
sudo apt install -y build-essential

# run and press ENTER
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

export PATH=$PATH:$HOME/.cargo/bin
echo "" >> ~/.bashrc
echo "export PATH=\$PATH:\$HOME/.cargo/bin" >> ~/.bashrc

git clone https://github.com/virtee/snpguest.git --depth=1

cd snpguest

# takes a while
cargo build --release

sudo cp target/release/snpguest /usr/local/bin/snpguest

cd ..

mkdir artifacts

sudo snpguest report \
	--random \
    ./artifacts/attestation-report.bin \
	./artifacts/request-file.txt

sudo snpguest certificates \
	pem \
	./artifacts/certs 
exit

##### [outside-vm]

scp -i ~/.ssh/id_inesc_cluster_joaohsereno -r ubuntu@EXTERNAL_IP:~/artifacts ./artifacts/remote-attestation

attestation_report_file=./artifacts/remote-attestation/attestation-report.bin

measurement_byte_offset=$((0x90))
measurement_size_bytes=48
measurement=$(dd if=$attestation_report_file bs=1 skip=$measurement_byte_offset count=$measurement_size_bytes 2>/dev/null | xxd -p -c $measurement_size_bytes)

golden_report_data_file=./artifacts/remote-attestation/request-file.txt
report_data_byte_offset=$((0x50))
report_data_size_bytes=64
report_data=$(dd if=$attestation_report_file bs=1 skip=$report_data_byte_offset count=$report_data_size_bytes 2>/dev/null | xxd -p -c 16)

[[ "$report_data" == "$(cat $golden_report_data_file; echo)" ]] && \
  echo "Report is fresh" || \
  echo "Report is not fresh"

# TODO: check amd signature
# TODO: get ark and ask from trusted source, not from VM
ark_crt=./artifacts/remote-attestation/certs/ark.pem
ask_crt=./artifacts/remote-attestation/certs/ask.pem
vcek_crt=./artifacts/remote-attestation/certs/vcek.pem

signature_byte_offset=$((0x2A0))
signature_byte_end=$((0x49F))
signature_size_bytes=$(($signature_byte_end - $signature_byte_offset))
signature=$(dd if=$attestation_report_file bs=1 skip=$signature_byte_offset count=$signature_size_bytes 2>/dev/null || xxd -p -c $signature_size_bytes)


# Verifying key certificates
# (1) self-signed ARK
openssl verify -CAfile $ark_crt $ark_crt

# (2) ARK -> ASK
openssl verify -CAfile $ark_crt $ask_crt

# (3) ASK -> VCEK
openssl verify -CAfile $ark_crt -untrusted $ask_crt $vcek_crt

# Download the binarypb file using the measurement
gcloud storage cp gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/$measurement.binarypb ./artifacts/remote-attestation/$measurement.binarypb
# if it fails, the measurement isn't recognized by Google

# Grab Google's Compute Engine Confidential Computing trusted computing base root key certificate 
curl -o artifacts/remote-attestation/GCE-cc-tcb-root_1.crt https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt

# Extract signature public key from endorsement message
gcetcbendorsement inspect mask "artifacts/remote-attestation/$measurement.binarypb" --path=cert --out artifacts/remote-attestation/endorsement-key.pub

# Extract signature from endorsement message
gcetcbendorsement inspect signature "artifacts/remote-attestation/$measurement.binarypb" --out artifacts/remote-attestation/endorsement-signature.pem

# Extract endosement (payload) from endorsement message -- what was actually signed
gcetcbendorsement inspect payload "artifacts/remote-attestation/$measurement.binarypb" --out artifacts/remote-attestation/endorsement-payload.bin

# Verify root certification of the public key and the endorsement signature validity
openssl verify \
    -CAfile <(openssl x509 -outform pem -in artifacts/remote-attestation/GCE-cc-tcb-root_1.crt) \
    artifacts/remote-attestation/endorsement-key.pub \
&& \
openssl pkeyutl -verify \
    -pkeyopt rsa_padding_mode:pss \
    -pkeyopt rsa_pss_saltlen:32 -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pubin \
    -inkey <(openssl x509 -pubkey -nocert -outform pem -in artifacts/remote-attestation/endorsement-key.pub) \
    -sigfile artifacts/remote-attestation/endorsement-signature.pem -keyform PEM \
    -in <(openssl dgst -sha256 -binary artifacts/remote-attestation/endorsement-payload.bin)

# since the endorsement includes the expected measurement given the selected VMSAs (vcpu_count), we need to provide that
vcpu_count=2 # for n2d-standard-2

# Extract the endorsed measurement in hexadecimal format
gcetcbendorsement inspect mask artifacts/remote-attestation/$measurement.binarypb \
    --path=sev_snp.measurements[$vcpu_count] \
    --bytesform hex \
    --out artifacts/remote-attestation/endorsed-measurement.hex

# Check if it is the same as the measurement retrieved from the VM
[[ "$measurement" == "$(cat artifacts/remote-attestation/endorsed-measurement.hex)" ]] && \
    echo "They match!" || \
    echo "They DON'T match!"

# Extract the endorsed hash of the UEFI binary
gcetcbendorsement inspect mask artifacts/remote-attestation/$measurement.binarypb \
    --path=digest \
    --bytesform hex \
    --out artifacts/remote-attestation/endorsed-uefi-binary-digest.sha384

endorsed_uefi_binary_digest=$(cat artifacts/remote-attestation/endorsed-uefi-binary-digest.sha384)

# Download the UEFI binary
gcloud storage cp \
    gs://gce_tcb_integrity/ovmf_x64_csm/$endorsed_uefi_binary_digest.fd \
    artifacts/remote-attestation/uefi-binary.fd

downloaded_uefi_binary_digest=$(sha384sum "artifacts/remote-attestation/uefi-binary.fd" | awk '{print $1}')

[[ "$endorsed_uefi_binary_digest" == "$downloaded_uefi_binary_digest" ]] && \
    echo "They match!" || \
    echo "They DON'T match!"

cd ..
