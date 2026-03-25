## Getting started

### Pre-requisites

**Environment**: It might be wise to a VM to isolate the environment. If so, [Lima](https://lima-vm.io/) is an excellent tool to manage it.

A Linux-based operating system is assumed to be installed. Example snippets are given for Debian distribution of Linux.

#### Cloud Provider

For now, only Google Cloud is supported. The recommended option is to install the correspondent CLI tool of the cloud provider(s) you want to use and login with them. _Evident_ Client and Terraform will work out of the box afterwards.

<!--- AWS: `awscli` - Follow instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

```bash
aws login
```-->

- Google Cloud: `gcloud` - Follow instructions [here](https://docs.cloud.google.com/sdk/docs/install-sdk)

```bash
gcloud auth login
```

#### General utilities

- Example given for the aptitute package manager, adapt to your own

```bash
apt-get install -y build-essential debian-archive-keyring uidmap curl git sudo pkg-config just jq gpg systemd-container rsync
```

#### Building _Evident_ Client

If you want to build the client, your system needs the `go` compiler:

- Follow instructions [here](https://go.dev/doc/install)

Run the following command:

```bash
just build-client
```

Or use:

```bash
just install-client
```

to be able to run the client easily from anywhere in the system.

#### Building VM images

If you want to build VM images, your system needs:

- Nix package manager to be installed - Follow instructions [here](https://nixos.org/download/) or run the following commands:

```bash
cat <<EOF > /tmp/nix.conf
experimental-features = nix-command flakes
extra-platforms = x86_64-linux
EOF

sh <(curl -L https://nixos.org/nix/install) --no-daemon --nix-extra-conf-file /tmp/nix.conf
echo 'source /home/debian/.nix-profile/etc/profile.d/nix.sh' >> ~/.bashrc
```

> Note: while having more than one package manager in your operating system is generally discouraged, if `nix` is only used for building VM images, there shouldn't be conflicts.
> Note: `nix` builds gradually take a considerate amount of disk space as past build intermediate results are not automatically deleted. Consider running the command `nix-collect-garbage` sporadically.

#### Measuring VM images

If you want to measure VM images, your system needs:

- `systemd-pcrlock` which should be installed with `systemd-container` package, however, it is not directly accessible in `$PATH`. The client will try to find it in `/usr/lib/systemd/systemd-pcrlock` if not in `$PATH`.

#### Uploading a VM image to the cloud provider

- Install the tool `uplosi` by _Edgeless Systems_. Follow instructions [here](https://github.com/edgelesssys/uplosi)
- Use the provided configuration templates in `infrastructure/uplosi` to upload the built VM image to the cloud provider.

#### Deploying Confidential VMs

- Install the tool `terraform` by _HashiCorp_. Follow instructions [here](https://developer.hashicorp.com/terraform/install)
- It will use the installed cloud provider CLI tool (and credentials) to interact with the cloud provider
- Adapt the provided templates in `infrastructure/evns/dev` or use your own deployment configuration

#### Attesting Confidential VMs as a terraform plug-in

- The plug-in is not yet published, but it can be installed and used locally. Run the following command:

```bash
just install-provider
```

- Edit your terraform configuration (`~/.terraformrc`) to use the local provider. For example:

```hcl
provider_installation {

  dev_overrides {
      "registry.terraform.io/dpss-inesc-id/evident" = "/home/debian/go/bin"
  }

  # For all other providers, install them directly from their origin provider
  # registries as normal. If you omit this, Terraform will _only_ use
  # the dev_overrides block, and so no other providers will be available.
  direct {}
}
```

### Using _Evident_ Client

- `evident build`: builds a VM image from the provided Nix configuration files.

```bash
evident build <path-to-nix-flake> <derivation> <image-output-path>
```

For example:

```bash
mkdir -p ~/build-env
cp -r image/ ~/build-env
rsync -avq --exclude 'server/target' server/ ~/build-env
cd ~/build-env
git init # nix flake requires nix files to be tracked in a git repository
git add .
evident build ./image/flake.nix gce-base ./disk.raw
```

- `evident measure`: measures a VM image and outputs the expected measurements in a JSON file.

```bash
evident measure ~/build-env/disk.raw ~/build-env/expected-pcrs.json
```

- `uplosi`:

```bash
cd infrastructure/uplosi/gcp
uplosi upload ~/build-env/disk.raw -i
```

- `terraform`:

```bash
cd infrastructure/envs/dev
terraform init
terraform apply
# if the plug-in is used in the configuration, the remote attestation process will be executed as part of the deployment. If it fails, the deployment will NOT be rolled back, but the output will indicate the failure.
terraform destroy
```

- `evident attest`:

```bash
evident attest <ip-address> <port> <cpu-count> <cpu-platform> <cloud-provider> <path-to-expected-pcrs.json>
```

For example:

```bash
evident attest 34.111.111.111 5000 2 snp gce ~/build-env/expected-pcrs.json
```
