# Unnattended Reproducible Install of Ubuntu Server 24.04 LTS

The file `autoinstall-template.yaml.j2` is a Jinja2 template file to generate a `autoinstall.yaml` file to be used to do an unattended installation of Ubuntu Server 24.04 LTS from the base `.iso` file.

## Jinja2 Variables

> It is recommended to use a YAML file to fill this values. The file `config/autoinstall-values.template.yaml` has all the possible customizable values to be configured. **Caution**: make sure git isn't tracking your secret/generated files.

- (required) `identity_passwd_sha512`: password used to login in `ollama-host` hashed with SHA-512. You can use the helper script `crypt-passwd.sh` to generate the expected value for this field.

- (required) `ssh_keys`: list of public SSH keys that will be allowed to login into the machine. **Caution**: only allow access to authorized personnel and keep private keys confidential.

- `initial_packages`: list of additional aptitude packages to be installed on setup

- `late_commands`: list of additional commands to be executed after setup