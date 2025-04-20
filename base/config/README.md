This directory expected file tree is:

```
base/config/
├── autoinstall-values.yaml
├── local-vm-config.env
├── README.md
└── templates
    ├── autoinstall-values.template.yaml
    └── local-vm-config.template.env
```

The files under `base/config/templates` should be copied to `base/config` and manually adjusted to your needs. You should not track the manually adjusted files with git, as they might contain confidential information.

Respect the file names - don't include `.template` - as the example shows.
