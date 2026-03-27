These are examples of how to use systemd to wire these executables together. Adjust to your needs.

Boot ordering:

```
local-fs.target
    └─► evident-keygen.service   (Type=oneshot, RemainAfterExit=yes)
            └─► network-online.target
            └─► evident-server.service   (Type=notify → sends READY=1 after bind)
                    └─► evident-init.service   (Type=oneshot)
                            └─► multi-user.target   (unblocked, normal services start)
```

If you use the exported module from the Nix flake, it will setup the services for you.
