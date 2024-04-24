

# Setting up the agent


## Prepare privilege dropping

Create the chroot directory and create a user to drop privileges to.

```shell
mkdir -p -m 755 /var/empty/lophiid
useradd -d /var/empty/lophiid -M -r -s /bin/false lophiid-agent
```

Next update the configuration and set 'chroot_dir' to the chroot directory
and 'user' to the user created with the command above.
