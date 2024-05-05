# Setting up the agent

## Prepare privilege dropping

Create the chroot directory and create a user to drop privileges to.

```shell
mkdir -p -m 755 /var/empty/lophiid
useradd -d /var/empty/lophiid -M -r -s /bin/false lophiid-agent
```

Next update the configuration and set 'chroot_dir' to the chroot directory
and 'user' to the user created with the command above.

## Create the configuration

The configuration options are documented in the [config file](./config/agent-config.yaml).

## Optional: setup p0f

When p0f is running, you will need to setup the agent to use it.  First you need
to make sure that the p0f unix socket is accessible from the chroot directory so
using the example above, you want to run p0f with something like this:

```shell
p0f -s /var/empty/lophiid/p0f.socket
```
