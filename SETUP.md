# 

# Setting up the backend and agents

## Building the source

#### Install dependencies

##### Bazel

You will need to have [bazel](https://bazel.build/) installed. Just grab the latest version from your OS distribution and install it.

##### Protobuf

Before you can build, you will need to compile some protobuffers by running a script. For this to work, you need protobuf-compiler installed. On Debian and Ubuntu, you do this with:

```shell
sudo apt-get install protobuf-compiler
```

### Build the protobufs

The gRPC services are defined in the backend_service.proto. Build these with the following command:

```shell
./compile_proto.sh
```

There is no output on the terminal unless something went wrong.

### Build the backend

To build the backend, run the following command:

```shell
bazel build //cmd/backend:backend
```

This will take care of downloading all the remaining dependencies and build the backend. 

If you are unfamilair with bazel, you can find the binary at ./bazel-bin/cmd/backend/backend_/backend

### Build the agent

Build the agent using the following command:

```shell
bazel build //cmd/agent:client
```

# Create a CA and certificates

SSL is used for encryption and authentication (client certs). Using this is totally optional, you can leave the ssl_cert configuration options out of the config but that is not recommended.

Below are example commands for creating certificates. 

## Create a local CA

Use the following command to create a CA:

```shell
export COUNTRY=XX  # replace these
export STATE=XX
export LOCATION=XX
export ORG=XX

mkdir ca

openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:4096 \
    -keyout ca/ca-key.pem \
    -out ca/ca-cert.pem \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=ca.lophiid.org"

```

Make sure the creates CA key is properly protected and make sure it is backed up properly.



## Create the backend certificate

Create the backend certificate using the following command:

```shell
export IP="1.1.1.1"  # The public IP of your backend
mkdir server

openssl req -newkey rsa:4096 -nodes \
  -keyout server/server-key.pem \
  -x509 -days 365 \
  -CA ca/ca-cert.pem \
  -CAkey ca/ca-key.pem \
  -out server/server-cert.pem \
  -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=lophiid.org" \
  -addext "subjectAltName = IP:${IP}"

```

Note that the location of the created certificate and key, which are in the "server/" directory, need to be added to the backend configuration.



## Create a agent certificates

Now for every honeypot agent, you typically run one agent per IP,  make an SSL client certificate:

```shell
IP="2.2.2.2"

mkdir clients
openssl req -newkey rsa:4096 -nodes -days 365000 \
   -keyout clients/${IP}-client-key.pem \
   -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=${IP}" \
   -out clients/${IP}-client-req.pem

openssl x509 -req -days 365000 -set_serial 01 \
   -in clients/${IP}-client-req.pem \
   -out clients/${IP}-client-cert.pem \
   -CA ca/ca-cert.pem \
   -CAkey ca/ca-key.pem

```

The agent certificates need to be deployed with the agent on the honeypot machines.



# Setting up the backend

## Create the configuration

The configuration file is documented in the [example config](./config/backend-config.yaml)

Note that it is important that the backend is reachable to all the honeypot agents so keep that in mind while configuring the port and listen address in the config.  If you setup SSL certificate authentication then it is fine to expose the backend to the Internet.

### Getting VirusTotal access

Create an account on [www.virustotal.com](http://www.virustotal.com) and click on your profile picture in the top right corner of the screen. Now click on `API Key` and it will bring you to a page where you can copy the API key (and paste it in the config).

The default free account on VirusTotal has plenty of quota. You probably can run 100-200 honeypots on dedicates IPs before running into quota issues. 

The VirusTotal client in lophiid is also written in a way where requests are queued and retried in case of quota issues.  This queue, which is only populated when you run out of quota, is not persistent during lophiid restarts though.

### Configuring telegram alerting

Create a telegram bot:

1. Open Telegram and search for the [BotFather]([Telegram: Contact @BotFather](https://telegram.me/BotFather) bot.
2. Start a chat with the BotFather and use the `/newbot` command to create a new bot.
3. Follow the instructions to choose a name and username for your bot.
4. Once your bot is created, the BotFather will provide you with an API token. Add this token to the backend configuration file.

Getting the channel/group  ID:

One way to obtain it is by going to [https://web.telegram.org](https://web.telegram.org/) and going to the channel/group. The ID is now in the URL.





## Build the agent

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





# Build the UI

First install the vue dependency:

```shell
npm i @vue/cli-service
```

Now you can build and run the UI. This will start a development server and it is not recommended to expose it to the internet but fine to use internal (it does use auth)

```shell
npm run serve
```
