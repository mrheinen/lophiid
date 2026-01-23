> [!IMPORTANT]
> If you run into ANY problems or have questions then just open an issue and
> we'll help out!

Note that this is for manually deploying lophiid on your own server without
using docker. It is highly recommended however to use docker and you find instructions for doing so in the [Quick Start](./QUICK_START.md)

# Setting up the backend and agents

## Building the source

#### Install dependencies

##### Golang

You will need to have Golang 1.25.1 installed. You can get this here:
https://go.dev/dl/

##### Yara-X

Run the following command to install cargo-c

```shell
cargo install cargo-c
```

Now clone the YARA-X repository:

```shell
git clone https://github.com/VirusTotal/yara-x.git
```

Once cargo-c is installed, go to the directory of the YARA-X repository and run the following command as root:

```shell
cargo cinstall -p yara-x-capi --release
```

##### Protobuf

Before you can build, you will need to compile some protobuffers by running a script. For this to work, you need protobuf-compiler installed. On Debian and Ubuntu, you do this with:

```shell
sudo apt-get install protobuf-compiler
sudo apt-get install protoc-gen-go
sudo apt-get install protoc-gen-go-grpc
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
go build cmd/backend/backend.go
```

### Build the agent
First make sure that libmagic is installed:

```shell
sudo apt-get install libmagic-dev
```

Build the agent using the following command:

```shell
go build cmd/agent/agent_cli.go
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

### Setup the database

#### Install postgresql

Install [postgresql](https://www.postgresql.org/):

```shell
sudo apt install postgresql postgresql-contrib
```

#### Import the database schema

Now import the database definition that are stored in ./docker/configs/sql/.
First you need to edit the files and replace all macros (which start with %%)
with the values you want to use in production.

Import using the following commands:

```shell
# Become the postgres user
sudo su postgres
# Import the database schema
psql -f ./docker/configs/sql/01-database.sql.template
psql -f ./docker/configs/sql/02-database.sql.template
psql -f ./docker/configs/sql/03-database.sql.template
```

### Create the backend configuration

The configuration file is documented in the [example config](./config/backend-config.yaml)

Note that it is important that the backend is reachable to all the honeypot agents so keep that in mind while configuring the port and listen address in the config. If you setup SSL certificate authentication then it is fine to expose the backend to the Internet.

#### Getting VirusTotal access (optional)

Create an account on [www.virustotal.com](http://www.virustotal.com) and click on your profile picture in the top right corner of the screen. Now click on `API Key` and it will bring you to a page where you can copy the API key (and paste it in the config).

The default free account on VirusTotal has plenty of quota. You probably can run 75 honeypots on dedicated IPs before running into real quota issues.

The VirusTotal client in lophiid is also written in a way where requests are queued and retried in case of quota issues.  This queue, which is only populated when you run out of quota, is not persistent during lophiid restarts though.

#### Configuring telegram alerting (optional)

Create a telegram bot:

1. Open Telegram and search for the [BotFather]([Telegram: Contact @BotFather](https://telegram.me/BotFather) bot.
2. Start a chat with the BotFather and use the `/newbot` command to create a new bot.
3. Follow the instructions to choose a name and username for your bot.
4. Once your bot is created, the BotFather will provide you with an API token. Add this token to the backend configuration file.

Getting the channel/group  ID:

One way to obtain it is by going to [https://web.telegram.org](https://web.telegram.org/) and going to the channel/group. The ID is now in the URL.

Once you have this setup, you can enable alerting for specific rules by clicking
on the bell icon behind those rules in the Rules tab of the UI.

### Running the backend

Simple run the backend:
```shell
./backend -c backend-config.yaml
```

## Setting up LLM triage

If you like to enable LLM triage and LLM descriptions of attacks then you will
need edit the backend [config](./config/backend-config.yaml) and enable the
triage process.

In the config set AI -> Triage -> Describer -> enable to 1.  Also make sure you have set an LLM config in that section.

Now you need to run the triage process:

```shell
go run cmd/triage/triage_cli.go -c backend-config.yaml
```

## Setting up Yara scanning

You can optionally setup automatic yara scanning of the malware that is
collected. To do this, you need to run this command from the code root
directory, where your backend-config.yaml is:
```shell
go run cmd/yara/main.go -m -r <path-to-yara-rules> -b 100
```

We use Yara-X so some older yara rules might potentially not work or
need updating. The code simply ignores those rules (but does output an error on
the screen).

This process will regularly poll the database for new downloads and then runs
the loaded rules against them. The results are stored in the database and
visible in the UI (e.g. downloads tab).

# Setting up the agent

## Prepare privilege dropping

Create the chroot directory and create a user to drop privileges to.

```shell
mkdir -p -m 755 /var/empty/lophiid
useradd -d /var/empty/lophiid -M -r -s /bin/false lophiid-agent
```

Next update the configuration and set 'chroot_dir' to the chroot directory
and 'user' to the user created with the command above.

## Allow ICMP packets

Use the following command to allow ICMP ping by the agent. The example is a bit lazy and allows it to all users. You can update the group range with a group ID that lophiid-agent belongs to in order to make it more strict.
```shell
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

## Create the configuration

The configuration options are documented in the [config file](./config/agent-config.yaml).
Note that you need to run one agent per IP so you might have to run multiple
agents on a single machine and each is configured individually.

## Setting up p0f (optional)

When p0f is running, you will need to setup the agent to use it.  First you need to make sure that the p0f unix socket is accessible from the chroot directory so using the example above, you want to run p0f with something like this:

```shell
p0f -s /var/empty/lophiid/p0f.socket
```

While you might run multiple agents on a machine; you typically only have to run one p0f instance per machine.

# Setting up the UI

## Build and run the API server

Building the server is done with this command:

```shell
go build cmd/api/api_server.go
```

Now copy the example configuration from
[./config/api-config.yaml](./config/api-config.yaml] and make the necessary
changes, such as the database location and listen port and listen IP. Also
change allowed_origins so that you only allow requests from the UI which you
will build in the next step.

Running the API server is a matter of:
```shell
./api_server -c api-config.yaml
```

Take note of the API key. You will need to give this to the web UI when you
connect with a browser.

## Build and run UI
First install the vue dependency:

```shell
npm i @vue/cli-service
```

Modify the backendAddress and make sure it points to the API server. This needs to be edited in the ./ui/src/Config.js and you should do this before doing the next step. In fact, keep in mind that whenever you change the config, restart the UI server.

Now you can build and run the UI. This will start a development server
and it is not recommended to expose it to the internet but fine to use
internal (it does require auth)

```shell
npm run serve
```

You will now see the IP and port on which you can connect to the UI.
