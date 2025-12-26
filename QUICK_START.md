# Quick Start Guide

This guide provides a fast track to getting Lophiid up and running using
the `setup_lophiid.py` helper script. This script automates many of the
configuration and certificate generation steps required for a distributed
deployment.

## Prerequisites

- Linux environment
- Python 3 installed
- Docker and Docker Compose installed
- `openssl` and `golang` (1.24.7 or newer) installed

## Step 1: Prepare the install

### Set environment variables
Set the backend and agent IP addresses in environment variables. Doing so allows
you to just cut and paste the commands in th steps below. Note that we need
public IP addresses here.

```bash
export BACKEND_IP=1.2.3.4
export AGENT_IP=4.5.6.7

```

### Get a virustotal API key

This is super simple, just to to www.virustotal.com and sign up for an account.
Now in the top right corner click on your profile picture/icon and then click on
`API Key`

You can now copy the API key to clipboard and then export it to an environment
variable:

```bash
export VT_API_KEY=<your api key>
```

### Get an openrouter API key

In this quick start we will make use of preconfigured OpenRouter models. To use
them, you will need an OpenRouter API key which you can get by signing up on
www.openrouter.ai .

After signing up, click on your profile picture in the top right, click `Keys`
and click `Create API Key`. Finally copy the API key to the clipboard.

Next, create an environment variable:

```bash
export OR_API_KEY=<your api key>
```

## Step 2: Create a Local Certificate Authority (CA)

Lophiid uses SSL for authentication and encryption between the backend
and agents. First, create a local CA which will be used to sign all
subsequent certificates.

Run the following command:

```bash
./setup_lophiid.py --create-ca
```

**Example Output:**

```
$ ./setup_lophiid.py --create-ca
Creating CA in docker/certs/ca...
.........+.+++++++++++++++++++++++++++++++++++++++++++++*.+...+...+.......+.................+.+..+.+......+...+........+....+...+...+........+....+.....+.+.....+......+.+++++++++++++++++++++++++++++++++++++++++++++*....+..+.......+...+............+..+.....................+....+.....+...............+......+....+.....+...+............+......+.........+.+........................+.........+......+..............+..........+..+.......+..+.+..+.......+.........+...........+.+.........+.....+....+......+.........+......+.........+.....+............+...+.......+........+.+.....................+.........+.....+....+....................+.........+.+.....+......+.............+..+......+...+.+...+......+..+...+.......+...+.........+..+......+....+++++
.... snip snip snip ....
CA created successfully.

# Check that the files are created:
$ ls docker/certs/ca/
README  ca-cert.pem  ca-cert.srl  ca-key.pem
```

## Step 3: Prepare Backend Deployment

Now prepare the backend configuration and deployment files. This will make copies of the configuration template files and will subsitute important values withe values you have set in environment variables and flags.

This step will also automatically create the necessary backend certificates using the provided IP address.

Importantly, this script will prepare the database schema and the database
account. For this an account a password needs to be set which you can do with
the --db-password flag.

```bash
./setup_lophiid.py --prepare-backend-deployment \
    --db-password <password> \
    --openrouter-api-key ${OR_API_KEY} \
    --virustotal-api-key ${VT_API_KEY} \
    --backend-ip ${BACKEND_IP}
```

**Sample Output:**

```
Preparing backend deployment configuration...
Creating Backend Certs in docker/certs/backend...
Backend certificates created with IP SAN: 1.2.3.4
Generated docker/configs/api/api-config.yaml from docker/configs/api/api-config.yaml.template
Generated docker/configs/backend/backend-config.yaml from docker/configs/backend/backend-config.yaml.template
Generated docker/configs/sql/01-database.sql from docker/configs/sql/01-database.sql.template
...
Backend deployment preparation completed.

============================================================
Backend API Key: 550e8400-e29b-41d4-a716-446655440000
IMPORTANT: Use this key to log in to the Web UI!
============================================================
```

**Important:** Note down the "Backend API Key" displayed in the output. You will need this key to log in to the Lophiid Web UI.

## Step 4: Start the Backend

With the backend prepared, you can now start the services using Docker Compose:

```bash
sudo docker compose up -d
```

This will start the backend service, API server, database, and UI.

## Step 5: Prepare an Agent

An agent acts as the honeypot sensor. While typically deployed on separate remote machines, for this quick start you can run it on the same machine as the backend.

To prepare the agent files, run:

```bash
./setup_lophiid.py --prepare-agent-deployment \
    --agent-ip ${AGENT_IP} \
    --backend-ip ${BACKEND_IP}
```

**Sample Output:**

```
Preparing agent deployment in docker/agents/192.168.1.100...
Generating Client Certs for 192.168.1.100...
Generating Server Certs for 192.168.1.100...
Configuring agent_config.yaml...

============================================================
Generated Auth Token: aB3cD4...
IMPORTANT: Configure this token in the backend via the Web UI!
============================================================

Building agent_cli...
Built agent_cli to docker/agents/192.168.1.100/agent_cli
Agent deployment prepared successfully at docker/agents/192.168.1.100
```

This command creates a complete deployment directory for the agent at `./docker/agents/<agent public ip>`.

## Step 6: Start the Agent

If you are deploying the agent to a remote machine, copy the generated directory (`./docker/agents/<agent public ip>`) to that machine. If running locally, you can use the directory as is.

Navigate to the agent deployment directory and start the agent:

```bash
cd docker/agents/${AGENT_IP}
sudo docker compose up -d
```

The agent will automatically connect to the backend using the configured certificates and settings.
