#!/bin/bash
# Agent Certificate Setup
# Generates certificates for remote agent deployment
# Agent connects back to central backend infrastructure

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <backend-ip-or-domain> <agent-ip-or-domain> [agent-name]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100 192.168.1.200"
    echo "  $0 backend.mydomain.com 203.0.113.50 honeypot-web"
    echo "  $0 192.168.1.100 agent.mydomain.com"
    echo ""
    echo "This generates certificates for a remote agent that will:"
    echo "- Connect to backend gRPC server for instructions"
    echo "- Serve honeypot web traffic (HTTP/HTTPS)"
    echo "- Authenticate using client certificates"
    exit 1
fi

BACKEND_HOST="$1"
AGENT_HOST="$2"
AGENT_NAME="${3:-agent-$(echo $AGENT_HOST | tr '.' '-')}"
CERT_DIR="${CERT_DIR:-./certs}"
COUNTRY="${COUNTRY:-US}"
STATE="${STATE:-CA}"
LOCATION="${LOCATION:-San Francisco}"
ORG="${ORG:-Lophiid}"

# Auto-detect current user UID/GID for Docker user mapping if not already set
if [ -z "$DOCKER_UID" ]; then
    export DOCKER_UID=$(id -u)
fi
if [ -z "$DOCKER_GID" ]; then
    export DOCKER_GID=$(id -g)
fi

echo "Setting up AGENT certificates"
echo "============================="
echo "Backend host: $BACKEND_HOST"
echo "Agent host: $AGENT_HOST"
echo "Agent name: $AGENT_NAME"
echo "Certificate directory: $CERT_DIR"
echo ""
echo "This agent will:"
echo "- Connect to backend gRPC at $BACKEND_HOST:8080"
echo "- Serve honeypot traffic on $AGENT_HOST (HTTP/HTTPS)"
echo "- Use client certificate authentication"
echo ""

# Check if backend CA exists
if [ ! -f "$CERT_DIR/ca/ca-cert.pem" ]; then
    echo "ERROR: Backend CA certificate not found at $CERT_DIR/ca/ca-cert.pem"
    echo ""
    echo "You must run the backend certificate setup first:"
    echo "  ./scripts/setup-backend-certs.sh $BACKEND_HOST"
    exit 1
fi

mkdir -p "$CERT_DIR/clients"

# Agent client certificate (for gRPC authentication to backend)
echo "Creating agent gRPC client certificate..."
openssl req -newkey rsa:4096 -nodes -days 365 \
    -keyout "$CERT_DIR/clients/${AGENT_NAME}-client-key.pem" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=${AGENT_NAME}" \
    -out "$CERT_DIR/clients/${AGENT_NAME}-client-req.pem"

openssl x509 -req -days 365 -set_serial 01 \
    -in "$CERT_DIR/clients/${AGENT_NAME}-client-req.pem" \
    -out "$CERT_DIR/clients/${AGENT_NAME}-client-cert.pem" \
    -CA "$CERT_DIR/ca/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca/ca-key.pem"

rm "$CERT_DIR/clients/${AGENT_NAME}-client-req.pem"

# Agent HTTPS server certificate (for honeypot web server)
echo "Creating agent HTTPS server certificate..."
if [[ "$AGENT_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # IP address
    SAN="IP:${AGENT_HOST},DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"
else
    # Domain name  
    SAN="DNS:${AGENT_HOST},DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"
fi

openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/${AGENT_NAME}-http-key.pem" \
    -x509 -days 365 \
    -CA "$CERT_DIR/ca/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca/ca-key.pem" \
    -out "$CERT_DIR/${AGENT_NAME}-http-cert.pem" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=${AGENT_HOST}" \
    -addext "subjectAltName = ${SAN}"

# Set permissions
chmod 600 "$CERT_DIR"/clients/${AGENT_NAME}-client-key.pem
chmod 600 "$CERT_DIR"/${AGENT_NAME}-http-key.pem
chmod 644 "$CERT_DIR"/clients/${AGENT_NAME}-client-cert.pem
chmod 644 "$CERT_DIR"/${AGENT_NAME}-http-cert.pem

# Create agent deployment directory
AGENT_DIR="./agent-${AGENT_NAME}"
mkdir -p "$AGENT_DIR"

# Copy necessary files for agent deployment
echo "Creating agent deployment package..."
cp docker-compose.agent.yml "$AGENT_DIR/"
cp Dockerfile.agent "$AGENT_DIR/"
cp .env.agent "$AGENT_DIR/"

# Copy all build-related files needed for Docker build
echo "Copying build files..."
cp compile_proto.sh "$AGENT_DIR/"
cp backend_service.proto "$AGENT_DIR/"
cp go.mod "$AGENT_DIR/"
cp go.sum "$AGENT_DIR/"
cp MODULE.bazel "$AGENT_DIR/"
cp WORKSPACE "$AGENT_DIR/"
cp BUILD "$AGENT_DIR/"
cp deps.bzl "$AGENT_DIR/"

# Copy source directories needed for agent build
cp -r backend_service/ "$AGENT_DIR/"
cp -r cmd/ "$AGENT_DIR/"
cp -r pkg/ "$AGENT_DIR/"

# Make scripts executable
chmod +x "$AGENT_DIR/compile_proto.sh"

# Copy certificates needed by agent
mkdir -p "$AGENT_DIR/certs"/{ca,clients}
cp "$CERT_DIR/ca/ca-cert.pem" "$AGENT_DIR/certs/ca/"
cp "$CERT_DIR/clients/${AGENT_NAME}-client-"*.pem "$AGENT_DIR/certs/clients/"
cp "$CERT_DIR/${AGENT_NAME}-http-"*.pem "$AGENT_DIR/certs/"

# Create Docker Compose .env file for variable expansion
cat > "$AGENT_DIR/.env" << EOF
# Docker user mapping for compose file variable expansion
DOCKER_UID=$DOCKER_UID
DOCKER_GID=$DOCKER_GID
EOF

# Create agent-specific environment file
cat > "$AGENT_DIR/.env.agent" << EOF
# Agent Environment Variables for $AGENT_NAME
# Deploy this on the agent machine at $AGENT_HOST

# Docker user mapping (matches backend certificate permissions)
DOCKER_UID=$DOCKER_UID
DOCKER_GID=$DOCKER_GID

# Agent Configuration
LOPHIID_GENERAL_PUBLIC_IP=$AGENT_HOST
LOPHIID_GENERAL_LOG_LEVEL=info
LOPHIID_GENERAL_LOG_FILE=/app/logs/agent.log

# HTTP Listener
LOPHIID_HTTP_LISTENER_IP=0.0.0.0
LOPHIID_HTTP_LISTENER_PORT=80,8000,8001,8002

# HTTPS Listener (honeypot web server)
LOPHIID_HTTPS_LISTENER_IP=0.0.0.0
LOPHIID_HTTPS_LISTENER_PORT=443,981,1311,8243,8333,8443,8448,8843
EOF

# Check if we should use Let's Encrypt certificates for this agent
USE_LETSENCRYPT=false
if [[ ! "$AGENT_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Agent uses domain name, check if Let's Encrypt certs exist
    if [ -f "$CERT_DIR/live/lophiid-backend/fullchain.pem" ] && [ -f "$CERT_DIR/live/lophiid-backend/privkey.pem" ]; then
        echo "Using Let's Encrypt certificates for agent HTTPS honeypot"
        USE_LETSENCRYPT=true
        
        # Copy Let's Encrypt certificates to agent directory
        mkdir -p "$AGENT_DIR/certs/live/lophiid-backend"
        cp "$CERT_DIR/live/lophiid-backend/fullchain.pem" "$AGENT_DIR/certs/live/lophiid-backend/"
        cp "$CERT_DIR/live/lophiid-backend/privkey.pem" "$AGENT_DIR/certs/live/lophiid-backend/"
        
        # Set certificate paths for Let's Encrypt
        cat >> "$AGENT_DIR/.env.agent" << 'EOF'
LOPHIID_HTTPS_LISTENER_SSL_CERT=/app/certs/live/lophiid-backend/fullchain.pem
LOPHIID_HTTPS_LISTENER_SSL_KEY=/app/certs/live/lophiid-backend/privkey.pem
EOF
    else
        echo "Let's Encrypt certificates not found, using self-signed certificates for agent HTTPS"
        USE_LETSENCRYPT=false
    fi
else
    echo "Agent uses IP address, using self-signed certificates for HTTPS"
    USE_LETSENCRYPT=false
fi

if [ "$USE_LETSENCRYPT" = false ]; then
    # Use self-signed certificates
    cat >> "$AGENT_DIR/.env.agent" << EOF
LOPHIID_HTTPS_LISTENER_SSL_CERT=/app/certs/${AGENT_NAME}-http-cert.pem
LOPHIID_HTTPS_LISTENER_SSL_KEY=/app/certs/${AGENT_NAME}-http-key.pem
EOF
fi

# Continue with backend client configuration
cat >> "$AGENT_DIR/.env.agent" << EOF

# Backend Client (connects to your backend server)
LOPHIID_BACKEND_CLIENT_IP=$BACKEND_HOST
LOPHIID_BACKEND_CLIENT_PORT=8080
LOPHIID_BACKEND_CLIENT_STATUS_INTERVAL=10s
LOPHIID_BACKEND_CLIENT_AUTH_TOKEN=$(openssl rand -hex 32)
LOPHIID_BACKEND_CLIENT_GRPC_CA_CERT=/app/certs/ca/ca-cert.pem
LOPHIID_BACKEND_CLIENT_GRPC_SSL_CERT=/app/certs/clients/${AGENT_NAME}-client-cert.pem
LOPHIID_BACKEND_CLIENT_GRPC_SSL_KEY=/app/certs/clients/${AGENT_NAME}-client-key.pem

# Downloader
LOPHIID_DOWNLOADER_HTTP_CLIENT_TIMEOUT=10m

# P0f disabled by default
LOPHIID_P0F_SOCKET_LOCATION=
EOF

# Set ownership
# Set proper permissions (no ownership changes needed with user mapping)
echo "Setting certificate permissions..."
find "$AGENT_DIR/certs" -name "*-key.pem" -exec chmod 600 {} \; 2>/dev/null || true
find "$AGENT_DIR/certs" -name "*-cert.pem" -exec chmod 644 {} \; 2>/dev/null || true

# Create compressed deployment package
echo "Creating compressed deployment package..."
ZIP_FILE="${AGENT_DIR}.zip"
zip -r "$ZIP_FILE" "$AGENT_DIR/" >/dev/null 2>&1

echo ""
echo "✓ Agent certificates and deployment package created!"
echo ""
echo "Generated certificates:"
echo "- Agent gRPC client: $CERT_DIR/clients/${AGENT_NAME}-client-cert.pem"
echo "- Agent HTTPS server: $CERT_DIR/${AGENT_NAME}-http-cert.pem"
echo ""
echo "Agent deployment package created:"
echo "- Directory: $AGENT_DIR/"  
echo "- Compressed: $ZIP_FILE"
echo ""
echo "Next steps:"
echo ""
echo "1. REGISTER AGENT in backend UI:"
echo "   - Access UI at http://$BACKEND_HOST:9888"
echo "   - Go to Honeypots section"
echo "   - Add new honeypot with IP: $AGENT_HOST"
echo "   - Use auth token from $AGENT_DIR/.env.agent"
echo ""
echo "2. DEPLOY AGENT to $AGENT_HOST:"
echo "   Option A: Copy compressed package"
echo "   - scp $ZIP_FILE user@$AGENT_HOST:~/"
echo "   - ssh user@$AGENT_HOST 'unzip $ZIP_FILE && cd $AGENT_DIR'"
echo "   - ssh user@$AGENT_HOST 'cd $AGENT_DIR && docker compose -f docker-compose.agent.yml up -d'"
echo ""
echo "   Option B: Copy directory directly"
echo "   - scp -r $AGENT_DIR/ user@$AGENT_HOST:~/"
echo "   - ssh user@$AGENT_HOST 'cd $AGENT_DIR && docker compose -f docker-compose.agent.yml up -d'"
echo ""
echo "3. VERIFY CONNECTION:"
echo "   - Check backend logs: docker compose logs backend | grep 'honeypot'"
echo "   - Test agent: curl http://$AGENT_HOST:8000/"
echo ""
echo "Agent will serve honeypot traffic on:"
echo "- HTTP: $AGENT_HOST:8000, $AGENT_HOST:80"
echo "- HTTPS: $AGENT_HOST:443, $AGENT_HOST:8443, etc."