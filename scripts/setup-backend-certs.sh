#!/bin/bash
# Backend Infrastructure Certificate Setup
# Generates certificates for the central backend server that hosts:
# - Backend gRPC server (for agent connections)
# - API server
# - UI
# - PostgreSQL database

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backend-ip-or-domain> [production]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100                    # Development with IP"
    echo "  $0 backend.mydomain.com              # Development with domain"
    echo "  $0 backend.mydomain.com production   # Production with Let's Encrypt"
    echo ""
    echo "This sets up the backend infrastructure certificates:"
    echo "- gRPC server certificate for agent connections"
    echo "- CA certificate for validating agent client certificates"
    echo "- Optional: Let's Encrypt certificates for production"
    exit 1
fi

BACKEND_HOST="$1"
PRODUCTION_MODE="${2:-}"
CERT_DIR="${CERT_DIR:-./certs}"
COUNTRY="${COUNTRY:-US}"
STATE="${STATE:-CA}"
LOCATION="${LOCATION:-San Francisco}"
ORG="${ORG:-Lophiid}"

# Auto-detect current user UID/GID for Docker user mapping
export DOCKER_UID=$(id -u)
export DOCKER_GID=$(id -g)

echo "Setting up BACKEND INFRASTRUCTURE certificates"
echo "=============================================="
echo "Backend host: $BACKEND_HOST"
echo "Mode: ${PRODUCTION_MODE:-development}"
echo "Certificate directory: $CERT_DIR"
echo ""
echo "This backend will host:"
echo "- Backend gRPC server - for agent connections"
echo "- API server - for UI"
echo "- UI - web interface"
echo "- PostgreSQL - database"
echo ""

mkdir -p "$CERT_DIR"/{ca,server}

# Create CA for agent authentication
echo "Creating CA for agent authentication..."
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout "$CERT_DIR/ca/ca-key.pem" \
    -out "$CERT_DIR/ca/ca-cert.pem" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=lophiid-backend-ca"

# Backend gRPC server certificate (for agent connections)
echo "Creating backend gRPC server certificate..."
if [[ "$BACKEND_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # IP address
    SAN="IP:${BACKEND_HOST},DNS:backend,DNS:localhost,IP:127.0.0.1"
else
    # Domain name
    SAN="DNS:${BACKEND_HOST},DNS:backend,DNS:localhost,IP:127.0.0.1"
fi

openssl req -newkey rsa:4096 -nodes \
    -keyout "$CERT_DIR/server/server-key.pem" \
    -x509 -days 365 \
    -CA "$CERT_DIR/ca/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca/ca-key.pem" \
    -out "$CERT_DIR/server/server-cert.pem" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCATION}/O=${ORG}/CN=${BACKEND_HOST}" \
    -addext "subjectAltName = ${SAN}"

# Set permissions
chmod 600 "$CERT_DIR"/ca/ca-key.pem
chmod 600 "$CERT_DIR"/server/server-key.pem
chmod 644 "$CERT_DIR"/ca/ca-cert.pem
chmod 644 "$CERT_DIR"/server/server-cert.pem

# Production mode: Set up for Let's Encrypt (optional)
if [ "$PRODUCTION_MODE" = "production" ]; then
    echo ""
    echo "Production mode detected. Setting up Let's Encrypt certificates..."
    echo "This requires CLOUDFLARE_API_TOKEN, LOPHIID_CERT_DOMAIN, and LOPHIID_CERT_EMAIL"
    echo "to be set in your .env.backend file."
    echo ""
    
    # Check if required environment variables are set
    if [ -f ".env.backend" ]; then
        echo "Checking environment variables from .env.backend..."
        source .env.backend
        
        if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ "$CLOUDFLARE_API_TOKEN" = "REPLACE_WITH_CLOUDFLARE_TOKEN" ]; then
            echo "Warning: CLOUDFLARE_API_TOKEN not set in .env.backend"
        fi
        
        if [ -z "$LOPHIID_CERT_DOMAIN" ] || [ "$LOPHIID_CERT_DOMAIN" = "REPLACE_WITH_YOUR_DOMAIN" ]; then
            echo "Warning: LOPHIID_CERT_DOMAIN not set in .env.backend"
        fi
        
        if [ -z "$LOPHIID_CERT_EMAIL" ] || [ "$LOPHIID_CERT_EMAIL" = "REPLACE_WITH_YOUR_EMAIL" ]; then
            echo "Warning: LOPHIID_CERT_EMAIL not set in .env.backend"
        fi
        
        if [ -n "$CLOUDFLARE_API_TOKEN" ] && [ "$CLOUDFLARE_API_TOKEN" != "REPLACE_WITH_CLOUDFLARE_TOKEN" ] && \
           [ -n "$LOPHIID_CERT_DOMAIN" ] && [ "$LOPHIID_CERT_DOMAIN" != "REPLACE_WITH_YOUR_DOMAIN" ]; then
            echo "Generating Let's Encrypt certificates with Cloudflare DNS validation..."
            # Pass environment variables to Docker Compose
            CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" \
            LOPHIID_CERT_DOMAIN="$LOPHIID_CERT_DOMAIN" \
            LOPHIID_CERT_EMAIL="$LOPHIID_CERT_EMAIL" \
            docker compose -f docker-compose.certs.yml --profile certs up certbot
        else
            echo "Skipping Let's Encrypt setup - environment variables not configured"
            echo "Update .env.backend with your Cloudflare API token and domain, then re-run with production mode"
        fi
    else
        echo "Warning: .env.backend not found. Create it first with certificate configuration."
    fi
    echo ""
    echo "Note: The self-signed certificates created above are for internal gRPC communication"
    echo "between backend and agents. Let's Encrypt certificates would be for public HTTPS traffic."
fi

# Set proper permissions (no ownership changes needed with user mapping)
echo "Setting certificate permissions..."
chmod 600 "$CERT_DIR"/ca/ca-key.pem "$CERT_DIR"/server/server-key.pem 2>/dev/null || true
chmod 644 "$CERT_DIR"/ca/ca-cert.pem "$CERT_DIR"/server/server-cert.pem 2>/dev/null || true

echo ""
echo "✓ Backend infrastructure certificates created successfully!"
echo ""
echo "Generated certificates:"
echo "- CA certificate: $CERT_DIR/ca/ca-cert.pem"
echo "- Backend gRPC server: $CERT_DIR/server/server-cert.pem"
echo ""
echo "Next steps:"
echo "1. Update .env.backend with your backend IP/domain and secure passwords"

if [ "$PRODUCTION_MODE" = "production" ]; then
    echo "2. For PRODUCTION deployment with HTTPS:"
    echo "   - Update LOPHIID_API_BACKEND_ADDRESS=https://$BACKEND_HOST in .env.backend"
    echo "   - Start with production config: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
    echo "   - Access UI at https://$BACKEND_HOST"
    echo "   - Agents with domain names will automatically use Let's Encrypt certificates"
else
    echo "2. For DEVELOPMENT deployment:"
    echo "   - Start backend infrastructure: docker compose up -d" 
    echo "   - Access UI at http://$BACKEND_HOST:9888"
fi

echo "3. Backend gRPC server listening on $BACKEND_HOST:8080 for agent connections"
echo ""
echo "To deploy agents, run:"
echo "  ./scripts/setup-agent-certs.sh $BACKEND_HOST <agent-ip> [agent-name]"