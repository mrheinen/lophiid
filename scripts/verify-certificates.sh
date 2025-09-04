#!/bin/bash
# Certificate Verification Script
# Verifies that Let's Encrypt certificates are properly integrated

set -e

CERT_DIR="${CERT_DIR:-./certs}"

echo "Lophiid Certificate Verification"
echo "================================"
echo ""

# Check if Let's Encrypt certificates exist
if [ -f "$CERT_DIR/live/lophiid-backend/fullchain.pem" ] && [ -f "$CERT_DIR/live/lophiid-backend/privkey.pem" ]; then
    echo "✓ Let's Encrypt certificates found"
    
    # Get certificate details
    CERT_SUBJECT=$(openssl x509 -in "$CERT_DIR/live/lophiid-backend/fullchain.pem" -noout -subject 2>/dev/null | sed 's/subject= //')
    CERT_ISSUER=$(openssl x509 -in "$CERT_DIR/live/lophiid-backend/fullchain.pem" -noout -issuer 2>/dev/null | sed 's/issuer= //')
    CERT_DATES=$(openssl x509 -in "$CERT_DIR/live/lophiid-backend/fullchain.pem" -noout -dates 2>/dev/null)
    
    echo "  Subject: $CERT_SUBJECT"
    echo "  Issuer: $CERT_ISSUER"
    echo "  $CERT_DATES"
    echo ""
else
    echo "! Let's Encrypt certificates not found"
    echo "  Run: ./scripts/setup-backend-certs.sh <domain> production"
    echo ""
fi

# Check self-signed certificates
if [ -f "$CERT_DIR/ca/ca-cert.pem" ] && [ -f "$CERT_DIR/server/server-cert.pem" ]; then
    echo "✓ Self-signed certificates found (for internal gRPC)"
    
    CA_SUBJECT=$(openssl x509 -in "$CERT_DIR/ca/ca-cert.pem" -noout -subject 2>/dev/null | sed 's/subject= //')
    SERVER_SUBJECT=$(openssl x509 -in "$CERT_DIR/server/server-cert.pem" -noout -subject 2>/dev/null | sed 's/subject= //')
    
    echo "  CA: $CA_SUBJECT"
    echo "  Server: $SERVER_SUBJECT"
    echo ""
else
    echo "! Self-signed certificates not found"
    echo "  Run: ./scripts/setup-backend-certs.sh <ip-or-domain>"
    echo ""
fi

# Check docker-compose configuration
if [ -f "docker-compose.prod.yml" ]; then
    if grep -q "nginx:" docker-compose.prod.yml; then
        echo "✓ Production nginx reverse proxy configured"
    else
        echo "! Production nginx reverse proxy not found in docker-compose.prod.yml"
    fi
    
    if grep -q "/etc/letsencrypt" docker-compose.prod.yml; then
        echo "✓ Let's Encrypt certificate volume mount configured"
    else
        echo "! Let's Encrypt certificate volume mount not configured"
    fi
else
    echo "! docker-compose.prod.yml not found"
fi

echo ""
echo "Certificate verification complete."
echo ""
echo "For production deployment:"
echo "1. Ensure Let's Encrypt certificates are present"
echo "2. Use: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
echo "3. Access UI at https://your-domain.com"