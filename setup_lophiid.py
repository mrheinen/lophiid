#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path

# Defaults for certificate fields
DEFAULT_COUNTRY = "XX"
DEFAULT_STATE = "State"
DEFAULT_LOCATION = "Location"
DEFAULT_ORG = "Corp"
DEFAULT_CN = "CN"

def run_command(cmd, cwd=None):
    """Run a shell command."""
    try:
        subprocess.run(cmd, check=True, shell=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}")
        sys.exit(1)

def get_cert_subj(args, cn_override=None):
    """Construct the OpenSSL subject string."""
    c = args.cert_country or DEFAULT_COUNTRY
    st = args.cert_state or DEFAULT_STATE
    l = args.cert_location or DEFAULT_LOCATION
    o = args.cert_company or DEFAULT_ORG
    cn = cn_override if cn_override else (args.cert_cn or DEFAULT_CN)
    return f"/C={c}/ST={st}/L={l}/O={o}/CN={cn}"

def confirm(message):
    """Ask user for confirmation."""
    response = input(f"{message} [y/N]: ").strip().lower()
    return response == 'y'

def create_ca(args):
    ca_dir = Path("./docker/certs/ca")
    key_path = ca_dir / "ca-key.pem"
    cert_path = ca_dir / "ca-cert.pem"

    if key_path.exists() or cert_path.exists():
        if not confirm("CA files already exist. Overwrite?"):
            print("Skipping CA creation.")
            return

    print(f"Creating CA in {ca_dir}...")
    ca_dir.mkdir(parents=True, exist_ok=True)

    subj = get_cert_subj(args, cn_override="Lophiid Root CA" if not args.cert_cn else None)

    cmd = (
        f"openssl req -x509 -nodes -days 3650 -newkey rsa:4096 "
        f"-keyout {key_path} -out {cert_path} -subj \"{subj}\""
    )
    run_command(cmd)
    print("CA created successfully.")

def create_backend_certs(args):
    ca_dir = Path("./docker/certs/ca")
    backend_dir = Path("./docker/certs/backend")
    ca_key = ca_dir / "ca-key.pem"
    ca_cert = ca_dir / "ca-cert.pem"

    if not ca_key.exists() or not ca_cert.exists():
        print("Error: CA files not found. Please run with --create-ca first.")
        sys.exit(1)

    if not args.backend_ip:
        print("Error: --backend-ip <IP> is required for backend certs.")
        sys.exit(1)

    if not args.cert_cn:
        print("Error: --cert-cn <CN> is required for backend certs.")
        sys.exit(1)

    print(f"Creating Backend Certs in {backend_dir}...")
    backend_dir.mkdir(parents=True, exist_ok=True)

    key_path = backend_dir / "server-key.pem"
    csr_path = backend_dir / "server.csr"
    cert_path = backend_dir / "server-cert.pem"

    backend_ip = args.backend_ip

    subj = get_cert_subj(args)

    # 1. Create CSR
    cmd_csr = (
        f"openssl req -new -newkey rsa:4096 -nodes "
        f"-keyout {key_path} -out {csr_path} -subj \"{subj}\" "
        f"-addext \"subjectAltName = IP:{backend_ip}\""
    )
    run_command(cmd_csr)

    # 2. Sign CSR
    # Note: Using -copy_extensions copy to ensure SAN is carried over from CSR
    cmd_sign = (
        f"openssl x509 -req -days 365 -in {csr_path} "
        f"-CA {ca_cert} -CAkey {ca_key} -CAcreateserial "
        f"-out {cert_path} -copy_extensions copy"
    )
    run_command(cmd_sign)

    # Cleanup CSR
    if csr_path.exists():
        os.remove(csr_path)

    print(f"Backend certificates created with IP SAN: {backend_ip}")

def create_agent_certs(args):
    if not args.agent_ip:
        print("Error: --agent-ip <IP> is required for agent certs.")
        sys.exit(1)

    ca_dir = Path("./docker/certs/ca")
    agent_dir = Path("./docker/certs/agent")
    ca_key = ca_dir / "ca-key.pem"
    ca_cert = ca_dir / "ca-cert.pem"

    if not ca_key.exists() or not ca_cert.exists():
        print("Error: CA files not found. Please run with --create-ca first.")
        sys.exit(1)

    print(f"Creating Agent Certs for IP {args.agent_ip} in {agent_dir}...")
    agent_dir.mkdir(parents=True, exist_ok=True)

    ip = args.agent_ip
    key_path = agent_dir / f"{ip}-key.pem"
    csr_path = agent_dir / f"{ip}.csr"
    cert_path = agent_dir / f"{ip}-cert.pem"

    subj = get_cert_subj(args, cn_override=ip)

    # 1. Create CSR
    cmd_csr = (
        f"openssl req -new -newkey rsa:4096 -nodes "
        f"-keyout {key_path} -out {csr_path} -subj \"{subj}\""
    )
    run_command(cmd_csr)

    # 2. Sign CSR
    cmd_sign = (
        f"openssl x509 -req -days 365 -in {csr_path} "
        f"-CA {ca_cert} -CAkey {ca_key} -CAcreateserial "
        f"-out {cert_path}"
    )
    run_command(cmd_sign)

    # Cleanup CSR
    if csr_path.exists():
        os.remove(csr_path)

    print(f"Agent certificates created: {key_path}, {cert_path}")

def main():
    parser = argparse.ArgumentParser(description="Swissknife setup script for Lophiid")

    # Action flags
    parser.add_argument("--create-ca", action="store_true", help="Create Certificate Authority")
    parser.add_argument("--create-backend-certs", action="store_true", help="Create Backend Certificates")
    parser.add_argument("--create-agent-certs", action="store_true", help="Create Agent Certificates")

    # Parameters
    parser.add_argument("--agent-ip", help="IP address for the agent certificate")
    parser.add_argument("--backend-ip", help="IP address for the backend certificate SAN")

    # Cert fields
    parser.add_argument("--cert-country", help="Certificate Country (C)")
    parser.add_argument("--cert-state", help="Certificate State (ST)")
    parser.add_argument("--cert-company", help="Certificate Company/Organization (O)")
    parser.add_argument("--cert-location", help="Certificate Location (L)")
    parser.add_argument("--cert-cn", help="Certificate Common Name (CN)")

    args = parser.parse_args()

    if not any([args.create_ca, args.create_backend_certs, args.create_agent_certs]):
        parser.print_help()
        sys.exit(0)

    if args.create_ca:
        create_ca(args)

    if args.create_backend_certs:
        create_backend_certs(args)

    if args.create_agent_certs:
        create_agent_certs(args)

if __name__ == "__main__":
    main()
