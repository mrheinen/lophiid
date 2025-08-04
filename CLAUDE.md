# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Quick Start (Simplified Certificate Setup)
```bash
# 1. Setup backend infrastructure with certificates
./scripts/setup-backend-certs.sh <your-server-ip>
docker compose up -d
# Access UI at http://<your-server-ip>:9888

# 2. Setup and deploy agents
./scripts/setup-agent-certs.sh <backend-ip> <agent-ip> [agent-name]
# Copy the generated agent-<name>/ directory to agent machine
# On agent machine: cd agent-<name>/ && docker compose up -d
# Register agent in backend UI with provided auth token
```

### Building Components
```bash
# Build protobuf files (required before building)
./compile_proto.sh

# Build the backend
bazel build //cmd/backend:backend

# Build the agent  
bazel build //cmd/agent:client

# Build the API server
bazel build //cmd/api:api

# Build the triage service
bazel build //cmd/triage:triage

# Build other utilities
bazel build //cmd/yara:yara          # Yara scanning service
bazel build //cmd/llm:llm            # LLM service
bazel build //cmd/api_client:api_client  # CLI client
```

### Docker Images
All services use consistent Dockerfile naming in the project root:
- `Dockerfile.backend` - Backend service
- `Dockerfile.api` - API server
- `Dockerfile.ui` - UI (Vue.js + nginx)
- `Dockerfile.agent` - Agent service
- `Dockerfile.triage` - Triage service

### Running Tests
```bash
# Run all tests
bazel test //...

# Run tests for specific package
bazel test //pkg/backend:go_default_test
bazel test //pkg/agent:go_default_test
```

### UI Development
```bash
cd ui/
npm install                    # Install dependencies
npm run serve                  # Development server
npm run build                  # Production build
npm run lint                   # Lint Vue files
```

## Architecture Overview

Lophiid is a distributed honeypot system with a **centralized backend** and **remote agents**:

### Deployment Architecture
- **Backend Infrastructure**: Single server running backend, API, UI, and PostgreSQL
- **Remote Agents**: Deployed on separate honeypot machines, connect to backend via gRPC
- **Certificate Security**: Mutual TLS authentication between backend and agents
- **Environment Variables**: All configuration via `.env` files (no YAML configs)

### Core Components

### Backend (`//cmd/backend`)
- Central controller that manages all honeypot agents
- Implements gRPC service defined in `backend_service.proto`
- Handles rule-based content serving and response generation
- Manages PostgreSQL database interactions
- Coordinates with external services (VirusTotal, LLM providers)
- Location: `pkg/backend/`

### Agent (`//cmd/agent`) 
- Lightweight honeypot sensor deployed on remote hosts
- Communicates with backend via gRPC with client certificates
- Handles HTTP requests and forwards to backend for processing
- Can execute commands like ICMP pings and file downloads
- Location: `pkg/agent/`

### API Server (`//cmd/api`)
- REST API layer for UI and CLI interactions
- Provides authenticated access to collected data
- Separate from backend for security isolation
- Location: `pkg/api/`

### UI (`//ui/`)
- Vue 3 application with PrimeVue components
- Provides web interface for viewing attacks, managing rules, etc.
- Communicates with API server via HTTP/HTTPS

### Database Models (`//pkg/database/models`)
- PostgreSQL schema and Go structs
- Key entities: Request, Content, ContentRule, Download, YaraResult
- Database schema: `config/database.sql`

### Configuration Files (`//config/`)
- `database.sql` - PostgreSQL schema initialization
- `nginx.prod.conf` - Production reverse proxy configuration (HTTPS, SSL, API routing)
- `nginx.ui.conf` - UI service nginx configuration

### Rule System
- Content rules define when/how to respond to requests
- Support static content, JavaScript scripts, and AI-generated responses
- Rules stored in `rules/` directory as YAML files
- Flow: Request → Rule matching → Content selection → Response generation

### Key Packages
- `pkg/backend/extractors/`: Extract data from requests (URLs, base64, etc.)
- `pkg/backend/responder/`: Generate responses (LLM integration)
- `pkg/javascript/`: JavaScript execution environment (Goja)
- `pkg/yara/`: Yara-X integration for malware analysis
- `pkg/llm/`: LLM provider abstraction
- `pkg/vt/`: VirusTotal integration

## Configuration & Deployment

Lophiid uses **environment variables** exclusively (12-factor app compliant):

### Two-Tier Architecture
1. **Backend Infrastructure** (one server):
   - `docker-compose.yml` - Backend, API, UI, PostgreSQL
   - `.env.backend` - Contains sensitive configuration
   - Generates certificates with `./scripts/setup-backend-certs.sh`

2. **Remote Agents** (multiple honeypot machines):
   - `docker-compose.agent.yml` - Single agent container
   - Agent-specific `.env.agent` - Contains agent configuration
   - Generated with `./scripts/setup-agent-certs.sh`

### Certificate Management
```bash
# Backend setup (creates CA and backend server cert)
./scripts/setup-backend-certs.sh 192.168.1.100

# Agent setup (creates client cert and deployment package)
./scripts/setup-agent-certs.sh 192.168.1.100 192.168.1.200 web-honeypot
```

### Environment Variable Prefixes
- Backend services: `LOPHIID_*`
- API service: `LOPHIID_API_*`
- UI build: `VUE_APP_*`

## Development Notes

### Dependencies
- Go 1.23+ required
- Bazel for building Go components
- Node.js/npm for UI development
- PostgreSQL for data storage
- libmagic-dev for file type detection
- Yara-X library installation required

### Testing
- 46 test files throughout the codebase
- Use `bazel test` for Go tests
- UI tests via `npm test` (if configured)

### Protocol Buffers
- gRPC service defined in `backend_service.proto`
- Run `./compile_proto.sh` after proto changes
- Generated files: `backend_service/backend_service.pb.go` and `backend_service_grpc.pb.go`

### Common Workflows
1. **Setup new deployment**: Use certificate scripts, then `docker compose up -d`
2. **Deploy new agent**: Run `setup-agent-certs.sh`, copy to agent machine, register in UI
3. **Adding new rule**: Create YAML in `rules/` directory
4. **Modifying response logic**: Edit `pkg/backend/responder/`
5. **Database changes**: Update `pkg/database/models/` and `config/database.sql`
6. **UI changes**: Work in `ui/src/`, use `npm run serve` for development