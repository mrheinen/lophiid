# Replay CLI Tool

A command-line tool to replay HTTP requests from the database to a honeypot using raw TCP sockets.

## Building

```bash
go build -o replay ./cmd/replay
```

## Usage

```bash
./replay -request-id <id> [options]
```

### Options

- `-config` - Path to the configuration file (default: `backend-config.yaml`)
- `-db` - Database connection string (overrides config)
- `-request-id` - ID of the request to replay (required)
- `-ip` - Override honeypot IP address
- `-port` - Override honeypot port
- `-timeout` - Connection timeout (default: `15s`)
- `-tls` - Use TLS for the connection
- `-insecure` - Skip TLS certificate verification (default: `true`)

### Examples

Replay a request to the original honeypot:
```bash
./replay -config backend-config.yaml -request-id 12345
```

Override the target IP and port:
```bash
./replay -request-id 12345 -ip 192.168.1.100 -port 8080
```

Replay to an HTTPS endpoint:
```bash
./replay -request-id 12345 -tls -port 443
```

Use a direct database connection string:
```bash
./replay -request-id 12345 -db "postgres://user:pass@localhost/lophiid"
```

## Output

Status messages are written to stderr. The raw HTTP response from the honeypot is written to stdout.

To save the response to a file:
```bash
./replay -request-id 12345 > response.txt
```
