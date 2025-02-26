# Deskflow Security Scripts

This directory contains security testing scripts and templates for Deskflow.

## Python Security Scripts

These scripts are designed to test Deskflow for various security vulnerabilities.

### Prerequisites

- Python 3.9+
- Deskflow must be running when executing these scripts

### How to Run

1. Start Deskflow on the target machine
2. Run the scripts with the target host as an argument

#### Main Vulnerability Scanner

```bash
python deskflow_vulnerability_scanner.py --host <target_ip>
```

Additional options:
- `--port <port>` - Specify a custom port (default: 24800)
- `--ssl` - Use SSL for the connection
- `--all` - Run all available scans
- `--session` - Run session vulnerability scan
- `--memory` - Run memory vulnerability scan
- `--descriptor` - Run descriptor vulnerability scan
- `--connection` - Run connection vulnerability scan
- `--client-verify` - Run client verification scan
- `--tls` - Run TLS vulnerability checks
- `--mitm` - Test for MITM vulnerabilities
- `--timing` - Check for timing attacks

#### CVE-Specific Scanners

```bash
# Test for CVE-2021-42072 (Authentication Bypass)
python cve_2021_42072.py --host <target_ip>

# Test for CVE-2021-42073 (Memory Corruption)
python cve_2021_42073.py <target_ip>

# Test for CVE-2021-42075 (Descriptor Exhaustion)
python cve_2021_42075.py <target_ip>

# Test for CVE-2021-42076 (Connection Flooding)
python cve_2021_42076.py <target_ip>
```

## Nuclei Templates

The `nuclei-templates` directory contains templates for use with the [Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner.

### Prerequisites

- Nuclei installed (https://github.com/projectdiscovery/nuclei)

### How to Run

```bash
# Run all templates
nuclei -t nuclei-templates/ -target <target_ip>:<port>

# Run a specific template
nuclei -t nuclei-templates/deskflow-session-scan.yaml -target <target_ip>:<port>
```

Available templates:
- `deskflow-session-scan.yaml` - Tests for session-related vulnerabilities
- `deskflow-memory-scan.yaml` - Tests for memory corruption vulnerabilities
- `deskflow-descriptor-scan.yaml` - Tests for descriptor exhaustion vulnerabilities
- `deskflow-connection-scan.yaml` - Tests for connection flooding vulnerabilities
- `deskflow-client-verify-scan.yaml` - Tests for client verification vulnerabilities 
