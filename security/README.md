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
# Test local instance (default)
python deskflow_vulnerability_scanner.py

# Test remote instance
python deskflow_vulnerability_scanner.py --host <target_ip> [--use-ssl] [--port <port>]
```

Common options:
- `--host`: Target hostname or IP (default: localhost)
- `--use-ssl`: Enable SSL/TLS for connections (required for testing TLS-specific vulnerabilities)
- `--port`: Specify custom port (default: 24800)

All scripts support `--help` to show their full usage information.

**⚠️ Warning**: Running all vulnerability tests together via the main scanner (deskflow_vulnerability_scanner.py) can cause severe issues that may require client reinstallation. For safer testing, use the individual test scripts below. (Descriptor exhaustion will definitely break it still. Be careful out there!)

#### Individual Test Scripts

For safer and more targeted testing, use these individual scripts:

```bash
# Test for CVE-2021-42072 (Authentication Bypass)
python cve_2021_42072.py --host <target_ip> [--port <port>]

# Test for CVE-2021-42073 (Memory Corruption)
python cve_2021_42073.py --host <target_ip> [--port <port>]

# Test for CVE-2021-42075 (Descriptor Exhaustion)
python cve_2021_42075.py --host <target_ip> [--port <port>]

# Test for CVE-2021-42076 (Connection Flooding)
python cve_2021_42076.py --host <target_ip> [--port <port>]
```

### Session Vulnerability Testing

For testing session-related vulnerabilities, use the Nuclei template (`deskflow-session-scan.yaml`). The template includes the following test payloads:

```
# Authentication test payloads
b"\x00\x01\x00\x08\x00"                      # Empty client name
b"\x00\x01\x00\x08guest\x00"                 # Guest client name
b"\x00\x01\x00\x08synergy\x00"               # Original project name
b"\x00\x01\x00\x08deskflow\x00"              # Current project name
b"\x00\x01\x00\x08Synergy\x00"               # Case variations
b"\x00\x01\x00\x08Deskflow\x00"
b"\x00\x01\x00\x08SYNERGY\x00"
b"\x00\x01\x00\x08DESKFLOW\x00"
b"\x00\x01\x00\x08" + "A" * 100 + "\x00"     # Long client name
```

These payloads are used to test various aspects of session authentication in Deskflow. To use these payloads with Nuclei:

```bash
nuclei -t nuclei-templates/deskflow-session-scan.yaml -target <target_ip>:<port>
```

These individual scripts are verification tools that complement the Nuclei templates (which are the primary security testing tools). They are 
designed to be run one at a time to prevent client corruption. All scripts use port 24800 by default and support `--help` for detailed usage 
information. When testing a local Deskflow instance, the `--host` parameter can be omitted to use localhost by default.

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
