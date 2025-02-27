# Deskflow Nuclei Templates

This directory contains [Nuclei](https://github.com/projectdiscovery/nuclei) templates for testing Deskflow for various security vulnerabilities.

## Prerequisites

- [Nuclei](https://github.com/projectdiscovery/nuclei) installed (Recommended method of installation is via GO)
- Deskflow must be running on the target machine

## How to Run

```bash
# Run all templates against a target
nuclei -t ./ -target <target_ip>:<port>

# Run a specific template
nuclei -t ./deskflow-session-scan.yaml -target <target_ip>:<port>
```

## Available Templates

| Template | Description |
|----------|-------------|
| `deskflow-session-scan.yaml` | Tests for session-related vulnerabilities (CVE-2021-42072) |
| `deskflow-memory-scan.yaml` | Tests for memory corruption vulnerabilities |
| `deskflow-descriptor-scan.yaml` | Tests for descriptor exhaustion vulnerabilities |
| `deskflow-connection-scan.yaml` | Tests for connection flooding vulnerabilities |
| `deskflow-client-verify-scan.yaml` | Tests for client verification vulnerabilities |

## Example

```bash
# Example: Run all templates against localhost
nuclei -t ./ -target 127.0.0.1:24800

# Example: Run session scan against a specific IP
nuclei -t ./deskflow-session-scan.yaml -target 192.168.1.100:24800
```

## Notes

- These templates are designed to test for known vulnerabilities in Deskflow
- Some tests may cause instability in the target application (Specially Connection flooding)
