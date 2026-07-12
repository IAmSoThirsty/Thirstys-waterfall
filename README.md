<div align="right">
  <img src="https://img.shields.io/badge/Date-2026--03--10-blue?style=for-the-badge" alt="Date" />
  <img src="https://img.shields.io/badge/Status-Standard%20v3%20In%20Progress-yellow?style=for-the-badge" alt="Status" />
  <img src="https://img.shields.io/badge/Tier-Master-gold?style=for-the-badge" alt="Tier" />
</div>

# Thirstys-waterfall

**Thirstys Waterfall** - Deployment-Gated Integrated Privacy-First System

## Standard v3 Evidence-Gated Privacy System

A comprehensive privacy-first system that is being completed toward 8 firewall types, a **built-in VPN**, and an incognito browser with encrypted privacy controls. This repository now has local deployment-smoke evidence, but broad deployment and all-platform claims remain gated by the Standard v3 acceptance matrix.

> **Standard v3 acceptance status:** This repository is under active completion toward the claims in this README. The current acceptance plan, verified evidence, and blockers are tracked in [docs/operations/README_CLAIM_ACCEPTANCE.md](docs/operations/README_CLAIM_ACCEPTANCE.md). Final deployment claims are not accepted as complete until that matrix is green.

### Capability Targets and Current Evidence

| Area | Standard v3 status | Evidence now present | Remaining acceptance work |
| --- | --- | --- | --- |
| Encryption and private data handling | Not accepted | Crypto helpers, encrypted storage helpers, and privacy-ledger components exist | End-to-end proof for browser state, logs, downloads, configuration, storage, and transport paths |
| 8 firewall categories | Partial | Firewall modules and backend tests exist; web status now fails closed when backend status is unavailable | Real rule apply/rollback evidence per supported OS or narrowed platform claims |
| Built-in VPN direction | Partial | Backend modules and tests exist; command paths are resolved before availability is reported; web connect/disconnect no longer fabricate success | Real OS connection/disconnection evidence, privilege requirements, and rollback behavior |
| Native browser engine | Partial | Native document/parser/fetcher/layout layer and local network navigation/session compatibility tests exist | Broader rendering coverage and supported-site acceptance evidence |
| Privacy/security engines | Partial | Modules and focused tests exist for multiple privacy/security subsystems | Add configured backend evidence and end-to-end acceptance evidence |
| Kill switch | Partial | Kill-switch modules and orchestration paths exist | Prove real network blocking and rollback behavior on supported platforms |

## New and Advanced Feature Areas

The sections below identify implemented modules, demos, and intended capability areas. They are not final Standard v3 acceptance claims unless the acceptance matrix marks the related row accepted.

### 🎯 Thirsty Consigliere - Privacy-First AI Assistant

Privacy-assistant direction: privacy as a first-class contract, not a vibe.

#### Core Principles:

- **Data Minimization**: Collect only what is strictly needed
- **No Training on User Data**: target behavior for local/private inference paths
- **On-Device Inference**: No external API calls by default
- **Zero "Accept All"**: Everything locked down by default
- **Transparency**: data-flow visibility remains acceptance work

#### Features:

- ✅ Capability system with explicit user permissions
- ✅ Action ledger with one-click deletion
- ✅ Privacy audit checklist
- ✅ Fine-grained permission toggles
- ✅ Ephemeral context windows (memory only)
- ✅ Privacy-preserving local-assistant direction

[Learn more →](docs/NEW_FEATURES.md#thirsty-consigliere)

### 🔐 Multi-Factor Authentication (MFA)

MFA module with multiple authentication methods and risk-based escalation paths.

#### Authentication Methods:

- **TOTP** (Time-based One-Time Password) - RFC 6238 compliant
- **FIDO2/WebAuthn** - Hardware security keys
- **Passkeys** - Passwordless authentication
- **X.509 Certificates** - Client certificate authentication
- **Biometric** - Fingerprint, Face ID, Iris scanning

#### Security Features:

- Context-aware authentication requirements
- Risk-based dynamic escalation
- Session management with automatic timeouts
- Comprehensive audit logging
- Privacy Risk Engine integration

[Learn more →](docs/mfa_authentication.md)

### 🖥️ MicroVM Isolation

MicroVM isolation module intended to isolate browser tabs, extensions, and sessions using Firecracker, QEMU, or compatible backends where available.

#### Capabilities:

- **Hard Process Separation**: Complete VM-level isolation
- **Micro-Segmentation**: Network-isolated VMs
- **Resource Management**: Per-VM CPU, memory, disk limits
- **Multiple Backends**: Firecracker, QEMU, Cloud Hypervisor
- **Health Monitoring**: Continuous monitoring and metrics

#### Use Cases:

- Isolate untrusted browser tabs
- Sandbox browser extensions
- Separate browsing sessions
- Plugin isolation

[Learn more →](docs/microvm_isolation.md)

### DOS Trap Mode - System Compromise Detection

Compromise-detection and automated-response module. Some low-level response paths still require real platform evidence.

#### Detection:

- **Rootkit Detection** - Kernel module scanning
- **Kernel Anomaly Detection** - System call integrity
- **Process Injection Detection** - Hidden process identification
- **Hardware Attestation Monitoring** - TPM/Secure Enclave integration

#### Response:

- **Secret Wiping** - Master key destruction
- **Hardware Key Destruction** - TPM/HSM key removal
- **Interface Isolation** - Network/USB interface disabling
- **Memory Sanitization** - Multi-pass secure wiping (DoD 5220.22-M, Gutmann)
- **Disk Sanitization** - Secure file deletion

[Learn more →](docs/DOS_TRAP_MODE.md)

### 📋 Privacy Accountability Ledger

Encrypted audit logging with integrity checks and zero-knowledge direction.

#### Security:

- **Zero-Knowledge Direction** - Dual-layer encryption helpers (Fernet + AES-256-GCM)
- **Tamper Detection** - SHA-512 cryptographic hashing
- **Merkle Tree Verification** - O(log n) integrity proofs
- **Atomic Writes** - ACID guarantees with WAL
- **Thread-Safe** - Full concurrency support

#### Features:

- Structured event logging with severity levels
- Efficient indexed search (user, type, time)
- Compliance-ready audit exports (GDPR, HIPAA, SOC2)
- Configurable retention policies
- Forensic resistance with secure data wiping

[Learn more →](docs/privacy_ledger.md)

### Advanced Network Stealth

Network anonymization and censorship-circumvention module.

#### Pluggable Transports:

- **obfs4** - Obfuscated bridge protocol
- **meek** - Domain fronting transport
- **snowflake** - WebRTC-based transport
- **HTTP/3** - QUIC-based protocol
- **WebSocket** - HTTP(S) tunneling

#### Obfuscation:

- Traffic padding and timing randomization
- Protocol mimicry (HTTP, TLS, DNS, BitTorrent, Gaming)
- Traffic shaping and fragmentation
- Domain fronting via major CDNs

#### Features:

- Per-request onion routing
- Dynamic circuit selection
- Comprehensive metrics and monitoring
- Multiple transport and obfuscation strategies

[Learn more →](docs/network_stealth.md)

### Media Downloader

Multi-mode media downloader with encrypted-library direction.

#### Features:

- Audio-only, video-only, audio+video, best quality modes
- Built-in encrypted media library
- Format conversion
- Metadata encryption helpers
- Download encryption support remains part of Standard v3 data-path acceptance work

### Local AI Assistant

Local AI-assistant direction with no external API calls by default.

#### Features:

- On-device inference (no external API calls)
- Local privacy-preserving inference direction
- Zero-data-collection target for local inference paths
- Text generation, code assistance, problem solving

### 🖥️ Remote Access - Browser & Desktop

Remote-access module with secure-tunnel direction.

#### Features:

- Remote browser direction with encrypted transport support
- Remote desktop streaming direction
- Secure tunnel through VPN
- Multi-hop VPN routing remains acceptance-gated

### Ad Annihilator - Ad and Tracker Blocking

Ad and tracker blocking module.

#### Features:

- Rule-based ad blocking
- 1000+ ad domains blocked
- Tracker blocking
- Pop-up blocking
- Autoplay blocking
- Malvertising protection
- Cryptomining prevention

### ⚙️ Comprehensive Settings System

13 setting categories covering all aspects of the system:

1. General, 2. Privacy, 3. Security, 4. Browser
1. Ad Blocker, 6. Consigliere, 7. Media Downloader
1. AI Assistant, 9. Remote Access, 10. Network
1. Firewalls, 12. Support, 13. Advanced

### 💬 Support System

- Q/A System with knowledge base
- Contact threads (improvements, features, security, code of conduct)
- Feedback manager (all encrypted)

## 📦 Installation

### Quick Install

#### Using Installer Scripts (Recommended)

**Linux/macOS:**

```bash

# Clone repository

git clone https://github.com/IAmSoThirsty/Thirstys-waterfall.git
cd Thirstys-waterfall

# Run installer

bash install.sh
```

**Windows:**

```batch

# Clone repository

git clone https://github.com/IAmSoThirsty/Thirstys-waterfall.git
cd Thirstys-waterfall

# Run installer

install.bat
```

#### Using pip

```bash

# Install from PyPI (when published)

pip install thirstys-waterfall

# Or install from source

git clone https://github.com/IAmSoThirsty/Thirstys-waterfall.git
cd Thirstys-waterfall
pip install -e .
```

#### Using Docker

```bash

# Using Docker Compose (recommended)

docker-compose up -d

# Or build and run directly

docker build -t thirstys-waterfall .
docker run -d --name thirstys-waterfall \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v thirstys_data:/home/thirsty/.thirstys_waterfall \
  thirstys-waterfall
```

### Manual Installation

```bash

# Clone repository

git clone https://github.com/IAmSoThirsty/Thirstys-waterfall.git
cd Thirstys-waterfall

# Install dependencies

pip install -r requirements.txt

# Install package

pip install -e .
```

### Platform-Specific Requirements

#### Linux

```bash

# For full VPN and firewall functionality

sudo apt-get install wireguard-tools openvpn nftables strongswan
```

#### Windows

- Download [WireGuard for Windows](https://www.wireguard.com/install/)
- Download [OpenVPN for Windows](https://openvpn.net/community-downloads/)
- Windows Firewall is built-in

#### macOS

```bash

# For full VPN functionality

brew install wireguard-tools openvpn

# PF (Packet Filter) is built into macOS

```

## 🚀 Quick Start

### Python API

```python
from thirstys_waterfall import ThirstysWaterfall

# Initialize system

waterfall = ThirstysWaterfall()

# Start configured subsystems

waterfall.start()

# Create encrypted browser tab

tab_id = waterfall.browser.create_tab()

# Navigate with the current browser engine implementation

waterfall.browser.navigate(tab_id, "https://example.com")

# Perform a search through the configured search path

results = waterfall.browser.search("my search query")

# Get system status

status = waterfall.get_status()
print(f"Encryption Status: {status['everything_encrypted']}")
print(f"VPN Backend Configured: {status['vpn']['built_in']}")
print(f"VPN Connected: {status['vpn']['connected']}")

# Run privacy audit

audit = waterfall.run_privacy_audit()

# Stop configured subsystems

waterfall.stop()
```

### Command Line

```bash

# Start system

thirstys-waterfall --start

# Show status

thirstys-waterfall --status

# Run privacy audit

thirstys-waterfall --audit

# Use custom config

thirstys-waterfall --config config.json --start
```

## 📋 Configuration

See `examples/config.json` for full configuration options.

```json
{
  "global": {
    "privacy_mode": "maximum",
    "kill_switch_enabled": true
  },
  "vpn": {
    "enabled": true,
    "multi_hop": true,
    "hop_count": 3,
    "kill_switch": true
  },
  "browser": {
    "incognito_mode": true,
    "no_history": true,
    "no_cache": true,
    "no_cookies": true
  }
}
```

## 🚀 Deployment Verification

Thirstys Waterfall currently has **release and local deployment-smoke verification**, not final target-host Production Deployment Verified status. The verifier runs tests, syntax gates, Bandit, Safety against the deployment lock, wheel build, local web health/auth smoke, Docker Compose config validation, Docker image build, Docker container health/auth smoke, and local rollback smoke. Release `v1.0.2` also pushed a verified GHCR image that was pulled and smoke-tested locally.

```powershell
python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"
```

See [Production Deployment Verification](docs/operations/PRODUCTION_DEPLOYMENT_VERIFICATION.md) and the [README Claim Acceptance Matrix](docs/operations/README_CLAIM_ACCEPTANCE.md) for current evidence and blockers.

### Deployment Methods

1. **Docker Deployment** (verified release-image smoke path)

   - Locked deployment dependencies through `requirements-deploy.lock`
   - Docker Compose orchestration
   - Health checks and resource limits
   - Non-root user security
   - GHCR release image pull, container smoke, and local rollback smoke verified

1. **Python Package**

   - Standard Python package metadata
   - Simple `pip install` deployment
   - Local wheel build verified

1. **Systemd Service** (planned Linux server path)

   - Native systemd integration still requires target-host evidence
   - Automatic startup and restart
   - System-level security hardening

1. **Windows Service** (planned Windows server path)

   - Native Windows service support still requires target-host evidence
   - Automatic startup configuration

### Quick Production Deploy

```bash

# Docker local smoke

docker-compose up -d

# Linux systemd

sudo systemctl enable thirstys-waterfall
sudo systemctl start thirstys-waterfall

# Check status

docker ps  # Docker
sudo systemctl status thirstys-waterfall  # Systemd
```

### Packaging & Distribution

- ✅ **Local wheel build verified**: Standard Python packaging with `pyproject.toml`
- ✅ **Local Docker image build verified**: Container starts and passes health/auth smoke
- ✅ **GitHub Release verified**: `v1.0.2` published with wheel and source artifacts
- ✅ **GHCR image verified**: `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2` published with digest `sha256:4095d4d28f4d39aa9859783d2a9f170be919aba0435061f3d6ee9b3af95db059`
- ⚠️ **Target-host deployment not yet accepted**: production host logs, secret rotation, target rollback, and host network policy evidence are still required
- ⚠️ **Platform backend support not yet accepted**: real VPN/firewall execution evidence is still required beyond availability tests

📖 **[Deployment Verification Guide →](docs/operations/PRODUCTION_DEPLOYMENT_VERIFICATION.md)**

## 🎯 Use Cases

- **Privacy-focused browsing research** - native browser direction, privacy controls, and acceptance-gated data handling
- **Secure research workflows** - encrypted storage/search direction with remaining end-to-end proof work
- **Anonymous communication direction** - multi-hop VPN and onion-routing modules with remaining real backend evidence
- **Threat-protection direction** - firewall categories, malware detection modules, and backend proof work
- **Leak-reduction direction** - kill switch and leak-detection modules with remaining platform proof
- **Pop-up/redirect controls** - browser-control modules with remaining acceptance coverage

## 🔬 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Thirstys Waterfall Orchestrator                     │
│                 STANDARD V3 EVIDENCE-GATED RUNTIME                  │
│                  CAPABILITIES TRACKED BY ACCEPTANCE MATRIX           │
└─────────────────────────────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
   ┌────▼────┐              ┌────▼────┐              ┌────▼────┐
   │ 8 Types │              │ Built-In│              │ Browser │
   │Firewalls│              │   VPN   │              │Encrypted│
   └─────────┘              └─────────┘              └─────────┘
        │                         │                         │
   Rule Control             Backend Control          Native Engine
   Evidence Needed          Evidence Needed          Evidence Needed
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
        ┌─────────────────────────┴─────────────────────────┐
        │                                                     │
   ┌────▼────────┐  ┌─────────────┐  ┌──────────────┐  ┌────────────┐
   │ Advanced    │  │   Privacy   │  │   Security   │  │ AI & Media │
   │ Features    │  │   Systems   │  │   Systems    │  │  Systems   │
   └─────────────┘  └─────────────┘  └──────────────┘  └────────────┘
        │                  │                 │                  │
   • Consigliere    • Ledger         • MFA Auth        • AI Assistant
   • Network        • Anti-Track     • DOS Trap        • Media DL
     Stealth        • Anti-Malware   • MicroVM         • Remote Access
   • AD             • Onion Router     Isolation       • Settings
     Annihilator                      • HW Root of
                                        Trust
```

### Component Overview

#### Core Layer

- **Orchestrator**: Coordinates configured subsystems with kill-switch paths
- **8 Firewall Categories**: packet-filtering, circuit-level, stateful, proxy, NGFW, software, hardware, cloud
- **Built-in VPN Direction**: backend orchestration for WireGuard, OpenVPN, and IKEv2 where supported
- **Privacy Browser**: native browser-engine direction with incognito/session controls

#### Advanced Features Layer

- **Thirsty Consigliere**: Privacy-first local assistant direction
- **Network Stealth**: Pluggable transports, domain fronting, protocol mimicry
- **Ad Annihilator**: Ad and tracker blocking

#### Privacy Systems Layer

- **Privacy Ledger**: Immutable encrypted audit logs with Merkle tree verification
- **Anti-Tracking**: Blocks all known trackers
- **Anti-Malware**: Real-time scanning
- **Onion Router**: Tor-like routing with per-request circuits

#### Security Systems Layer

- **MFA Authentication**: TOTP, FIDO2, Passkeys, Biometrics, X.509
- **DOS Trap Mode**: Rootkit detection, compromise response, secret wiping
- **MicroVM Isolation**: Hardware-level process separation with Firecracker/QEMU
- **Hardware Root of Trust**: TPM, Secure Enclave, HSM integration

#### AI & Media Systems Layer

- **AI Assistant**: On-device inference with local helper encryption
- **Media Downloader**: Multi-mode with encrypted library
- **Remote Access**: Secure browser and desktop streaming
- **Settings System**: 13 comprehensive categories

### 🔍 Implementation Proof

**Run the demo to see concrete implementations in action:**

```bash
python examples/concrete_implementation_demo.py
```

This demo shows:

- Real VPN backend detection (WireGuard, OpenVPN, IKEv2)
- Real firewall backend detection (nftables, Windows Firewall, PF)
- Platform-specific integration details
- Actual command-line tools used for each platform

**Example output on Linux:**

```
Available VPN backends on this system: ['ikev2']
Available firewall backends on this system: ['nftables']
Platform-specific firewall backend: NftablesBackend
```

### 📚 Feature Demonstrations

Each major feature has a dedicated demonstration script:

```bash

# MFA Authentication

python examples/mfa_authentication_example.py

# MicroVM Isolation

python examples/microvm_isolation_demo.py

# DOS Trap Mode

python examples/dos_trap_demo.py

# Privacy Ledger

python examples/privacy_ledger_examples.py

# Advanced Network Stealth

python examples/advanced_stealth_demo.py

# Hardware Root of Trust

python examples/hardware_root_of_trust_security_demo.py

# Basic usage

python examples/basic_usage.py

# Advanced usage with all features

python examples/advanced_usage.py

# Complete integrated usage

python examples/complete_usage.py
```

### 📊 Local Verification Evidence

#### Local Test Coverage

```bash

# Run all unit tests

python -m unittest discover -s tests -p "test_*.py" -v

# Specific test suites

python -m unittest tests.test_vpn_backends -v
python -m unittest tests.test_firewall_backends -v
python -m unittest tests.test_mfa_auth -v
python -m unittest tests.test_microvm_isolation -v
python -m unittest tests.test_dos_trap -v
python -m unittest tests.test_privacy_ledger -v
```

#### ✅ Backend Verification

```bash

# Check available VPN backends on your system

python -c "from thirstys_waterfall.vpn.backends import VPNBackendFactory; print(VPNBackendFactory.get_available_backends())"

# Check available firewall backends on your system

python -c "from thirstys_waterfall.firewalls.backends import FirewallBackendFactory; print(FirewallBackendFactory.get_available_backends())"
```

#### Current Documentation

- [Architecture](docs/ARCHITECTURE.md) - System architecture
- [Competition Comparison](docs/COMPETITION_COMPARISON.md) - Evidence-gated capability comparison
- [Threat Model](THREAT_MODEL.md) - Security architecture and limitations
- [Security Policy](SECURITY.md) - Security practices and incident response
- [New Features](docs/NEW_FEATURES.md) - Latest feature additions
- [Showcase](docs/SHOWCASE.md) - Current evidence and remaining gaps
- [Encryption Evidence Map](docs/operations/ENCRYPTION_EVIDENCE_MAP.md) - Data-surface encryption evidence and gaps
- [Platform Capabilities](docs/operations/PLATFORM_CAPABILITIES.md) - OS-specific capability boundaries

## 🎯 Platform Support

### Cross-Platform Implementation Status

Thirstys Waterfall contains backend implementations and availability checks for major platforms. `thirstys_waterfall.get_platform_capabilities()` reports the current OS-specific VPN, firewall, service, and privilege boundaries while keeping `production_accepted: false`. Standard v3 acceptance still requires real execution evidence for VPN/firewall apply, rollback, and privilege behavior on each supported OS.

#### VPN Backends

- **Linux**: WireGuard (wg-quick), OpenVPN, strongSwan (IKEv2)
- **Windows**: WireGuard for Windows, OpenVPN GUI, Native IKEv2
- **macOS**: WireGuard, OpenVPN, Native IKEv2/IPSec

#### Firewall Backends

- **Linux**: nftables integration (modern netfilter)
- **Windows**: Windows Firewall API (netsh advfirewall)
- **macOS**: PF (Packet Filter) via pfctl

Current backend coverage includes platform detection, command resolution, protocol fallback paths, and unit/integration tests. Real handshake, rule application, rollback, and platform privilege evidence remain acceptance work.

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed security architecture and limitations.

## 🛡️ Security Features

### Core Security

- **Encryption Direction** - crypto and storage helpers exist; end-to-end data-path proof remains required
- **Zero-Knowledge Direction** - no-plaintext storage claims require acceptance evidence
- **Forensic Resistance Direction** - secure wiping modules exist; real platform evidence remains required
- **Kill Switch** - protection paths exist; real network-blocking proof remains required
- **Logging Policy Direction** - no-logging claims require end-to-end audit evidence
- **Anti-Fingerprinting** - randomized browser fingerprint module
- **Leak Protection** - DNS, IPv6, and WebRTC protection modules

### Advanced Security Features

- **Secret Management** - No hardcoded secrets, environment-based configuration
- **Hardware Root of Trust** - TPM, Secure Enclave, HSM integration
- **DOS Trap Mode** - Advanced compromise detection and response
- **Multi-Factor Authentication** - TOTP, FIDO2, Passkeys, Biometrics, X.509
- **MicroVM Isolation** - Hardware-level process separation
- **Privacy Accountability Ledger** - Immutable, encrypted audit logs
- **Advanced Network Stealth** - Pluggable transports, domain fronting, obfuscation

### 🔐 Threat Model & Security Architecture

**See [THREAT_MODEL.md](THREAT_MODEL.md) for security documentation:**

- Threat actors and attack scenarios we defend against
- What we protect and what's out of scope
- Encryption architecture and key management
- Security assumptions and limitations
- Incident response procedures
- Honest assessment of current capabilities vs. roadmap

### 🔐 Secret Management

This project follows strict security practices for secret management:

- **Never hardcode secrets** in source code
- Load all secrets from **environment variables** or **secure vaults**
- See [SECURITY.md](SECURITY.md) for complete guidelines
- See [.env.example](.env.example) for configuration template

For detailed security policies, incident response, and secret rotation procedures, refer to our [Security Policy](SECURITY.md).

## 📚 Examples

### Basic Examples

- `basic_usage.py` - Simple usage example
- `complete_usage.py` - Complete feature demonstration
- `advanced_usage.py` - Advanced features demonstration

### Security & Privacy Examples

- `mfa_authentication_example.py` - Multi-factor authentication
- `microvm_isolation_demo.py` - MicroVM isolation
- `dos_trap_demo.py` - DOS trap mode and compromise detection
- `privacy_ledger_examples.py` - Privacy accountability ledger
- `hardware_root_of_trust_security_demo.py` - Hardware security

### Network & Stealth Examples

- `advanced_stealth_demo.py` - Network stealth and obfuscation
- `concrete_implementation_demo.py` - Backend verification

### Configuration

- `config.json` - Configuration template

Examples are development and verification aids. Standard v3 acceptance for each feature is tracked in [docs/operations/README_CLAIM_ACCEPTANCE.md](docs/operations/README_CLAIM_ACCEPTANCE.md).

## 🧪 Testing & CI

### Continuous Integration

[![CI Status](https://github.com/IAmSoThirsty/Thirstys-waterfall/actions/workflows/ci.yml/badge.svg)](https://github.com/IAmSoThirsty/Thirstys-waterfall/actions)

Automated testing across multiple platforms:

- **Unit Tests**: All core components tested
- **Integration Tests**: backend command construction, browser behavior, auth, MicroVM lifecycle, privacy ledger, and security components
- **Platform Tests**: Linux (Ubuntu), Windows, macOS in CI workflow configuration; external run evidence is still required for acceptance
- **Python Versions**: 3.10, 3.11
- **Security Scans**: Bandit, Safety, dependency checks

### Run Tests Locally

```bash

# Run all tests

python -m pytest -q

# Run specific test suites

python -m pytest tests/test_vpn_backends.py -q
python -m pytest tests/test_firewall_backends.py -q

# Check VPN backend availability on your system

python -c "from thirstys_waterfall.vpn.backends import VPNBackendFactory; print(VPNBackendFactory.get_available_backends())"

# Check firewall backend availability on your system

python -c "from thirstys_waterfall.firewalls.backends import FirewallBackendFactory; print(FirewallBackendFactory.get_available_backends())"
```

### Test Coverage

The current test suite includes:

- ✅ **VPN Backend Tests**: command construction, availability checks, and protocol fallback paths
- ✅ **Firewall Backend Tests**: command construction and platform backend selection
- ✅ **Platform Detection**: backend selection per OS
- ✅ **Connection Resilience Paths**: reconnection and error-handling coverage
- ✅ **MFA Authentication**: provider and risk-escalation coverage
- ✅ **MicroVM Isolation**: lifecycle, resource management, and health-monitoring coverage
- ✅ **DOS Trap Mode**: compromise-detection and response-path coverage
- ✅ **Privacy Ledger**: encryption, integrity, and audit-workflow coverage
- ✅ **Network Stealth**: transport and obfuscation module coverage

Real OS VPN/firewall execution evidence remains separate from CI unit/integration coverage.

### Continuous Integration

The CI workflow is configured for:

- **Platforms**: Linux (Ubuntu), Windows, macOS
- **Python Versions**: 3.10, 3.11
- **Tests**: Unit tests, integration tests, platform tests
- **Security Scans**: Bandit, Safety, dependency checks

View the [CI workflow results](https://github.com/IAmSoThirsty/Thirstys-waterfall/actions)

## 🎖️ Feature Summary

### What Sets Thirstys Waterfall Apart

Thirstys Waterfall is being built as a comprehensive privacy ecosystem that integrates features typically found in multiple separate products. Claims below are target capabilities until accepted in the Standard v3 matrix.

#### All-in-One Direction

- **8 firewall categories** represented in code, with real rule evidence still required
- **Built-in VPN direction** with backend orchestration, with real OS execution evidence still required
- **Privacy browser direction** with a native document/parser/fetcher layer, with rendering/session acceptance still required
- **Multi-factor authentication** module with several provider paths
- **MicroVM isolation** module with backend-specific acceptance still required
- **Advanced network stealth** module with multiple transport strategies
- **Encryption/privacy helpers** that still require end-to-end data-path proof

#### Security Feature Areas

- **DOS Trap Mode**: Rootkit detection and automated response
- **Hardware Root of Trust**: TPM, Secure Enclave, HSM integration
- **MicroVM Isolation**: Firecracker/QEMU browser tab sandboxing
- **Privacy Accountability Ledger**: Immutable encrypted audit logs
- **Advanced Network Stealth**: Domain fronting, protocol mimicry
- **Forensic Resistance**: DoD 5220.22-M and Gutmann secure wiping

#### Cost and Packaging

- **Thirstys Waterfall source**: available under this repository's license.
- **Local install path**: source install and local wheel build are verified.
- **Container path**: release image publication and local published-image smoke are verified.
- **Target deployment cost**: depends on the user's host, runtime, and operating model.

#### Feature Count and Encryption Claims

Feature-count and encryption-strength comparisons are not accepted Standard v3 evidence. The accepted source of truth is the claim matrix, which separates implemented helpers, tests, and remaining end-to-end proof.

### Production Readiness Status

Current accepted evidence includes local tests, hosted Linux/Windows/macOS CI, CodeQL, production-mode secret/CORS startup checks, local wheel build, release wheel/source artifacts, full-repo Bandit, locked dependency vulnerability check, local web smoke, Docker Compose config validation, Docker image build, release workflow Docker smoke, GHCR push, published image pull, published image container smoke, local container log capture, and local Docker rollback smoke. Full target-host Production Deployment Verified status still requires target rollback evidence, production host logs, secrets rotation evidence, host network policy evidence, and platform proof for real VPN/firewall backend execution.

### Proof of Implementation

Current proof surfaces:

- **Deployment Verification Script** - `scripts/verify_production_deployment.py`
- **Backend Verification Scripts** - Check available VPN/firewall backends
- **Feature Demonstrations** - example scripts for local inspection
- **Tests** - unit/integration coverage for current components
- **CI Pipeline** - Automated testing on every commit
- **Documentation** - Detailed docs for every major feature

Run `python examples/concrete_implementation_demo.py` to see platform-specific implementations in action.

## 🤝 Contributing

This is a security-critical project. Contributions should preserve Standard v3 evidence discipline and avoid claiming acceptance before proof exists.

## 📄 License

MIT License - See LICENSE file

## ⚠️ Disclaimer

This is a privacy and security tool. Use responsibly and in accordance with applicable laws.

______________________________________________________________________

**Built with 🔒 by the Thirsty Security Team**
