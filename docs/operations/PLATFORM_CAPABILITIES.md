# Platform Capabilities

Status: Standard v3 evidence surface, not production acceptance.

This file documents the platform-specific capability differences currently
represented by the code. It does not prove target-host production readiness.
`thirstys_waterfall.get_platform_capabilities()` reports
`production_accepted: false` for every platform until real VPN, firewall,
privilege, service, rollback, and log evidence exists on that platform.

## Linux

- VPN backends: WireGuard through `wg`/`wg-quick`, OpenVPN through `openvpn`,
  and IKEv2 through strongSwan `ipsec` or `swanctl`.
- Firewall backend: nftables through `nft`.
- Service model: systemd.
- Privileged operations: `sudo wg-quick up/down`, `sudo openvpn`,
  `sudo ipsec up/down`, and `sudo nft` rule/table changes.
- Remaining Standard v3 evidence: real VPN connect/disconnect, real nftables
  apply/rollback, service installation behavior, target-host logs, and privilege
  requirements.

## Windows

- VPN backends: WireGuard tunnel service, OpenVPN, and native IKEv2 through
  `rasdial`.
- Firewall backend: Windows Firewall through `netsh advfirewall`.
- Service model: Windows Service.
- Privileged operations: WireGuard tunnel service install/uninstall, OpenVPN
  process execution, native VPN connect/disconnect, and Windows Firewall
  profile/rule changes.
- Remaining Standard v3 evidence: real VPN connect/disconnect, real firewall
  apply/rollback, service installation behavior, target-host logs, and privilege
  requirements.

## macOS

- VPN backends: WireGuard through `wg`/`wg-quick`, OpenVPN through `openvpn`,
  and native IKEv2 through `scutil`.
- Firewall backend: PF through `pfctl`.
- Service model: launchd.
- Privileged operations: `sudo wg-quick up/down`, `sudo openvpn`, `scutil`
  network connection control, and `sudo pfctl` anchor/rule changes.
- Remaining Standard v3 evidence: real VPN connect/disconnect, real PF
  apply/rollback, service installation behavior, target-host logs, and privilege
  requirements.

## Acceptance Rule

Cross-platform support remains below full Standard v3 acceptance until each
supported OS has evidence for:

- install and runtime behavior,
- required privileges and service setup,
- VPN connect/disconnect and rollback,
- firewall apply/rollback,
- target-host logs,
- failure behavior when OS tools are missing.
