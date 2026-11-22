# HAProxy Studio
<!-- impeccable:product-schema 1 -->

## Platform
web

## Stack
Implementation delegated to the agent. Python 3.9+ standard library and native HTML/CSS/JavaScript. No runtime package downloads.

## Users
HAProxy administrators. Initially the owner's existing server; designed for independent installations.

## Product Purpose
Provide a free GUI with live state, routes and controlled configuration changes.

## Capabilities and Constraints
The owner requires a standalone project suitable for later GitHub publication and installation beyond CentOS. Keep live state and credentials outside source. Native Linux/systemd management; Docker monitoring. Preserve existing unrelated services and configuration. User delegates visual design using installed plugins. No GitHub publication until requested.

## Evidence on Hand
Existing HAProxy 2.8 system service and runtime socket. No fabricated metrics.

## Visual publishing
The owner requires a novice-friendly wizard that writes working HAProxy configuration from form choices. Native HTTP/TLS, RDP, SSH, mail including SMTPS/IMAPS, backend pools, certificate import, redirects and managed lifecycle are implemented. DNS/provider firewall and installing backend applications remain external prerequisites.

## Enterprise publishing
Multi-domain HTTP, per-path Exchange pools and health checks, case-insensitive paths, root redirects, HTTP exceptions and shared implicit-TLS ports with SNI/fallback are supported. Existing global settings remain untouched. Workplace domains, addresses and credentials are not embedded in distributable examples. Certificate upload was confirmed working by the owner and was left unchanged in this update.
