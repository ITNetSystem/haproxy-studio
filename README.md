# HAProxy Studio

[Русская инструкция](README.ru.md)

Self-hosted Russian-language administration interface for an existing HAProxy.
Independent project: no commercial subscription, vendor account or external telemetry.

## Visual service publishing

The three-step Russian-language wizard publishes HTTP/HTTPS, WebSocket, RDP/RDS Connection Broker, SSH, SMTP/submission/SMTPS, IMAP/IMAPS, POP3/POP3S, ManageSieve, databases and generic TCP/TLS services. It includes certificate import (PEM/CRT/KEY and PFX/P12), redirects, backend pools, health checks, source IP restrictions and edit/disable/delete workflows. [Wizard guide](docs/services.ru.md). OpenSSL CLI and system CA certificates are required for native certificate/TLS operations.

## Accounts and resource maintenance

Version 0.4 adds password changes, administrator/viewer accounts, named certificate management and dependency-aware deletion of manually configured backend pools, including conf.d files. Existing administrator credentials migrate without rotation. [Administration guide (Russian)](docs/administration.ru.md).

## Status

Initial development release. Linux is the administration target. Python 3.9+;
no Python runtime dependencies. Native installation targets Debian 12+, Ubuntu
22.04+, CentOS Stream 9, Rocky Linux 9 and AlmaLinux 9 with systemd. These are
targets, not a claim that production installation was verified on every OS.
CI includes distribution userspace and installed-HAProxy validation tests;
container tests do not verify a booted systemd host or SELinux policy.

## Native installation

Install Python 3.9+ and an existing HAProxy with your distribution package manager.
Clone this repository or extract its source archive, then run:

```sh
sudo sh scripts/install.sh
sudoedit /etc/haproxy-studio/config.json
sudo systemctl enable --now haproxy-studio
sudo cat /var/lib/haproxy-studio/initial-password
```

Open `http://127.0.0.1:9130/haproxy-admin/`, username `admin`. From another machine,
use an SSH tunnel: `ssh -L 9130:127.0.0.1:9130 user@server`.
For permanent browser access, configure an HTTPS reverse proxy and set `public_url`
to its exact origin (for example `https://admin.example.org`, without the base path).
No firewall, DNS or public proxy rule is created by the installer.
The initial password is generated locally, never committed or printed in logs.

The installer preserves existing application settings, never installs/replaces
HAProxy and does not start or reload either service. Native apply mode needs
privileges to read HAProxy dependencies, replace its config, and reload the service.
Review these permissions before enabling writes. Start with `read_only: true`.

## Configuration and portability

Copy `config.example.json` to a private file. Set `STUDIO_CONFIG` to its path.
Every host-specific path is configurable: executable (auto-detected with PATH plus
/usr/local/sbin and /usr/sbin fallbacks), config, extra config directory, runtime
socket, certificate directory, state directory, URL and port. Reload and health
checks are argument arrays, executed without a shell. A non-systemd host can use
its own command adapter. Runtime socket access requires appropriate file permissions.
The systemd example permits writes only under /etc/haproxy and the state directory;
if changing paths, update ReadWritePaths too. SELinux may require a local policy;
the installer never disables it. Windows/macOS are development/browser clients,
not native management targets for a Linux HAProxy service.

## Docker

```sh
docker compose up -d --build
docker compose exec studio cat /var/lib/haproxy-studio/initial-password
```

The provided container is a **read-only monitor** for the host HAProxy. Adjust bind
mounts and runtime socket path to your host. The image does not include a second
HAProxy binary and does not validate or apply host configs. A read-only bind mount
does not make Unix socket commands read-only: the application issues only `show info`
and `show stat`. No Docker socket, privileged container, host PID namespace or host
systemd mount is required. Docker Desktop cannot access a remote Linux HAProxy socket
through local mounts. For full control install natively on the HAProxy host.
For SELinux hosts use a reviewed local policy, not indiscriminate relabelling of
system HAProxy directories. The image builds locally and the test suite passes on its Debian/Python 3.12 base; host-mount deployment on other OSes is not yet verified.

## Changes and recovery

Write mode: configuration draft → HAProxy validation → redacted diff → explicit
apply. Applying rechecks the revision and validates again, stores a private backup,
replaces the file atomically, then gracefully reloads HAProxy. A failed reload
restores the previous file and attempts a recovery reload. The UI reports recovery
failure and keeps the backup. Backups and credentials live outside the repository.
Extra *.cfg files participate in revision checks and validation. The service wizard
and raw editor change the main file; manual backend deletion can also update
referencing rules and pools in conf.d with backup and rollback across changed files. Secrets stay masked with protected placeholders. The editor
preserves non-UTF-8 bytes in unchanged lines.

## Development

```sh
cp config.example.json config.json
# Set local state_dir and your public_url; keep read_only true.
STUDIO_CONFIG=./config.json python3 -m haproxy_studio
python3 -m unittest discover -s tests -v
```

## License and private data

MIT licensed. Server settings, account databases, certificates, private keys and
backups belong outside the source tree and are excluded from release archives.
The installer does not upload source or runtime data to GitHub.

## Exchange и общие TLS-порты

В версии 0.3 добавлены группы доменов, маршруты и проверки служб Exchange, перенаправление корня, HTTP-исключения, общие SMTPS/IMAPS/POP3S-порты с SNI и fallback. [Инструкция и ограничения STARTTLS](docs/exchange-sni.ru.md).

Version 0.5 adds an RDS Connection Broker template with native RDP forwarding and broker-token persistence to configured Session Hosts. [RDS guide (Russian)](docs/rds.ru.md).
