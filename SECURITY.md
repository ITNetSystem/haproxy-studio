# Security

Report suspected vulnerabilities privately to the repository owner. A public
contact will be supplied when the repository is published. Do not post passwords,
config files, certificates, private keys or backups in issues.

The panel is an administrative trust boundary: administrators who may edit HAProxy
configuration effectively control its process. It is not a multi-tenant product.
Bind to loopback and expose through HTTPS or SSH. Application authentication,
expiring sessions, same-origin checks, CSRF protection and protected secret lines
are required. Never expose the development HTTP endpoint directly to the Internet.
The native service needs elevated HAProxy access; Docker monitoring requires only
mounted config and socket access. Git ignores are convenience, not a secret scanner.

Local accounts use PBKDF2-HMAC-SHA256 (310,000 iterations, unique salts). Legacy
admin credentials migrate to state_dir/users.json; auth.json is retained only for
bootstrap/recovery compatibility, not used for subsequent web authentication.
Account generations revoke sessions after password, role or enabled-state changes.
Viewer accounts can inspect masked configuration and metadata and change their own
password; server-side checks reject all HAProxy/certificate/user mutations.
Administrators retain effective control of the HAProxy process.
