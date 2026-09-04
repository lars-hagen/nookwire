# Security policy

## Supported versions

Security fixes are applied to the latest release and the default branch.

## File transfer and confinement

Nookwire permits SSH shell commands and execution as the host operating-system user. By default, SFTP and modern SCP mirror shell filesystem visibility: relative paths resolve within the configured project root, while absolute paths refer to host paths subject to standard OS user permissions.

Starting Nookwire with `--confine-sftp` (or `NOOKWIRE_CONFINE_SFTP=1` / `NOOKWIRE_SSH_CONFINE_SFTP=1`) restricts SFTP and SCP file transfers to the configured project root and rejects symlink escapes outside that root. This limits automated file-transfer clients, but because authenticated users can still run arbitrary shell commands with host user privileges, it does not provide an operating-system sandbox or privilege isolation.

## Reporting a vulnerability

Please report security issues privately through [GitHub private vulnerability reporting](https://github.com/lars-hagen/nookwire/security/advisories/new). Do not open a public issue for an undisclosed vulnerability.

Include the affected version or commit, expected impact, reproduction steps, and any suggested mitigation. Reports will be acknowledged as soon as practical.

Only test systems and environments you own or are explicitly authorized to assess.
