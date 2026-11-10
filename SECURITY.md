# Security Policy

To report a vulnerability, follow the fuzdev organization's security policy:
<https://github.com/fuzdev/.github/blob/main/SECURITY.md>

## Scope

Everything in this repository is in scope: the `zap` CLI and its engine, and the
`@fuzdev/zap` package, its builder types, schema, and recipes. The recipes emit
configuration that runs as root on the machines they describe (nginx sites, systemd
units and OpenRC services, sshd drop-ins, firewall rules, sudo-run scripts), so a
recipe whose output is unsafe for the values it accepts is a vulnerability in Zap.
The threat model is <https://zap.fuz.dev/docs/security>.

## Supported versions

Only the latest release is supported. Zap is pre-alpha, and a fix ships in a new
release, not as a backport.
