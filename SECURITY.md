# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue: use GitHub's private vulnerability reporting on
the repository, [Report a vulnerability](https://github.com/paularlott/quisora/security/advisories/new) (the
repository's Security tab). Only the maintainers see the report.

Include what you found, how to reproduce it, and the version (`quisora --version`). You get an acknowledgement within
3 working days and an assessment within 10. We agree a disclosure date with you, normally once a fixed release is
out and at most 90 days after the report, and credit you in the release notes unless you would rather not be named.

Please give us the chance to fix a problem before disclosing it, do not access data that is not yours, and do not
degrade a service others depend on while testing.

## Supported versions

Quisora has not had a stable release yet: only the latest `main` is supported, and fixes land there. From the first
release, the latest release and the one before it receive security fixes.

## For operators

Running Quisora securely (threat model, hardening checklist, incident response): [docs/SECURITY.md](docs/SECURITY.md).
Personal data it holds, and how to answer a data subject's request: [docs/PRIVACY.md](docs/PRIVACY.md).
