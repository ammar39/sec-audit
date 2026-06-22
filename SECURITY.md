# Security Policy

## Supported Versions

`django-sec-audit` is currently pre-1.0. Security fixes are provided for the
latest `0.3.x` release line only. Older alpha releases may contain incompatible
schemas or APIs and should be upgraded before reporting production issues.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | Yes                |
| < 0.3   | No                 |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. If GitHub private security
advisories are enabled for the repository, open one there. Otherwise contact
the maintainers through the project issue tracker with a brief non-sensitive
summary and ask for a private disclosure channel.

Do not include working exploit payloads, credentials, private log files, or
customer data in a public issue.

Helpful reports include:

- affected package version and Python/Django versions
- configuration needed to reproduce the issue
- whether the issue affects logging, enforcement, rules, integrations, or the
  demo application
- impact and suggested remediation, if known

The maintainers will acknowledge accepted reports, coordinate a fix, and
document the security-relevant behavior change in the changelog.
