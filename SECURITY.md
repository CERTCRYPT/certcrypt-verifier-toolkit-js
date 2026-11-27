# Security Policy

## Supported Versions

Security fixes land on the latest published version. Upgrading is the remediation
path — fixes are not backported to superseded versions.

| Version | Supported |
| --- | --- |
| Latest `1.x` release | Yes |
| Earlier releases | Upgrade to the latest |

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities.

Report security concerns by email to security@certcrypt.com.

Include:

- affected repository or component
- affected version or commit, if known
- a clear description of the issue
- reproduction steps, if available
- potential impact

Please avoid including customer data, production credentials, private keys, or confidential third-party material in reports.

We will acknowledge valid reports as soon as practical and coordinate remediation before public disclosure.

## Coordinated Disclosure

Please give us a reasonable opportunity to investigate and remediate security issues before public disclosure.

Do not publish exploit details, proof-of-concept code, or operational indicators before we have completed triage and remediation planning.

## Scope

This repository is intended for public verifier tooling.

Do not submit secrets, production credentials, private keys, customer data, or any other sensitive material in issues, pull requests, or discussions.

## Non-production profiles

This toolkit verifies any deployment of the protocol, so it can run under a
profile that is not the published production one. That is a supported capability
and a deliberately narrow one.

- The published package carries the production profile only. The test-profile
  helpers live in `harness/`, which npm excludes. Running against any other
  deployment requires the operator to supply its configuration; nothing is
  defaulted and a missing field throws.
- Any verification performed under a non-production profile is reported as
  `production_verification: false`. That flag is set by comparing the ENTIRE
  configuration against the published production profile, so a test verdict
  cannot be relabelled as production by substituting individual fields.

**Presenting a `production_verification: false` result as a CERTCRYPT
verification is a misrepresentation, not a vulnerability.**

A genuine finding in this area is the opposite: a configuration that is NOT the
published production profile yet still yields `production_verification: true`.
That is a real fail-open and we want to hear about it.

## Out of Scope

The following are not handled through this repository's security process:

- general product questions
- documentation corrections without security impact
- requests for roadmap information
- reports about private CERTCRYPT systems not represented in this repository
- claims about semantic truth, legal validity, or factual correctness of certificate content

For non-security questions, use the public contact channel:

opensource@certcrypt.com
