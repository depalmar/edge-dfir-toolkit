# Security Policy

## Reporting issues with the toolkit or its content

If you believe a profile step can change device state despite the read-only
guard, a detection could be weaponized, or a fixture works as a functional
exploit, do not open a public issue. Email the maintainer directly (see the
GitHub profile for contact).

Examples of what belongs in a private report:
- A command that passes a profile's allow-list but modifies, reloads or crashes a device
- A way for an ingested bundle to write outside the case directory
- Any content you believe crosses the line between detection and attack enablement

## Reporting bugs, false positives, or improvements

Use public issues for false positives, wrong commands on a particular release,
coverage gaps and bugs. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Scope

This repository contains:
- A collection and analysis engine and declarative collection profiles
- Detection rules (Sigma, YARA) and detection packs
- Synthetic test fixtures clearly marked as test data
- Documentation

This repository does NOT contain:
- Real malware samples or device images
- Working exploits
- Data from real incidents or real organizations
- Credentials

## A note on research ethics

All content targets publicly disclosed vulnerabilities and published research.
Please follow the same standard in contributions.
