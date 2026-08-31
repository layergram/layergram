# Security Response Lifecycle

This document describes the public, repository-level process used to receive,
triage, remediate, and disclose security vulnerabilities affecting Layergram.
Sensitive evidence and active incident details stay in the relevant GitHub
Security Advisory or another approved private response channel.

## Response Roles

- **Intake owner:** monitors private reports, acknowledges receipt, and keeps
  communication with the reporter in the private channel.
- **Triage owner:** reproduces the issue, evaluates impact and exploitability,
  assigns severity, and identifies affected versions.
- **Fix owner:** prepares the narrowest complete correction and regression tests.
- **Release owner:** verifies distribution artifacts and coordinates publication.

One maintainer may hold more than one role. A person who authored a sensitive
fix should seek an independent review before release whenever possible.

## Severity Guidance

- **Critical:** practical compromise of cryptographic keys or plaintext at
  scale, arbitrary code execution, or a systemic protocol failure without a
  reasonable user-controlled mitigation.
- **High:** meaningful confidentiality, integrity, identity, or app-lock bypass
  under realistic preconditions.
- **Medium:** limited disclosure, denial of service, unsafe state transition, or
  weakened security control that requires substantial interaction or access.
- **Low:** defense-in-depth weakness, low-impact information exposure, or
  security documentation and hardening gap.

Severity can change as reproduction and impact become clearer. The final rating
records both exploitability and user impact rather than relying on a label alone.

## Lifecycle

1. **Receive privately.** Keep reports out of public issues and discussions.
   Acknowledge receipt within the target stated in [`SECURITY.md`](SECURITY.md).
2. **Protect evidence.** Ask reporters to remove real credentials, private keys,
   plaintext, and personal data. Do not run untrusted proof-of-concept material
   on signing, release, or everyday development machines.
3. **Validate.** Reproduce on an isolated environment against an identified
   version or commit. Record the security invariant, affected platforms, and
   the smallest source-to-sink path that demonstrates the issue.
4. **Triage.** Assign an owner and provisional severity, identify supported
   versions, and decide whether containment is required before a code fix.
5. **Contain and remediate.** Revoke exposed credentials or pause affected
   distribution paths when needed. Implement a scoped fix without weakening
   authentication, validation, isolation, or failure behavior.
6. **Verify independently.** Demonstrate that the original issue no longer
   reproduces, legitimate behavior remains intact, regression tests pass, and
   affected release artifacts are built from the reviewed revision.
7. **Coordinate disclosure.** Prepare a GitHub Security Advisory and request a
   CVE when appropriate. Publish technical details only after a fix or practical
   mitigation is available, unless ongoing harm requires earlier disclosure.
8. **Recover and close.** Confirm fixed versions are available, revoke temporary
   access, notify the reporter, and document residual risk and follow-up work.
9. **Review.** Record lessons that improve tests, threat models, release gates,
   or response procedures without publishing sensitive operational evidence.

## Public and Private Records

Public records may include the fixed versions, affected components, severity,
credits accepted by the reporter, mitigations, and advisory or CVE identifiers.
Private records include reporter contact details, unredacted evidence, live
credentials, exploit material, internal access details, and pre-disclosure
discussion.
