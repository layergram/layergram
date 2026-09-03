## Pre-review gate

Do not open a pull request without explicit approval for its exact scope in a
linked issue, unless the maintainer invited the contribution directly.
Unapproved, oversized, or out-of-scope pull requests may be closed without a
complete technical review. Approval to implement does not guarantee merge or a
review timeline.

- Approved issue:
- Maintainer approval comment:

## Summary

Describe the problem and the smallest change that addresses the approved scope.

## Scope confirmation

- [ ] The linked issue contains explicit maintainer approval to implement this exact scope.
- [ ] This pull request stays within that approved scope.
- [ ] The change stands on its own in the public repository.
- [ ] The change does not depend on or disclose private services, unpublished add-ons, billing logic, private URLs, internal paths, credentials, or operational evidence.
- [ ] I understand that review can be paused or stopped if scope, risk, or maintenance cost changes.

## Security and compatibility

Describe effects on cryptography, identity, protocol formats, storage,
migrations, deep links, steganography, supported platforms, and backward
compatibility. Write `None` only after checking each area.

Do not disclose an uncoordinated vulnerability here. Stop and use
[GitHub private vulnerability reporting](https://github.com/layergram/layergram/security/advisories/new)
instead.

## Validation

List the exact commands and results. Include new or updated tests when behavior
changes. Do not use real secrets, identities, recovery phrases, plaintext, or
personal data in evidence.

```text
command -> result
```

## Provenance and licensing

- Automated tools used to generate or substantially transform code or text:
- Third-party code, specifications, examples, or other material used:
- Required licenses, notices, or attribution:

- [ ] I have the right to contribute every part of this change under Apache-2.0.
- [ ] Generated, copied, adapted, or vendored material is disclosed above with its provenance and applicable license.
- [ ] No source from an incompatible or undisclosed license was copied, adapted, linked, or embedded.

## Maintainer notes

Leave this section unchanged. The maintainer may record additional review,
independent verification, migration, release, or disclosure gates here.
