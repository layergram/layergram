# Layergram Protocol v3 Migration Guide

Status: **public migration contract for active protocol v3**

Protocol v3 is intentionally incompatible with protocol v2. It is designed to
add hybrid post-quantum protection without adding Layergram accounts, servers,
key directories, or a new message-delivery network. Protocol v3 is active in
Layergram 2.0.0 and later; earlier releases continue to use protocol v2 and are
not post-quantum protected.

## What users keep

- The same 24-word BIP39 recovery phrase restores the user's identity secret.
- An optional BIP39 passphrase continues to select its separate deterministic
  identity context.
- Layergram remains fully local and messages continue to travel through an
  external application or any other compatible text channel.
- Message export remains available as direct text, a `layergram://` deep link,
  or zero-width steganography.
- Public identity sharing remains available as a complete direct-text token, a
  deep link, or one branded static QR code suitable for a screen, printed card,
  sticker, or social profile.

The recovery phrase and optional passphrase are private recovery secrets. They
are entered only into the user's own Layergram installation and must never be
sent to a contact or encoded in an identity QR code.

## What changes

The same recovery secret deterministically derives **new v3 cryptographic key
material**: a complete X25519 public key and a complete ML-KEM-768 public key.
Consequently, v3 has a different:

- public identity bundle and identity ID;
- fingerprint and SAS verification result;
- contact trust binding;
- device/session and ratchet state;
- wire format and message compatibility.

“Keep the same 24 words” therefore means that users do not need to create and
protect another recovery phrase. It does not mean that Layergram reuses the old
v2 public or private keys.

## Required user migration

After installing Layergram 2.0.0 or a later v3-capable release:

1. Update Layergram on each supported device.
2. Restore or unlock the same recovery phrase and, if applicable, intentionally
   activate the desired passphrase context.
3. Export the complete new v3 public identity as text, deep link, or one static
   QR code.
4. Share that public identity with each contact. Publishing it on a profile,
   card, or sticker is supported, but does not authenticate who controls it.
5. Import each contact's complete v3 public identity.
6. Verify the new fingerprint or SAS through an independent channel before
   treating the contact as authenticated.
7. Start a new v3 session. Existing v2 sessions and verification badges are not
   promoted to v3 automatically.

Layergram must never silently rewrite a v2 contact as v3. Once a contact is
migrated, v2 user-message sending is blocked rather than presented as equivalent
post-quantum security.

## Identity carriers

All three carriers contain the complete public identity. None is merely a
verification reference or an online lookup key:

| Carrier | Contents | Intended use |
|---|---|---|
| Direct text | Complete canonical v3 public identity | Copy/paste and social profiles |
| Deep link | `layergram://` prefix plus the same complete text identity | One-tap import where links are supported |
| Branded static QR | Complete canonical binary v3 public identity | Screens, print, stickers, and business cards |

The QR is deliberately a single, non-animated symbol. Compact encoding removes
redundant representation data but never truncates X25519 or ML-KEM-768 public
material. Its maximum form uses QR version 30 with error correction M, a
four-module quiet zone, and a centered Layergram logo whose side is 20% of the
complete symbol. The enlarged in-app view uses a uniform light surface and a
temporary 60% brightness floor that is restored when the view closes. Users
should share the full-size preview or the 1,024-pixel PNG rather than a
compressed thumbnail. Printed cards and stickers must preserve the whole quiet
zone and be tested with representative phones; successful digital rendering at
a given physical scale is not by itself a guarantee that every printer, paper,
camera, and lighting condition will scan reliably.

## Messages and unreliable external delivery

Protocol v3 preserves Layergram's three message forms:

- direct ciphertext text;
- the same text with a message deep-link prefix;
- the same canonical encrypted frame embedded in zero-width steganography.

Layergram does not control the transport. A generated item can remain unsent or
be lost, delayed, duplicated, normalized, or delivered out of order by the
chosen application. V3 therefore stores exact pending exports before sharing,
uses bounded independently shareable parts when fragmentation is necessary,
accepts duplicates safely, and advances/cleans state only through authenticated
durable acknowledgements. It cannot force WhatsApp, Telegram, Signal, iMessage,
email, or another carrier to deliver anything.

The portable carrier target is at most 4,000 characters per exported part.
Real cross-application text, link, and steganographic preservation remains a
release gate. Steganography must keep the current minimum-cover behavior: the
user is not required to invent a cover message disproportionately longer than
the current Layergram workflow, although large logical messages may require
multiple independently shareable parts.

## Normal and Maximum modes

- **Normal** is the default and can deliver the same logical message to every
  currently accepted device for a contact. Each device keeps an independent
  authenticated v3 session.
- **Maximum** binds the conversation to exactly one exclusive authenticated
  device pair. User content remains pending whenever that strict session is not
  active; Layergram does not silently fall back to Normal or v2.

Neither mode can prevent an external carrier from losing a setup or message
part. Their security behavior therefore separates “pending/not delivered” from
“delivered under weaker cryptography.”

## Passphrases, deniability, and multiple identities

Each mnemonic/passphrase context derives a distinct deterministic v3 public
identity. Only the context intentionally activated by the user should expose
its contacts and local records. The base context does not enumerate or reveal
another passphrase context.

Separately managed identities use the same public v3 protocol contract and each
must migrate, share, and verify its own complete public identity. Optional
downstream capabilities must not create a different wire protocol or weaken the
activation policy.

This provides limited practical plausible deniability, not protection against a
compromised operating system, observation while entering a passphrase, forensic
correlation, coercion, screenshots, or memory capture while the context is
unlocked.

## Recovery and old data

The recovery phrase restores deterministic identity keys. It does not recreate
missing local chat history, unexported message parts, acknowledgements, device
sessions, ratchet state, or contact verification. Those require the relevant
encrypted local state or an intentionally supported backup/restore path.

Users should retain any old installation or backup needed to read historical v2
data until they no longer need it. V3 does not reinterpret old v2 ciphertext as
v3.

## Release boundary

The active implementation remains behind a single fail-closed selector whose
identity, messaging, and production decisions must all be true. Official
release artifacts must package the exact allowlisted native backend and pass
the documented platform, migration, carrier, persistence, and security gates.
Source availability, a public identity, or a successful build alone is not
evidence that an unofficial binary used the required backend.
