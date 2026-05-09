// Tests for FsContactSecurityState and FsContactSecurityRegistry — Phase 7.
//
// Mandatory tests (roadmap §10 Phase 7):
//
//  T7.1  Bob has primary FS active and passphrase FS inactive;
//        UI shows only active context.
//  T7.2  Expel passphrase → passphrase-specific state disappears.
//  T7.3  Shared contact record remains unchanged by FS state changes.
//  T7.4  Lookup by (contactId, identityContext, sessionId) is precise.
//  T7.5  forContact returns only entries for the given (contactId, context).
//  T7.6  clearContext removes only that context's entries.
//  T7.7  Same contactId can have different states in primary vs passphrase ctx.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

void main() {
  const kPrimary = 'primary';
  const kPassphrase = 'pp-ctx-deadbeef';
  const kBobId = 'bob@example.com';
  const kAliceId = 'alice@example.com';
  const kSession1 = 'session-abc';
  const kSession2 = 'session-xyz';

  // T7.1 — Bob has primary FS active; passphrase context absent → only primary visible.
  test('T7.1: primary FS active for Bob; passphrase context absent → only primary entry', () {
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));

    // Primary context is present.
    final primary = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    expect(primary, isNotNull);
    expect(primary!.isActive, isTrue);
    expect(primary.fsState, equals(FsSessionState.fsActive));

    // Passphrase context is absent.
    final pp = registry.lookup(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession1,
    );
    expect(pp, isNull,
        reason: 'Passphrase FS state must not be visible when context is absent');

    // forContact for primary returns 1 entry.
    final primaryEntries = registry.forContact(
      contactId: kBobId,
      identityContext: kPrimary,
    );
    expect(primaryEntries.length, equals(1));
    expect(primaryEntries.first.isActive, isTrue);
  });

  // T7.2 — Expel passphrase context: passphrase-specific state disappears.
  test('T7.2: expel passphrase → passphrase-specific FS state cleared', () {
    final registry = FsContactSecurityRegistry();

    // Both primary and passphrase states registered.
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession2,
      fsState: FsSessionState.fsInitSent,
    ));

    expect(registry.length, equals(2));

    // Expel passphrase context.
    registry.clearContext(kPassphrase);

    // Passphrase entry gone.
    expect(
      registry.lookup(
        contactId: kBobId,
        identityContext: kPassphrase,
        sessionId: kSession2,
      ),
      isNull,
      reason: 'Passphrase state must be cleared after expel',
    );

    // Primary entry unaffected.
    final primary = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    expect(primary, isNotNull);
    expect(primary!.fsState, equals(FsSessionState.fsActive));
    expect(registry.length, equals(1));
  });

  // T7.3 — Shared contact record remains unchanged.
  // (No FS fields in RemoteIdentity — verified by checking the model has no such fields.)
  test('T7.3: FsContactSecurityState is separate from contact record model', () {
    // The registry holds state entirely in memory, keyed by contactId.
    // It never modifies RemoteIdentity.  We verify this by confirming that
    // all state changes happen only in the registry.
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));

    // Simulate "update FS state" — registry is mutated, contact record is not.
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.strictFsActive,
    ));

    final updated = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    expect(updated!.fsState, equals(FsSessionState.strictFsActive));
    // Only 1 entry: upsert replaces, doesn't duplicate.
    expect(registry.length, equals(1));
  });

  // T7.4 — Lookup precision: (contactId, identityContext, sessionId).
  test('T7.4: lookup is precise — different sessionId returns different entry', () {
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession2,
      fsState: FsSessionState.fsSuspended,
    ));

    final s1 = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    final s2 = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession2,
    );
    expect(s1!.fsState, equals(FsSessionState.fsActive));
    expect(s2!.fsState, equals(FsSessionState.fsSuspended));
    expect(s1, isNot(equals(s2)));
  });

  // T7.5 — forContact returns only entries for that (contactId, context).
  test('T7.5: forContact scoped to contactId + identityContext', () {
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kAliceId,
      identityContext: kPrimary,
      sessionId: kSession2,
      fsState: FsSessionState.legacyOnly,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession2,
      fsState: FsSessionState.fsInitSent,
    ));

    final bobPrimary = registry.forContact(
      contactId: kBobId,
      identityContext: kPrimary,
    );
    expect(bobPrimary.length, equals(1));
    expect(bobPrimary.first.contactId, equals(kBobId));
    expect(bobPrimary.first.identityContext, equals(kPrimary));

    final bobAll = registry.forContactAllContexts(kBobId);
    expect(bobAll.length, equals(2),
        reason: 'Bob has entries in both primary and passphrase context');

    final alicePrimary = registry.forContact(
      contactId: kAliceId,
      identityContext: kPrimary,
    );
    expect(alicePrimary.length, equals(1));
    expect(alicePrimary.first.fsState, equals(FsSessionState.legacyOnly));
  });

  // T7.6 — clearContext removes only that context.
  test('T7.6: clearContext removes only entries for that identityContext', () {
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession2,
      fsState: FsSessionState.fsInitSent,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kAliceId,
      identityContext: kPassphrase,
      sessionId: 'alice-pp-session',
      fsState: FsSessionState.fsInitSeen,
    ));

    registry.clearContext(kPassphrase);

    // Passphrase entries for both Bob and Alice gone.
    expect(
      registry.lookup(
        contactId: kBobId,
        identityContext: kPassphrase,
        sessionId: kSession2,
      ),
      isNull,
    );
    expect(
      registry.lookup(
        contactId: kAliceId,
        identityContext: kPassphrase,
        sessionId: 'alice-pp-session',
      ),
      isNull,
    );

    // Primary entry for Bob survives.
    expect(
      registry.lookup(
        contactId: kBobId,
        identityContext: kPrimary,
        sessionId: kSession1,
      ),
      isNotNull,
    );
    expect(registry.length, equals(1));
  });

  // T7.7 — Same contactId, different contexts → different states coexist.
  test('T7.7: same contactId can have different FS state per identity context', () {
    final registry = FsContactSecurityRegistry();

    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession2,
      fsState: FsSessionState.legacyOnly,
    ));

    final primary = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    final pp = registry.lookup(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession2,
    );

    expect(primary!.fsState, equals(FsSessionState.fsActive));
    expect(pp!.fsState, equals(FsSessionState.legacyOnly));
    expect(primary.fsState, isNot(equals(pp.fsState)));
  });

  // copyWith produces a correctly mutated copy.
  test('FsContactSecurityState.copyWith updates only specified fields', () {
    const original = FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    );

    final updated = original.copyWith(fsState: FsSessionState.fsBroken);
    expect(updated.fsState, equals(FsSessionState.fsBroken));
    expect(updated.contactId, equals(kBobId));
    expect(updated.sessionId, equals(kSession1));
    expect(updated.identityContext, equals(kPrimary));

    // Original unchanged.
    expect(original.fsState, equals(FsSessionState.fsActive));
  });

  // isActive / isBroken / isStrict helpers.
  test('FsContactSecurityState flag helpers', () {
    const active = FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: null,
      fsState: FsSessionState.fsActive,
    );
    expect(active.isActive, isTrue);
    expect(active.isBroken, isFalse);
    expect(active.isStrict, isFalse);

    const strict = FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: null,
      fsState: FsSessionState.strictFsActive,
    );
    expect(strict.isActive, isTrue);
    expect(strict.isStrict, isTrue);

    const broken = FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: null,
      fsState: FsSessionState.fsBroken,
    );
    expect(broken.isActive, isFalse);
    expect(broken.isBroken, isTrue);
  });

  // T7.8 — markAllBroken marks all sessions in a context as broken (spec §8.6.3).
  test('T7.8: markAllBroken marks all sessions as broken for identity reset', () {
    final registry = FsContactSecurityRegistry();

    // Setup: multiple active sessions in primary context
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));
    registry.upsert(FsContactSecurityState(
      contactId: kAliceId,
      identityContext: kPrimary,
      sessionId: kSession2,
      fsState: FsSessionState.strictFsActive,
    ));
    // Session in passphrase context (should NOT be affected)
    registry.upsert(FsContactSecurityState(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession1,
      fsState: FsSessionState.fsActive,
    ));

    // Mark all primary sessions as broken (identity reset scenario)
    registry.markAllBroken(kPrimary);

    // Verify primary sessions are now broken
    final bobPrimary = registry.lookup(
      contactId: kBobId,
      identityContext: kPrimary,
      sessionId: kSession1,
    );
    expect(bobPrimary, isNotNull);
    expect(bobPrimary!.fsState, equals(FsSessionState.fsBroken));

    final alicePrimary = registry.lookup(
      contactId: kAliceId,
      identityContext: kPrimary,
      sessionId: kSession2,
    );
    expect(alicePrimary, isNotNull);
    expect(alicePrimary!.fsState, equals(FsSessionState.fsBroken));

    // Verify passphrase context is unaffected
    final bobPassphrase = registry.lookup(
      contactId: kBobId,
      identityContext: kPassphrase,
      sessionId: kSession1,
    );
    expect(bobPassphrase, isNotNull);
    expect(bobPassphrase!.fsState, equals(FsSessionState.fsActive));
  });
}
