import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_working_set.dart';

V3LmfStoredRecord record(String id, String kind,
        [Map<String, dynamic> data = const {}]) =>
    V3LmfStoredRecord(storageId: id, payload: {'kind': kind, ...data});
V3LmfStoredRecord archive(String id, String assembly) =>
    record(id, 'v3_application_record_v1', {
      'stableRecordId': 'v3:$assembly',
      'assemblyId': assembly,
      'record': 'private archive body'
    });
void main() {
  test(
      'unreferenced history and app presentation stay private; device key moves with owner',
      () {
    final records = [
      archive('old', 'old'),
      archive('required', 'required'),
      record('cp', 'v3_session_checkpoint_v1', {
        'receipts': [
          {'stableRecordId': 'v3:required'}
        ]
      }),
      record('presentation', 'v3_application_presentation_v1',
          {'reference': 'v3:old'}),
      record('device', 'v3_device_key_v1')
    ];
    expect(SystemKeyboardWorkingSet.select(records).map((r) => r.storageId),
        ['required', 'cp', 'device']);
    expect(records.length, 5);
  });
  test(
      'assembly references and malformed archive envelopes are conservatively retained',
      () {
    final records = [
      archive('needed', 'assembly'),
      record('out', 'v3_send_effect_v1', {'assemblyId': 'assembly'}),
      record('malformed', 'v3_application_record_v1', {'stableRecordId': 7})
    ];
    expect(SystemKeyboardWorkingSet.select(records), records);
  });
  test('unfinished V3 negotiation stays with the exclusive keyboard owner', () {
    final records = [
      record('device', 'v3_device_key_v1'),
      record('handoff', 'v3_handshake_handoff_v1'),
      record('pending-handshake', 'v3_handshake_pending_v1'),
      record('pending', 'v3.prefs.pending.manifest'),
    ];
    expect(SystemKeyboardWorkingSet.select(records), records);
  });
  test('unknown protocol state prevents delegation', () {
    for (final kind in ['v3_unknown_v2', 'v3.future.pending']) {
      expect(() => SystemKeyboardWorkingSet.select([record('unknown', kind)]),
          throwsStateError);
    }
  });
}
