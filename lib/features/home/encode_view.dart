// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/fs_security_mode.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/stego_encoder.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import '../../utils/sharing.dart';
import 'home_controller.dart';

class EncodeView extends ConsumerStatefulWidget {
  const EncodeView({super.key});

  @override
  ConsumerState<EncodeView> createState() => _EncodeViewState();
}

class _EncodeViewState extends ConsumerState<EncodeView> {
  final _coverCtrl = TextEditingController();
  final _secretCtrl = TextEditingController();
  final _expiresCtrl = TextEditingController();
  final _recipientSearchCtrl = TextEditingController();
  RemoteIdentity? _recipient;
  bool _deleteAfterRead = false;
  String _output = '';
  int? _exactCoverMissingCount;

  int get _estimatedPayloadBytes {
    return _estimatedPayloadBytesForSecret(_secretCtrl.text);
  }

  int? get _coverLengthLimit {
    return ref.read(coverMessageLengthLimitProvider);
  }

  int _estimatedPayloadBytesForSecret(String secretText) {
    if (_usesFsCoverPayloadBudget) {
      return StegoEncoder.estimatedCoverMessagePayloadBytes(secretText);
    }
    return StegoEncoder.estimatedEncryptedPayloadBytes(secretText);
  }

  bool get _usesFsCoverPayloadBudget {
    final recipient = _recipient;
    if (recipient == null) return true;
    final fsController = ref.read(
      fsOpportunisticControllerProvider(recipient.identityId),
    );
    final mode = ref.read(fsSecurityModeServiceProvider).getModeSync(
          contactId: recipient.identityId,
          identityContext: fsController.identityContext,
        );
    return mode != FsSecurityMode.base;
  }

  int _minimumStegoCharacterCount({
    String? coverText,
    String? secretText,
  }) {
    final effectiveCover = coverText ?? _coverCtrl.text;
    final effectiveSecret = secretText ?? _secretCtrl.text;
    if (effectiveSecret.trim().isEmpty) {
      return StegoEncoder.visibleCharacterCount(effectiveCover);
    }
    return StegoEncoder.minimumEncodedLengthForBytes(
      effectiveCover,
      _estimatedPayloadBytesForSecret(effectiveSecret),
    );
  }

  bool _fitsWithinCoverLengthLimit({
    String? coverText,
    String? secretText,
  }) {
    final limit = _coverLengthLimit;
    if (limit == null) return true;
    return _minimumStegoCharacterCount(
          coverText: coverText,
          secretText: secretText,
        ) <=
        limit;
  }

  TextEditingValue _limitStegoFieldEdit(
    TextEditingValue oldValue,
    TextEditingValue newValue, {
    required bool isCoverField,
  }) {
    if (_coverLengthLimit == null || newValue.text == oldValue.text) {
      return newValue;
    }

    final currentCover = isCoverField ? oldValue.text : _coverCtrl.text;
    final currentSecret = isCoverField ? _secretCtrl.text : oldValue.text;
    final nextCover = isCoverField ? newValue.text : _coverCtrl.text;
    final nextSecret = isCoverField ? _secretCtrl.text : newValue.text;

    if (_fitsWithinCoverLengthLimit(
      coverText: nextCover,
      secretText: nextSecret,
    )) {
      return newValue;
    }

    final currentFits = _fitsWithinCoverLengthLimit(
      coverText: currentCover,
      secretText: currentSecret,
    );
    final currentLength = _minimumStegoCharacterCount(
      coverText: currentCover,
      secretText: currentSecret,
    );
    final nextLength = _minimumStegoCharacterCount(
      coverText: nextCover,
      secretText: nextSecret,
    );

    if (!currentFits && nextLength < currentLength) {
      return newValue;
    }

    return oldValue;
  }

  List<TextInputFormatter> _coverLimitInputFormatters({
    required bool isCoverField,
  }) {
    if (_coverLengthLimit == null) return const [];
    return [
      TextInputFormatter.withFunction(
        (oldValue, newValue) => _limitStegoFieldEdit(
          oldValue,
          newValue,
          isCoverField: isCoverField,
        ),
      ),
    ];
  }

  String? _coverLimitCounterText(int? coverLengthLimit) {
    if (coverLengthLimit == null) return null;
    return '${_minimumStegoCharacterCount()}/$coverLengthLimit';
  }

  @override
  void initState() {
    super.initState();
    _coverCtrl.addListener(_onFieldChanged);
    _secretCtrl.addListener(_onFieldChanged);
    _onFieldChanged();
  }

  @override
  void dispose() {
    _coverCtrl.removeListener(_onFieldChanged);
    _secretCtrl.removeListener(_onFieldChanged);
    _coverCtrl.dispose();
    _secretCtrl.dispose();
    _expiresCtrl.dispose();
    _recipientSearchCtrl.dispose();
    super.dispose();
  }

  void _onFieldChanged() {
    if (!mounted) return;
    setState(() {
      _exactCoverMissingCount = null;
    });
  }

  bool get _coverTooShort {
    if (_secretCtrl.text.trim().isEmpty) return false;
    if (_exactCoverMissingCount != null) return true;
    return !StegoEncoder.canEmbedBytes(_coverCtrl.text, _estimatedPayloadBytes);
  }

  int get _coverMissingCount {
    if (_secretCtrl.text.trim().isEmpty) {
      return 0;
    }
    if (_exactCoverMissingCount != null) return _exactCoverMissingCount!;
    return StegoEncoder.missingCoverCapacityForBytes(
      _coverCtrl.text,
      _estimatedPayloadBytes,
    );
  }

  bool get _coverLengthLimitExceeded {
    return !_fitsWithinCoverLengthLimit();
  }

  bool get _canGenerate {
    return _recipient != null &&
        _coverCtrl.text.trim().isNotEmpty &&
        !_coverTooShort &&
        !_coverLengthLimitExceeded;
  }

  Future<List<RemoteIdentity>> _loadRecipients() async {
    final remote =
        await ref.read(identitiesRepositoryProvider).watchRemote().first;
    final local = await ref.read(identityManagerProvider).getLocalIdentity();

    final recipients = <RemoteIdentity>[];
    if (local != null) {
      recipients.add(
        RemoteIdentity(
          identityId: local.identityId,
          publicKeyBase64: local.publicKeyBase64,
          fingerprint: local.fingerprint,
          displayName: '${local.displayName} (Me)',
          verified: true,
        ),
      );
    }
    recipients.addAll(remote);
    return recipients;
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStrings.t;
    final coverLengthLimit = ref.watch(coverMessageLengthLimitProvider);
    final presetRecipient = ref.watch(encodeRecipientProvider);
    _recipient ??= presetRecipient;

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(strings(context, 'recipient')),
                const SizedBox(height: 8),
                TextField(
                  controller: _recipientSearchCtrl,
                  decoration: InputDecoration(
                    prefixIcon: const Icon(Icons.search),
                    labelText: strings(context, 'search'),
                  ),
                  onChanged: (_) => setState(() {}),
                ),
                const SizedBox(height: 8),
                FutureBuilder<List<RemoteIdentity>>(
                  future: _loadRecipients(),
                  builder: (context, snapshot) {
                    final query =
                        _recipientSearchCtrl.text.trim().toLowerCase();
                    final items = (snapshot.data ?? [])
                        .where((r) =>
                            query.isEmpty ||
                            r.displayName.toLowerCase().contains(query) ||
                            r.fingerprint.toLowerCase().contains(query))
                        .toList();

                    if (items.isEmpty) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Column(
                          children: [
                            Text(
                              strings(context, 'noResults'),
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyMedium
                                  ?.copyWith(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .outline),
                            ),
                          ],
                        ),
                      );
                    }

                    final selectedId =
                        _recipient?.identityId ?? presetRecipient?.identityId;

                    return ConstrainedBox(
                      constraints: const BoxConstraints(maxHeight: 260),
                      child: Scrollbar(
                        child: ListView.separated(
                          shrinkWrap: true,
                          itemCount: items.length,
                          separatorBuilder: (_, __) =>
                              const Divider(height: 1, thickness: 0.2),
                          itemBuilder: (context, index) {
                            final item = items[index];
                            return RadioMenuButton<String>(
                              value: item.identityId,
                              groupValue: selectedId,
                              onChanged: (value) {
                                final chosen = items
                                    .firstWhere((r) => r.identityId == value);
                                ref
                                    .read(encodeRecipientProvider.notifier)
                                    .state = chosen;
                                setState(() => _recipient = chosen);
                              },
                              child: Expanded(
                                child: Padding(
                                  padding: const EdgeInsets.symmetric(vertical: 8.0),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(item.displayName, style: Theme.of(context).textTheme.bodyLarge),
                                      Text(item.fingerprint, style: Theme.of(context).textTheme.bodyMedium),
                                    ],
                                  ),
                                ),
                              ),
                            );
                          },
                        ),
                      ),
                    );
                  },
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _coverCtrl,
                  maxLines: 3,
                  inputFormatters: _coverLimitInputFormatters(
                    isCoverField: true,
                  ),
                  decoration: InputDecoration(
                    labelText: strings(context, 'coverText'),
                    helperText: _coverTooShort
                        ? strings(context, 'coverTooShort')
                            .replaceAll('{n}', '$_coverMissingCount')
                        : null,
                    helperStyle: _coverTooShort
                        ? TextStyle(color: Theme.of(context).colorScheme.error)
                        : null,
                    counterText: _coverLimitCounterText(coverLengthLimit),
                    counterStyle: _coverLengthLimitExceeded
                        ? TextStyle(color: Theme.of(context).colorScheme.error)
                        : null,
                  ),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _secretCtrl,
                  maxLines: 3,
                  inputFormatters: _coverLimitInputFormatters(
                    isCoverField: false,
                  ),
                  decoration: InputDecoration(
                    labelText: strings(context, 'secretText'),
                    counterText: _coverLimitCounterText(coverLengthLimit),
                    counterStyle: _coverLengthLimitExceeded
                        ? TextStyle(color: Theme.of(context).colorScheme.error)
                        : null,
                  ),
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Flexible(
                      child: Text(
                        strings(context, 'deleteAfterRead'),
                        maxLines: 2,
                        softWrap: true,
                        textAlign: TextAlign.right,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Switch.adaptive(
                      value: _deleteAfterRead,
                      onChanged: (value) =>
                          setState(() => _deleteAfterRead = value),
                    ),
                  ],
                ),
                TextField(
                  controller: _expiresCtrl,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText:
                        '${strings(context, 'expiresInMinutes')} (${strings(context, 'optional')})',
                  ),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: !_canGenerate
                      ? null
                      : () async {
                          final recipient = _recipient!;
                          final expiresMinutes =
                              int.tryParse(_expiresCtrl.text.trim());
                          final expireAfter = expiresMinutes == null
                              ? null
                              : (DateTime.now().millisecondsSinceEpoch ~/
                                      1000) +
                                  (expiresMinutes * 60);
                          final encResult = await ref
                              .read(homeControllerProvider)
                              .encryptForRecipient(
                                secretText: _secretCtrl.text,
                                recipient: recipient,
                                expireAfter: expireAfter,
                                deleteAfterRead: _deleteAfterRead,
                              );
                          final encrypted = encResult.message;
                          final rawBytes = encrypted.toRawBytes();
                          if (!StegoEncoder.canEmbedBytes(
                            _coverCtrl.text,
                            rawBytes.length,
                          )) {
                            final missing =
                                StegoEncoder.missingCoverCapacityForBytes(
                              _coverCtrl.text,
                              rawBytes.length,
                            );
                            if (!context.mounted) return;
                            setState(() => _exactCoverMissingCount = missing);
                            final message = strings(context, 'coverTooShort')
                                .replaceAll('{n}', '$missing');
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text(message)),
                            );
                            return;
                          }
                          final output = ref.read(stegoEncoderProvider).encodeBytes(
                              _coverCtrl.text,
                              rawBytes,
                              maxTotalCharacters: _coverLengthLimit);
                          
                          // Only save to chat if deleteAfterRead is false
                          if (!_deleteAfterRead) {
                            final ctrl = ref.read(homeControllerProvider);
                            final keyTag = await ctrl.currentKeyTag();
                            final storageKey = await ctrl.currentStorageKey();
                            final recordId = DateTime.now()
                                        .microsecondsSinceEpoch
                                        .toString();

                            // §12.3: FS plaintext → encrypted aux record
                            if (encResult.isFsEncrypted && _secretCtrl.text.isNotEmpty) {
                              await ref.read(fsPlaintextPersistenceServiceProvider).savePlaintext(
                                messageId: recordId,
                                plaintext: _secretCtrl.text,
                                contactId: recipient.identityId,
                              );
                              final fsController = ref.read(
                                fsOpportunisticControllerProvider(recipient.identityId),
                              );
                              fsController.cachePlaintext(
                                '${recipient.identityId}|$recordId',
                                _secretCtrl.text,
                              );
                            }

                            await ref.read(messagesRepositoryProvider).add(
                                  MessageRecord(
                                    id: recordId,
                                    senderId: 'me',
                                    recipientId: recipient.identityId,
                                    direction: 'outgoing',
                                    timestamp:
                                        DateTime.now().millisecondsSinceEpoch ~/
                                            1000,
                                    text: encResult.isFsEncrypted ? null : _secretCtrl.text,
                                    ciphertextBase64: encrypted.ciphertextBase64,
                                    nonceBase64: encrypted.nonceBase64,
                                    rawSource: output,
                                    expireAfter: expireAfter,
                                    deleteAfterRead: _deleteAfterRead,
                                    keyTag: keyTag,
                                    isFsEncrypted: encResult.isFsEncrypted,
                                    fsClassification: encResult.classification,
                                  ),
                                  storageKey: storageKey,
                                );
                          }
                          
                          if (!mounted) return;
                          setState(() => _output = output);
                        },
                  child: Text(strings(context, 'generateHidden')),
                ),
                const SizedBox(height: 12),
                if (_output.isNotEmpty)
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(12),
                        decoration: ShapeDecoration(
                          color: Theme.of(context)
                              .colorScheme
                              .primary
                              .withValues(alpha: 0.08),
                          shape: ContinuousRectangleBorder(
                            borderRadius: BorderRadius.circular(32),
                            side: BorderSide(
                                color: Theme.of(context)
                                    .colorScheme
                                    .outlineVariant),
                          ),
                        ),
                        child: SelectableText(_output),
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Expanded(
                            child: OutlinedButton.icon(
                              onPressed: () async {
                                final messenger = ScaffoldMessenger.of(context);
                                final strings = AppStrings.t;
                                await ref
                                    .read(clipboardServiceProvider)
                                    .writeText(_output);
                                if (!context.mounted) return;
                                messenger.showSnackBar(
                                  SnackBar(
                                    content: Text(strings(context, 'messageCopiedClipboard')),
                                  ),
                                );
                              },
                              icon: const Icon(Icons.copy_outlined),
                              label: Text(strings(context, 'copy')),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: FilledButton.icon(
                              onPressed: () async {
                                await shareTextExternally(context, _output, forceStegoCover: true);
                              },
                              icon: const Icon(Icons.share_outlined),
                              label: Text(strings(context, 'share')),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
