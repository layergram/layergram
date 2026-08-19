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
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../core/crypto/models.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import 'identities_controller.dart';

class AddIdentityView extends ConsumerStatefulWidget {
  const AddIdentityView({super.key, this.initialText});

  final String? initialText;

  @override
  ConsumerState<AddIdentityView> createState() => _AddIdentityViewState();
}

class _AddIdentityViewState extends ConsumerState<AddIdentityView> {
  final _controller = TextEditingController();
  final _inputFocusNode = FocusNode();
  String? _error;
  bool _qrImported = false;
  RemoteIdentity? _pendingIdentity;

  @override
  void dispose() {
    _inputFocusNode.dispose();
    _controller.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    final initial = widget.initialText;
    if (initial != null && initial.trim().isNotEmpty) {
      _controller.text = initial;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          _parseText(context);
        }
      });
    }
  }

  Future<String> _readClipboardImportText() async {
    final directText = await ref.read(clipboardServiceProvider).readText();
    if (directText.trim().isNotEmpty) {
      return directText;
    }

    const fallbackFormats = <String>[
      'text/uri-list',
      'public.url',
      'public.utf8-plain-text',
    ];

    for (final format in fallbackFormats) {
      try {
        final data = await Clipboard.getData(format);
        final text = data?.text;
        if (text != null && text.trim().isNotEmpty) {
          return text;
        }
      } on PlatformException {
        continue;
      }
    }

    return '';
  }

  Future<void> _pasteFromClipboard(BuildContext context) async {
    final text = await _readClipboardImportText();
    if (!context.mounted || text.isEmpty) return;

    FocusScope.of(context).requestFocus(_inputFocusNode);
    setState(() {
      _controller.value = TextEditingValue(
        text: text,
        selection: TextSelection.collapsed(offset: text.length),
      );
      _error = null;
      _pendingIdentity = null;
    });
  }

  Future<void> _parseText(BuildContext context) async {
    FocusScope.of(context).unfocus();
    final input = _controller.text;
    try {
      final parsed =
          ref.read(identitiesControllerProvider).parseIdentityImport(input);
      setState(() {
        _pendingIdentity = parsed;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = AppStrings.t(context, 'invalidLayergramLink'));
    }
  }

  Future<void> _confirmImport(BuildContext context) async {
    final identity = _pendingIdentity;
    if (identity == null) return;
    await ref.read(identitiesControllerProvider).saveIdentity(identity);
    if (context.mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(title: Text(t(context, 'addIdentityTitle'))),
      body: DefaultTabController(
        length: 2,
        child: Column(
          children: [
            TabBar(
              dividerColor: Colors.transparent,
              indicatorSize: TabBarIndicatorSize.tab,
              labelPadding:
                  const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              indicator: ShapeDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .primary
                    .withValues(alpha: 0.22),
                shape: ContinuousRectangleBorder(
                    borderRadius: BorderRadius.circular(48)),
              ),
              tabs: [
                Tab(text: t(context, 'pasteLinkTab')),
                Tab(text: t(context, 'scanQr')),
              ],
            ),
            Expanded(
              child: TabBarView(
                children: [
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Card(
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          children: [
                            TextField(
                              controller: _controller,
                              focusNode: _inputFocusNode,
                              minLines: 2,
                              maxLines: 4,
                              decoration: InputDecoration(
                                labelText: t(context, 'pasteLinkLabel'),
                                hintText: 'layergram://...',
                              ),
                            ),
                            const SizedBox(height: 6),
                            Align(
                              alignment: Alignment.centerLeft,
                              child: Text(
                                t(context, 'pasteLinkHint'),
                                style: const TextStyle(
                                    fontSize: 12, color: Colors.grey),
                              ),
                            ),
                            if (_error != null) ...[
                              const SizedBox(height: 8),
                              Text(_error!,
                                  style: const TextStyle(color: Colors.red)),
                            ],
                            const SizedBox(height: 12),
                            Row(
                              children: [
                                Expanded(
                                  child: FilledButton.tonal(
                                    onPressed: () =>
                                        _pasteFromClipboard(context),
                                    child:
                                        Text(t(context, 'pasteFromClipboard')),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: FilledButton(
                                    onPressed: () => _parseText(context),
                                    child: Text(t(context, 'import')),
                                  ),
                                ),
                              ],
                            ),
                            if (_pendingIdentity != null) ...[
                              const SizedBox(height: 12),
                              Card(
                                child: Padding(
                                  padding: const EdgeInsets.all(12),
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        _pendingIdentity!.displayName,
                                        style: Theme.of(context)
                                            .textTheme
                                            .titleMedium,
                                      ),
                                      const SizedBox(height: 8),
                                      Text(
                                        '${t(context, 'identityIdLabel')}: ${_pendingIdentity!.identityId}',
                                      ),
                                      Text(
                                        '${t(context, 'fingerprintLabel')}: ${_pendingIdentity!.fingerprint}',
                                      ),
                                      const SizedBox(height: 8),
                                      Align(
                                        alignment: Alignment.centerRight,
                                        child: FilledButton(
                                          onPressed: () =>
                                              _confirmImport(context),
                                          child: Text(t(context, 'save')),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      children: [
                        Text(t(context, 'scanIdentityQrHint')),
                        const SizedBox(height: 12),
                        Expanded(
                          child: ClipPath(
                            clipper: ShapeBorderClipper(
                              shape: ContinuousRectangleBorder(
                                borderRadius: BorderRadius.circular(32),
                              ),
                            ),
                            child: MobileScanner(
                              onDetect: (capture) async {
                                if (_qrImported) return;
                                final barcode = capture.barcodes.first;
                                final Object? value =
                                    switch (barcode.rawDecodedBytes) {
                                  DecodedBarcodeBytes(:final bytes) => bytes,
                                  DecodedVisionBarcodeBytes(:final bytes?) =>
                                    bytes,
                                  _ => barcode.rawValue,
                                };
                                if (value == null ||
                                    (value is String && value.isEmpty)) {
                                  return;
                                }
                                _qrImported = true;
                                try {
                                  final parsed = ref
                                      .read(identitiesControllerProvider)
                                      .parseIdentityFromQrPayload(value);
                                  setState(() {
                                    _pendingIdentity = parsed;
                                    _error = null;
                                  });
                                } catch (e) {
                                  setState(() => _error =
                                      AppStrings.t(context, 'invalidQrCode'));
                                  _qrImported = false;
                                }
                              },
                            ),
                          ),
                        ),
                        if (_error != null) ...[
                          const SizedBox(height: 8),
                          Text(_error!,
                              style: const TextStyle(color: Colors.red)),
                        ],
                        if (_pendingIdentity != null) ...[
                          const SizedBox(height: 8),
                          Card(
                            child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    _pendingIdentity!.displayName,
                                    style:
                                        Theme.of(context).textTheme.titleMedium,
                                  ),
                                  const SizedBox(height: 6),
                                  Text(
                                    '${t(context, 'identityIdLabel')}: ${_pendingIdentity!.identityId}',
                                  ),
                                  Text(
                                    '${t(context, 'fingerprintLabel')}: ${_pendingIdentity!.fingerprint}',
                                  ),
                                  const SizedBox(height: 8),
                                  Align(
                                    alignment: Alignment.centerRight,
                                    child: FilledButton(
                                      onPressed: () => _confirmImport(context),
                                      child: Text(t(context, 'save')),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
