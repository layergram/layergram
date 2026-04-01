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
  String? _error;
  bool _qrImported = false;
  RemoteIdentity? _pendingIdentity;

  @override
  void initState() {
    super.initState();
    final initial = widget.initialText;
    if (initial != null && initial.trim().isNotEmpty) {
      _controller.text = initial;
    }
  }

  Future<void> _parseText(BuildContext context) async {
    final input = _controller.text;
    try {
      final parsed = input.trim().startsWith('layergram://')
          ? ref.read(identitiesControllerProvider).parseIdentityFromLink(input)
          : ref.read(identitiesControllerProvider).parseIdentityFromText(input);
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
              labelPadding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              indicator: ShapeDecoration(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.22),
                shape: ContinuousRectangleBorder(borderRadius: BorderRadius.circular(48)),
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
                                style: const TextStyle(fontSize: 12, color: Colors.grey),
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
                                    onPressed: () async {
                                      final text = await ref
                                          .read(clipboardServiceProvider)
                                          .readText();
                                      setState(() => _controller.text = text);
                                    },
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
                                final value = capture.barcodes.first.rawValue;
                                if (value == null || value.isEmpty) return;
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
                                  setState(() => _error = AppStrings.t(context, 'invalidQrCode'));
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
