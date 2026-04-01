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

import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

class CoverGeneratorView extends ConsumerStatefulWidget {
  const CoverGeneratorView({super.key});

  @override
  ConsumerState<CoverGeneratorView> createState() => _CoverGeneratorViewState();
}

class _CoverGeneratorViewState extends ConsumerState<CoverGeneratorView> {
  final _toneCtrl = TextEditingController();

  bool _busy = false;
  String _output = '';
  String? _error;

  @override
  void dispose() {
    _toneCtrl.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    if (_busy) return;

    final caps = ref.read(layergramCapabilitiesProvider);
    final generator = caps.coverGenerator;
    if (!generator.isAvailable) return;

    setState(() {
      _busy = true;
      _error = null;
      _output = '';
    });

    try {
      final locale = Localizations.localeOf(context);
      final tone = _toneCtrl.text.trim();
      final result = await generator.generate(
        languageCode: locale.languageCode,
        recentMessages: const <String>[],
        tone: tone.isEmpty ? null : tone,
      );
      if (!mounted) return;
      setState(() {
        _busy = false;
        _output = result;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final caps = ref.watch(layergramCapabilitiesProvider);
    final available = caps.coverGenerator.isAvailable;

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(title: Text(t(context, 'premiumCoverTitle'))),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: available
            ? _buildAvailable(context, t)
            : _buildLocked(context, t),
      ),
    );
  }

  Widget _buildLocked(
    BuildContext context,
    String Function(BuildContext, String) t,
  ) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.lock_outline, size: 44),
          const SizedBox(height: 12),
          Text(
            t(context, 'premiumTag'),
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            t(context, 'premiumNotAvailable'),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildAvailable(
    BuildContext context,
    String Function(BuildContext, String) t,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(t(context, 'premiumCoverSubtitle')),
        const SizedBox(height: 16),
        TextField(
          controller: _toneCtrl,
          decoration: InputDecoration(
            labelText: t(context, 'toneOptional'),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: _busy ? null : _generate,
          icon: const Icon(Icons.auto_awesome),
          label: Text(t(context, 'generateCover')),
        ),
        const SizedBox(height: 16),
        if (_busy) const LinearProgressIndicator(),
        if (_error != null) ...[
          const SizedBox(height: 8),
          Text(
            _error!,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ],
        if (_output.isNotEmpty) ...[
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: ShapeDecoration(
              color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.06),
              shape: ContinuousRectangleBorder(
                borderRadius: BorderRadius.circular(32),
                side: BorderSide(color: Theme.of(context).colorScheme.outlineVariant),
              ),
            ),
            child: SelectableText(_output),
          ),
          const SizedBox(height: 10),
          OutlinedButton.icon(
            onPressed: () async {
              await ref.read(clipboardServiceProvider).writeText(_output);
              if (!context.mounted) return;
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(t(context, 'copy'))),
              );
            },
            icon: const Icon(Icons.copy),
            label: Text(t(context, 'copy')),
          ),
        ],
      ],
    );
  }
}
