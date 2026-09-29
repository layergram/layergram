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

import '../../l10n/app_strings.dart';

/// An already-verified identity must remain available for a fresh SAS
/// comparison when one of its devices is newly restored. Revocation is a
/// separate, explicit action and never a prerequisite for seeing the code.
class ContactVerificationActions extends StatelessWidget {
  const ContactVerificationActions({
    super.key,
    required this.verified,
    required this.onCompare,
    required this.onRevoke,
    this.enabled = true,
  });

  final bool verified;
  final bool enabled;
  final VoidCallback onCompare;
  final VoidCallback onRevoke;

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        FilledButton.tonal(
          onPressed: enabled ? onCompare : null,
          child: Text(AppStrings.t(context,
              verified ? 'verifyContactTitle' : 'verifyContactCtaVerifyNow')),
        ),
        if (verified)
          TextButton(
            onPressed: enabled ? onRevoke : null,
            child: Text(
                AppStrings.t(context, 'verifyContactCtaRevokeVerification')),
          ),
      ],
    );
  }
}
