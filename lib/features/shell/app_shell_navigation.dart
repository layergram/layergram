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

import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Requests that the shell opens the Contacts import flow.
///
/// The shell owns section selection, so child views use this provider instead
/// of hard-coding a navigation index that could change when Premium folders
/// are present.
final pendingIdentityImportProvider = StateProvider<String?>((_) => null);
