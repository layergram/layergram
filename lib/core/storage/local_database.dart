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

import 'package:hive_flutter/hive_flutter.dart';

class LocalDatabase {
  static const String identitiesBoxName = 'layergram_identities';
  static const String messagesBoxName = 'layergram_messages';
  static const String chatMetaBoxName = 'layergram_chat_meta';

  static Future<void> init() async {
    await Hive.initFlutter();
    if (!Hive.isBoxOpen(identitiesBoxName)) {
      await Hive.openBox<Map>(identitiesBoxName);
    }
    if (!Hive.isBoxOpen(messagesBoxName)) {
      await Hive.openBox<Map>(messagesBoxName);
    }
    if (!Hive.isBoxOpen(chatMetaBoxName)) {
      await Hive.openBox<Map>(chatMetaBoxName);
    }
  }

  static Future<void> clearAll() async {
    if (!Hive.isBoxOpen(identitiesBoxName)) {
      await Hive.openBox<Map>(identitiesBoxName);
    }
    if (!Hive.isBoxOpen(messagesBoxName)) {
      await Hive.openBox<Map>(messagesBoxName);
    }
    if (!Hive.isBoxOpen(chatMetaBoxName)) {
      await Hive.openBox<Map>(chatMetaBoxName);
    }

    await Hive.box<Map>(identitiesBoxName).clear();
    await Hive.box<Map>(messagesBoxName).clear();
    await Hive.box<Map>(chatMetaBoxName).clear();
  }
}
