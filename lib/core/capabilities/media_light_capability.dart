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

import 'dart:typed_data';

enum MediaLightKind {
  photo,
  audio,
}

class MediaLightDraft {
  const MediaLightDraft({
    required this.kind,
    required this.bytes,
    required this.mimeType,
    this.fileName,
    this.durationMs,
    this.width,
    this.height,
  });

  final MediaLightKind kind;
  final Uint8List bytes;
  final String mimeType;
  final String? fileName;

  /// Duration for audio (or video in the future), if known.
  final int? durationMs;

  /// Dimensions for photos, if known.
  final int? width;
  final int? height;
}

class MediaLightAttachment {
  const MediaLightAttachment({
    required this.kind,
    required this.mimeType,
    required this.payload,
    this.fileName,
    this.byteLength,
    this.durationMs,
    this.width,
    this.height,
  });

  final MediaLightKind kind;
  final String mimeType;

  /// Opaque, already-encrypted attachment representation.
  ///
  /// The core treats this as an opaque string. The premium implementation can
  /// decide whether this is a base64 payload, a token, or a link.
  final String payload;

  final String? fileName;
  final int? byteLength;
  final int? durationMs;
  final int? width;
  final int? height;
}

abstract class MediaLightCapability {
  bool get isAvailable;

  Future<MediaLightDraft?> pickPhoto();

  Future<MediaLightDraft?> recordAudio();

  Future<MediaLightAttachment?> encryptAndAttach({
    required MediaLightDraft draft,
    required String senderId,
    required String recipientId,
    required String senderPrivateKeyBase64,
    required String recipientPublicKeyBase64,
    int? expireAfter,
    bool deleteAfterRead = false,
  });
}

class NoMediaLightCapability implements MediaLightCapability {
  const NoMediaLightCapability();

  @override
  bool get isAvailable => false;

  @override
  Future<MediaLightDraft?> pickPhoto() async => null;

  @override
  Future<MediaLightDraft?> recordAudio() async => null;

  @override
  Future<MediaLightAttachment?> encryptAndAttach({
    required MediaLightDraft draft,
    required String senderId,
    required String recipientId,
    required String senderPrivateKeyBase64,
    required String recipientPublicKeyBase64,
    int? expireAfter,
    bool deleteAfterRead = false,
  }) async {
    return null;
  }
}
