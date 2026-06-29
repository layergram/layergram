enum MessageOutputMode {
  cover,
  text,
  link;

  static const defaultMode = MessageOutputMode.text;

  String get storageValue {
    switch (this) {
      case MessageOutputMode.cover:
        return 'cover';
      case MessageOutputMode.text:
        return 'text';
      case MessageOutputMode.link:
        return 'link';
    }
  }

  static MessageOutputMode fromStorageValue(String? value) {
    switch (value) {
      case 'cover':
        return MessageOutputMode.cover;
      case 'link':
        return MessageOutputMode.link;
      case 'text':
      default:
        return defaultMode;
    }
  }
}
