#import <UIKit/UIKit.h>

// UIKit can return nil before the keyboard's proxy is attached even though its
// documentIdentifier property is annotated nonnull. Read it in Objective-C so
// Swift does not unconditionally bridge a missing NSUUID into a UUID and trap.
// This reads only the opaque identifier, never any text from the host editor.
static inline NSString * _Nullable LGKeyboardDocumentIdentifier(
    id<UITextDocumentProxy> _Nonnull proxy) {
  return [proxy.documentIdentifier UUIDString];
}
