import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/identity_runtime_v3.dart';
import 'package:layergram/core/providers.dart';

void main() {
  test('active selector without an identity never constructs a v3 runtime',
      () async {
    var mlKemLoads = 0;
    var applicationOpens = 0;
    final identityRuntime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: () {
        mlKemLoads++;
        throw StateError('unscoped v3 must not load ML-KEM');
      },
    );
    Future<V3ApplicationSessionRuntime> factory({
      required localIdentity,
      required scopeToken,
    }) async {
      applicationOpens++;
      throw StateError('unscoped v3 must not open SCKA');
    }

    final container = ProviderContainer(
      overrides: [
        v3IdentityRuntimeProvider.overrideWithValue(identityRuntime),
        v3ApplicationRuntimeFactoryProvider.overrideWithValue(factory),
      ],
    );
    addTearDown(() async {
      container.dispose();
      await identityRuntime.close();
    });

    expect(await container.read(v3ApplicationSessionRuntimeProvider.future),
        isNull);
    expect(mlKemLoads, 0);
    expect(applicationOpens, 0);
  });
}
