Pod::Spec.new do |spec|
  spec.name = 'LayergramMlKem'
  spec.version = '0.1.0'
  spec.summary = 'Inactive Layergram protocol-v3 ML-KEM-768 native backend.'
  spec.homepage = 'https://github.com/layergram/layergram'
  spec.license = { :type => 'Apache-2.0', :file => 'LICENSE' }
  spec.author = { 'Layergram' => 'https://layergram.app' }
  spec.source = {
    :git => 'https://github.com/layergram/layergram.git',
    :tag => spec.version.to_s
  }

  spec.ios.deployment_target = '15.5'
  spec.osx.deployment_target = '10.15'
  spec.frameworks = 'Security'
  spec.source_files = 'native/layergram_mlkem/layergram_mlkem.{c,h}'
  spec.public_header_files = 'native/layergram_mlkem/layergram_mlkem.h'
  spec.preserve_paths = [
    'third_party/mlkem-native/LICENSE',
    'third_party/mlkem-native/SOURCE.json',
    'third_party/mlkem-native/mlkem/**/*',
    'third_party/mlkem-native/test/expected_test_vectors.h'
  ]

  spec.compiler_flags = [
    '-std=c99',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Wpedantic',
    '-Wconversion',
    '-Wsign-conversion',
    '-Wshadow',
    '-Wpointer-arith',
    '-Wmissing-prototypes'
  ].join(' ')

  spec.pod_target_xcconfig = {
    'CLANG_C_LANGUAGE_STANDARD' => 'c99',
    'DEFINES_MODULE' => 'YES',
    'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) LG_MLKEM_BUILD=1',
    'GCC_SYMBOLS_PRIVATE_EXTERN' => 'YES',
    'HEADER_SEARCH_PATHS' => [
      '$(inherited)',
      '"$(PODS_TARGET_SRCROOT)/third_party/mlkem-native/mlkem"',
      '"$(PODS_TARGET_SRCROOT)/third_party/mlkem-native/test"'
    ].join(' ')
  }

  # Dart FFI symbol lookup is invisible to the static linker. Explicitly root
  # the narrow ABI so release dead stripping cannot remove it.
  abi_symbols = %w[
    lg_mlkem768_abi_version
    lg_mlkem768_implementation_id
    lg_mlkem768_public_key_bytes
    lg_mlkem768_private_key_bytes
    lg_mlkem768_ciphertext_bytes
    lg_mlkem768_shared_secret_bytes
    lg_mlkem768_keygen_seed_bytes
    lg_mlkem768_encaps_seed_bytes
    lg_mlkem768_keypair_from_seed
    lg_mlkem768_validate_public_key
    lg_mlkem768_encapsulate
    lg_mlkem768_decapsulate
    lg_mlkem768_private_key_destroy
    lg_mlkem768_self_test
  ]
  spec.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) ' +
      abi_symbols.map { |symbol| "-Wl,-u,_#{symbol}" }.join(' ')
  }
end
