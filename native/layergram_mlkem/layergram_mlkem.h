// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#ifndef LAYERGRAM_MLKEM_H
#define LAYERGRAM_MLKEM_H

#include <stdint.h>

#if defined(_WIN32)
#if defined(LG_MLKEM_BUILD)
#define LG_MLKEM_EXPORT __declspec(dllexport)
#else
#define LG_MLKEM_EXPORT __declspec(dllimport)
#endif
#else
#define LG_MLKEM_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
  LG_MLKEM768_ABI_VERSION = 1,
  LG_MLKEM768_PUBLIC_KEY_BYTES = 1184,
  LG_MLKEM768_PRIVATE_KEY_BYTES = 2400,
  LG_MLKEM768_CIPHERTEXT_BYTES = 1088,
  LG_MLKEM768_SHARED_SECRET_BYTES = 32,
  LG_MLKEM768_KEYGEN_SEED_BYTES = 64,
  LG_MLKEM768_ENCAPS_SEED_BYTES = 32
};

enum lg_mlkem_status {
  LG_MLKEM_OK = 0,
  LG_MLKEM_ERR_INVALID_ARGUMENT = -1,
  LG_MLKEM_ERR_ALLOCATION = -2,
  LG_MLKEM_ERR_INVALID_PUBLIC_KEY = -3,
  LG_MLKEM_ERR_INVALID_PRIVATE_KEY = -4,
  LG_MLKEM_ERR_BACKEND = -5,
  LG_MLKEM_ERR_INVALID_HANDLE = -6,
  LG_MLKEM_ERR_SELF_TEST = -7,
  LG_MLKEM_ERR_ENTROPY = -8
};

typedef struct lg_mlkem768_private_key lg_mlkem768_private_key;

LG_MLKEM_EXPORT uint32_t lg_mlkem768_abi_version(void);
LG_MLKEM_EXPORT const char *lg_mlkem768_implementation_id(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_public_key_bytes(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_private_key_bytes(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_ciphertext_bytes(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_shared_secret_bytes(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_keygen_seed_bytes(void);
LG_MLKEM_EXPORT uint32_t lg_mlkem768_encaps_seed_bytes(void);

// The returned private-key handle owns native memory. The caller must destroy
// it exactly once with lg_mlkem768_private_key_destroy().
LG_MLKEM_EXPORT int32_t lg_mlkem768_keypair_from_seed(
    const uint8_t *seed, uint64_t seed_len, uint8_t *public_key,
    uint64_t public_key_len, lg_mlkem768_private_key **private_key_out);

LG_MLKEM_EXPORT int32_t lg_mlkem768_validate_public_key(
    const uint8_t *public_key, uint64_t public_key_len);

// Production encapsulation obtains fresh entropy inside the native wrapper
// directly from the operating-system CSPRNG.
LG_MLKEM_EXPORT int32_t lg_mlkem768_encapsulate(
    const uint8_t *public_key, uint64_t public_key_len, uint8_t *ciphertext,
    uint64_t ciphertext_len, uint8_t *shared_secret,
    uint64_t shared_secret_len);

// ML-KEM implicit rejection is preserved: a malformed ciphertext does not
// produce a validity signal. It produces the FIPS 203 rejection secret.
LG_MLKEM_EXPORT int32_t lg_mlkem768_decapsulate(
    const lg_mlkem768_private_key *private_key,
    const uint8_t *ciphertext, uint64_t ciphertext_len,
    uint8_t *shared_secret, uint64_t shared_secret_len);

LG_MLKEM_EXPORT void lg_mlkem768_private_key_destroy(
    lg_mlkem768_private_key *private_key);

LG_MLKEM_EXPORT int32_t lg_mlkem768_self_test(void);

#if defined(LG_MLKEM_TESTING)
// Deterministic FIPS 203 Encaps_Internal boundary for KATs only. It is absent
// from production libraries so application code cannot inject weak entropy.
LG_MLKEM_EXPORT int32_t lg_mlkem768_test_encapsulate_from_seed(
    const uint8_t *public_key, uint64_t public_key_len,
    const uint8_t *encaps_seed, uint64_t encaps_seed_len,
    uint8_t *ciphertext, uint64_t ciphertext_len, uint8_t *shared_secret,
    uint64_t shared_secret_len);
LG_MLKEM_EXPORT uint64_t lg_mlkem768_test_destroyed_handle_count(void);
LG_MLKEM_EXPORT int32_t lg_mlkem768_test_last_destroy_was_zero(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
