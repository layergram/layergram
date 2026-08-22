// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#include "layergram_mlkem.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <Security/SecRandom.h>
#include <os/lock.h>
#elif defined(__ANDROID__)
// arc4random_buf is provided by Android's Bionic libc on every supported
// Layergram API level. It handles kernel getrandom and /dev/urandom fallback
// internally and has no caller-visible failure mode.
#include <pthread.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <pthread.h>
#include <sys/random.h>
#else
#error Layergram ML-KEM requires an approved operating-system CSPRNG
#endif

// Build only ML-KEM-768 and expose only Layergram's narrow wrapper ABI.
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX layergram_upstream_mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static

#include "mlkem_native.h"

enum {
  LG_UPSTREAM_ERR_OUT_OF_MEMORY = MLK_ERR_OUT_OF_MEMORY,
  LG_UPSTREAM_ERR_INVALID_PK = MLK_ERR_INVALID_PK,
  LG_UPSTREAM_ERR_INVALID_SK = MLK_ERR_INVALID_SK
};

static int (*const lg_upstream_keypair_from_seed)(uint8_t *, uint8_t *,
                                                   const uint8_t *) =
    layergram_upstream_mlkem_keypair_derand;
static int (*const lg_upstream_encapsulate_from_seed)(
    uint8_t *, uint8_t *, const uint8_t *, const uint8_t *) =
    layergram_upstream_mlkem_enc_derand;
static int (*const lg_upstream_decapsulate)(uint8_t *, const uint8_t *,
                                            const uint8_t *) =
    layergram_upstream_mlkem_dec;
static int (*const lg_upstream_validate_public_key)(const uint8_t *) =
    layergram_upstream_mlkem_check_pk;
static int (*const lg_upstream_validate_private_key)(const uint8_t *) =
    layergram_upstream_mlkem_check_sk;

// Single compilation unit from the exact vendored upstream commit.
#include "mlkem_native.c"

#include "expected_test_vectors.h"

#define LG_PRIVATE_KEY_MAGIC UINT64_C(0x4c47334d4c4b454d)
#define LG_MAX_LIVE_PRIVATE_KEYS 4096U

typedef struct lg_mlkem768_private_key_record {
  uint64_t magic;
  uint8_t bytes[LG_MLKEM768_PRIVATE_KEY_BYTES];
  uintptr_t token;
  struct lg_mlkem768_private_key_record *next;
} lg_mlkem768_private_key_record;

static lg_mlkem768_private_key_record *lg_live_private_keys = NULL;
static size_t lg_live_private_key_count = 0;
static uintptr_t lg_next_private_key_token = (uintptr_t)1U;

#if defined(_WIN32)
static SRWLOCK lg_private_key_registry_lock = SRWLOCK_INIT;

static void lg_private_key_registry_acquire(void) {
  AcquireSRWLockExclusive(&lg_private_key_registry_lock);
}

static void lg_private_key_registry_release(void) {
  ReleaseSRWLockExclusive(&lg_private_key_registry_lock);
}
#elif defined(__APPLE__)
static os_unfair_lock lg_private_key_registry_lock = OS_UNFAIR_LOCK_INIT;

static void lg_private_key_registry_acquire(void) {
  os_unfair_lock_lock(&lg_private_key_registry_lock);
}

static void lg_private_key_registry_release(void) {
  os_unfair_lock_unlock(&lg_private_key_registry_lock);
}
#else
static pthread_mutex_t lg_private_key_registry_lock = PTHREAD_MUTEX_INITIALIZER;

static void lg_private_key_registry_acquire(void) {
  (void)pthread_mutex_lock(&lg_private_key_registry_lock);
}

static void lg_private_key_registry_release(void) {
  (void)pthread_mutex_unlock(&lg_private_key_registry_lock);
}
#endif

#if defined(LG_MLKEM_TESTING)
static uint64_t lg_destroyed_handle_count = 0;
static int32_t lg_last_destroy_was_zero = 0;
#endif

static void lg_secure_zero(void *pointer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  size_t index;
  if (pointer == NULL) {
    return;
  }
  for (index = 0; index < length; index++) {
    bytes[index] = 0;
  }
}

static lg_mlkem768_private_key_record *lg_find_private_key_locked(
    const lg_mlkem768_private_key *private_key) {
  const uintptr_t token = (uintptr_t)private_key;
  lg_mlkem768_private_key_record *candidate = lg_live_private_keys;
  while (candidate != NULL) {
    if (candidate->token == token) {
      return candidate;
    }
    candidate = candidate->next;
  }
  return NULL;
}

static int32_t lg_register_private_key(
    lg_mlkem768_private_key_record *record,
    lg_mlkem768_private_key **private_key_out) {
  uintptr_t token;
  if (record == NULL || private_key_out == NULL) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }
  lg_private_key_registry_acquire();
  if (lg_live_private_key_count >= LG_MAX_LIVE_PRIVATE_KEYS ||
      lg_next_private_key_token == (uintptr_t)0U ||
      lg_next_private_key_token > UINTPTR_MAX - (uintptr_t)2U) {
    lg_private_key_registry_release();
    return LG_MLKEM_ERR_ALLOCATION;
  }
  token = lg_next_private_key_token;
  lg_next_private_key_token += (uintptr_t)2U;
  record->token = token;
  record->next = lg_live_private_keys;
  lg_live_private_keys = record;
  lg_live_private_key_count++;
  *private_key_out = (lg_mlkem768_private_key *)token;
  lg_private_key_registry_release();
  return LG_MLKEM_OK;
}

static int lg_private_key_bytes_equal(
    const lg_mlkem768_private_key *private_key, const uint8_t *expected,
    size_t expected_len) {
  lg_mlkem768_private_key_record *record;
  int equal = 0;
  lg_private_key_registry_acquire();
  record = lg_find_private_key_locked(private_key);
  if (record != NULL && record->magic == LG_PRIVATE_KEY_MAGIC &&
      expected != NULL && expected_len == sizeof(record->bytes)) {
    equal = memcmp(record->bytes, expected, expected_len) == 0 ? 1 : 0;
  }
  lg_private_key_registry_release();
  return equal;
}

#if defined(LG_MLKEM_TESTING)
static int lg_is_all_zero(const void *pointer, size_t length) {
  const volatile uint8_t *bytes = (const volatile uint8_t *)pointer;
  uint8_t difference = 0;
  size_t index;
  for (index = 0; index < length; index++) {
    difference = (uint8_t)(difference | bytes[index]);
  }
  return difference == 0;
}
#endif

static int32_t lg_map_upstream_status(int status) {
  if (status == 0) {
    return LG_MLKEM_OK;
  }
  if (status == LG_UPSTREAM_ERR_OUT_OF_MEMORY) {
    return LG_MLKEM_ERR_ALLOCATION;
  }
  if (status == LG_UPSTREAM_ERR_INVALID_PK) {
    return LG_MLKEM_ERR_INVALID_PUBLIC_KEY;
  }
  if (status == LG_UPSTREAM_ERR_INVALID_SK) {
    return LG_MLKEM_ERR_INVALID_PRIVATE_KEY;
  }
  return LG_MLKEM_ERR_BACKEND;
}

static int32_t lg_secure_random(uint8_t *output, size_t length) {
#if defined(__APPLE__)
  return SecRandomCopyBytes(kSecRandomDefault, length, output) == errSecSuccess
             ? LG_MLKEM_OK
             : LG_MLKEM_ERR_ENTROPY;
#elif defined(__ANDROID__)
  arc4random_buf(output, length);
  return LG_MLKEM_OK;
#elif defined(_WIN32)
  return BCryptGenRandom(NULL, output, (ULONG)length,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
             ? LG_MLKEM_OK
             : LG_MLKEM_ERR_ENTROPY;
#elif defined(__linux__)
  size_t offset = 0;
  while (offset < length) {
    const ssize_t count = getrandom(output + offset, length - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      lg_secure_zero(output, length);
      return LG_MLKEM_ERR_ENTROPY;
    }
    offset += (size_t)count;
  }
  return LG_MLKEM_OK;
#endif
}

uint32_t lg_mlkem768_abi_version(void) { return LG_MLKEM768_ABI_VERSION; }

const char *lg_mlkem768_implementation_id(void) {
  return "mlkem-native-v2.0.0-d1b2fe782888bdb7+layergram-abi1";
}

uint32_t lg_mlkem768_public_key_bytes(void) {
  return LG_MLKEM768_PUBLIC_KEY_BYTES;
}

uint32_t lg_mlkem768_private_key_bytes(void) {
  return LG_MLKEM768_PRIVATE_KEY_BYTES;
}

uint32_t lg_mlkem768_ciphertext_bytes(void) {
  return LG_MLKEM768_CIPHERTEXT_BYTES;
}

uint32_t lg_mlkem768_shared_secret_bytes(void) {
  return LG_MLKEM768_SHARED_SECRET_BYTES;
}

uint32_t lg_mlkem768_keygen_seed_bytes(void) {
  return LG_MLKEM768_KEYGEN_SEED_BYTES;
}

uint32_t lg_mlkem768_encaps_seed_bytes(void) {
  return LG_MLKEM768_ENCAPS_SEED_BYTES;
}

int32_t lg_mlkem768_keypair_from_seed(
    const uint8_t *seed, uint64_t seed_len, uint8_t *public_key,
    uint64_t public_key_len, lg_mlkem768_private_key **private_key_out) {
  lg_mlkem768_private_key_record *private_key;
  int32_t register_status;
  int status;

  if (private_key_out != NULL) {
    *private_key_out = NULL;
  }
  if (public_key != NULL &&
      public_key_len == LG_MLKEM768_PUBLIC_KEY_BYTES) {
    lg_secure_zero(public_key, LG_MLKEM768_PUBLIC_KEY_BYTES);
  }
  if (seed == NULL || seed_len != LG_MLKEM768_KEYGEN_SEED_BYTES ||
      public_key == NULL ||
      public_key_len != LG_MLKEM768_PUBLIC_KEY_BYTES ||
      private_key_out == NULL) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }

  private_key =
      (lg_mlkem768_private_key_record *)calloc(1, sizeof(*private_key));
  if (private_key == NULL) {
    return LG_MLKEM_ERR_ALLOCATION;
  }

  status = lg_upstream_keypair_from_seed(public_key, private_key->bytes, seed);
  if (status == 0) {
    status = lg_upstream_validate_private_key(private_key->bytes);
  }
  if (status != 0) {
    lg_secure_zero(public_key, LG_MLKEM768_PUBLIC_KEY_BYTES);
    lg_secure_zero(private_key, sizeof(*private_key));
    free(private_key);
    return lg_map_upstream_status(status);
  }

  private_key->magic = LG_PRIVATE_KEY_MAGIC;
  register_status = lg_register_private_key(private_key, private_key_out);
  if (register_status != LG_MLKEM_OK) {
    lg_secure_zero(public_key, LG_MLKEM768_PUBLIC_KEY_BYTES);
    lg_secure_zero(private_key, sizeof(*private_key));
    free(private_key);
    return register_status;
  }
  return LG_MLKEM_OK;
}

int32_t lg_mlkem768_validate_public_key(const uint8_t *public_key,
                                        uint64_t public_key_len) {
  if (public_key == NULL ||
      public_key_len != LG_MLKEM768_PUBLIC_KEY_BYTES) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }
  return lg_map_upstream_status(lg_upstream_validate_public_key(public_key));
}

static int32_t lg_mlkem768_encapsulate_from_seed_internal(
    const uint8_t *public_key, uint64_t public_key_len,
    const uint8_t *encaps_seed, uint64_t encaps_seed_len,
    uint8_t *ciphertext, uint64_t ciphertext_len, uint8_t *shared_secret,
    uint64_t shared_secret_len) {
  int status;

  if (ciphertext != NULL &&
      ciphertext_len == LG_MLKEM768_CIPHERTEXT_BYTES) {
    lg_secure_zero(ciphertext, LG_MLKEM768_CIPHERTEXT_BYTES);
  }
  if (shared_secret != NULL &&
      shared_secret_len == LG_MLKEM768_SHARED_SECRET_BYTES) {
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  if (public_key == NULL ||
      public_key_len != LG_MLKEM768_PUBLIC_KEY_BYTES ||
      encaps_seed == NULL ||
      encaps_seed_len != LG_MLKEM768_ENCAPS_SEED_BYTES ||
      ciphertext == NULL ||
      ciphertext_len != LG_MLKEM768_CIPHERTEXT_BYTES ||
      shared_secret == NULL ||
      shared_secret_len != LG_MLKEM768_SHARED_SECRET_BYTES) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }

  status = lg_upstream_validate_public_key(public_key);
  if (status == 0) {
    status = lg_upstream_encapsulate_from_seed(
        ciphertext, shared_secret, public_key, encaps_seed);
  }
  if (status != 0) {
    lg_secure_zero(ciphertext, LG_MLKEM768_CIPHERTEXT_BYTES);
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  return lg_map_upstream_status(status);
}

int32_t lg_mlkem768_encapsulate(const uint8_t *public_key,
                                uint64_t public_key_len,
                                uint8_t *ciphertext,
                                uint64_t ciphertext_len,
                                uint8_t *shared_secret,
                                uint64_t shared_secret_len) {
  uint8_t encaps_seed[LG_MLKEM768_ENCAPS_SEED_BYTES];
  int32_t status;

  if (ciphertext != NULL &&
      ciphertext_len == LG_MLKEM768_CIPHERTEXT_BYTES) {
    lg_secure_zero(ciphertext, LG_MLKEM768_CIPHERTEXT_BYTES);
  }
  if (shared_secret != NULL &&
      shared_secret_len == LG_MLKEM768_SHARED_SECRET_BYTES) {
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  if (public_key == NULL ||
      public_key_len != LG_MLKEM768_PUBLIC_KEY_BYTES ||
      ciphertext == NULL ||
      ciphertext_len != LG_MLKEM768_CIPHERTEXT_BYTES ||
      shared_secret == NULL ||
      shared_secret_len != LG_MLKEM768_SHARED_SECRET_BYTES) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }

  status = lg_secure_random(encaps_seed, sizeof(encaps_seed));
  if (status == LG_MLKEM_OK) {
    status = lg_mlkem768_encapsulate_from_seed_internal(
        public_key, public_key_len, encaps_seed, sizeof(encaps_seed),
        ciphertext, ciphertext_len, shared_secret, shared_secret_len);
  } else {
    lg_secure_zero(ciphertext, LG_MLKEM768_CIPHERTEXT_BYTES);
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  lg_secure_zero(encaps_seed, sizeof(encaps_seed));
  return status;
}

int32_t lg_mlkem768_decapsulate(
    const lg_mlkem768_private_key *private_key,
    const uint8_t *ciphertext, uint64_t ciphertext_len,
    uint8_t *shared_secret, uint64_t shared_secret_len) {
  lg_mlkem768_private_key_record *record;
  int status;

  if (shared_secret != NULL &&
      shared_secret_len == LG_MLKEM768_SHARED_SECRET_BYTES) {
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  if (private_key == NULL) {
    return LG_MLKEM_ERR_INVALID_HANDLE;
  }
  if (ciphertext == NULL ||
      ciphertext_len != LG_MLKEM768_CIPHERTEXT_BYTES ||
      shared_secret == NULL ||
      shared_secret_len != LG_MLKEM768_SHARED_SECRET_BYTES) {
    return LG_MLKEM_ERR_INVALID_ARGUMENT;
  }

  lg_private_key_registry_acquire();
  record = lg_find_private_key_locked(private_key);
  if (record == NULL || record->magic != LG_PRIVATE_KEY_MAGIC) {
    lg_private_key_registry_release();
    return LG_MLKEM_ERR_INVALID_HANDLE;
  }
  status = lg_upstream_decapsulate(shared_secret, ciphertext,
                                   record->bytes);
  lg_private_key_registry_release();
  if (status != 0) {
    lg_secure_zero(shared_secret, LG_MLKEM768_SHARED_SECRET_BYTES);
  }
  return lg_map_upstream_status(status);
}

void lg_mlkem768_private_key_destroy(
    lg_mlkem768_private_key *private_key) {
  const uintptr_t token = (uintptr_t)private_key;
  lg_mlkem768_private_key_record **link;
  lg_mlkem768_private_key_record *record;
  if (private_key == NULL) {
    return;
  }
  lg_private_key_registry_acquire();
  link = &lg_live_private_keys;
  while (*link != NULL && (*link)->token != token) {
    link = &(*link)->next;
  }
  record = *link;
  if (record == NULL) {
    lg_private_key_registry_release();
    return;
  }
  *link = record->next;
  lg_live_private_key_count--;
  lg_secure_zero(record, sizeof(*record));
#if defined(LG_MLKEM_TESTING)
  lg_last_destroy_was_zero =
      lg_is_all_zero(record, sizeof(*record)) ? 1 : 0;
  lg_destroyed_handle_count++;
#endif
  lg_private_key_registry_release();
  free(record);
}

int32_t lg_mlkem768_self_test(void) {
  uint8_t seed[LG_MLKEM768_KEYGEN_SEED_BYTES];
  uint8_t public_key[LG_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t ciphertext[LG_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t shared_secret[LG_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t decapsulated[LG_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t rejected[LG_MLKEM768_SHARED_SECRET_BYTES];
  lg_mlkem768_private_key *private_key = NULL;
  int32_t result = LG_MLKEM_ERR_SELF_TEST;

  memcpy(seed, test_vector_d, sizeof(test_vector_d));
  memcpy(seed + sizeof(test_vector_d), test_vector_z, sizeof(test_vector_z));

  if (lg_mlkem768_keypair_from_seed(seed, sizeof(seed), public_key,
                                    sizeof(public_key), &private_key) != 0 ||
      private_key == NULL ||
      memcmp(public_key, test_vector_pk, sizeof(public_key)) != 0 ||
      !lg_private_key_bytes_equal(private_key, test_vector_sk,
                                  sizeof(test_vector_sk)) ||
      lg_mlkem768_validate_public_key(public_key, sizeof(public_key)) != 0 ||
      lg_mlkem768_encapsulate_from_seed_internal(
          public_key, sizeof(public_key), test_vector_m,
          sizeof(test_vector_m), ciphertext, sizeof(ciphertext), shared_secret,
          sizeof(shared_secret)) != 0 ||
      memcmp(ciphertext, test_vector_ct, sizeof(ciphertext)) != 0 ||
      memcmp(shared_secret, test_vector_ss, sizeof(shared_secret)) != 0 ||
      lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                              decapsulated, sizeof(decapsulated)) != 0 ||
      memcmp(decapsulated, test_vector_ss, sizeof(decapsulated)) != 0) {
    goto cleanup;
  }

  ciphertext[0] ^= 1;
  if (lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                              rejected, sizeof(rejected)) != 0 ||
      memcmp(rejected, shared_secret, sizeof(rejected)) == 0) {
    goto cleanup;
  }

  result = LG_MLKEM_OK;

cleanup:
  lg_mlkem768_private_key_destroy(private_key);
  lg_secure_zero(seed, sizeof(seed));
  lg_secure_zero(public_key, sizeof(public_key));
  lg_secure_zero(ciphertext, sizeof(ciphertext));
  lg_secure_zero(shared_secret, sizeof(shared_secret));
  lg_secure_zero(decapsulated, sizeof(decapsulated));
  lg_secure_zero(rejected, sizeof(rejected));
  return result;
}

#if defined(LG_MLKEM_TESTING)
int32_t lg_mlkem768_test_encapsulate_from_seed(
    const uint8_t *public_key, uint64_t public_key_len,
    const uint8_t *encaps_seed, uint64_t encaps_seed_len,
    uint8_t *ciphertext, uint64_t ciphertext_len, uint8_t *shared_secret,
    uint64_t shared_secret_len) {
  return lg_mlkem768_encapsulate_from_seed_internal(
      public_key, public_key_len, encaps_seed, encaps_seed_len, ciphertext,
      ciphertext_len, shared_secret, shared_secret_len);
}

uint64_t lg_mlkem768_test_destroyed_handle_count(void) {
  uint64_t result;
  lg_private_key_registry_acquire();
  result = lg_destroyed_handle_count;
  lg_private_key_registry_release();
  return result;
}

int32_t lg_mlkem768_test_last_destroy_was_zero(void) {
  int32_t result;
  lg_private_key_registry_acquire();
  result = lg_last_destroy_was_zero;
  lg_private_key_registry_release();
  return result;
}

uint64_t lg_mlkem768_test_live_handle_count(void) {
  uint64_t result;
  lg_private_key_registry_acquire();
  result = (uint64_t)lg_live_private_key_count;
  lg_private_key_registry_release();
  return result;
}
#endif
