// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#include "layergram_mlkem.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "ABI test failed at %s:%d: %s\n", __FILE__, __LINE__,   \
              #condition);                                                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int all_zero(const uint8_t *value, size_t length) {
  uint8_t difference = 0;
  size_t index;
  for (index = 0; index < length; index++) {
    difference = (uint8_t)(difference | value[index]);
  }
  return difference == 0;
}

typedef struct decapsulation_race_context {
  lg_mlkem768_private_key *private_key;
  uint8_t ciphertext[LG_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t expected_secret[LG_MLKEM768_SHARED_SECRET_BYTES];
  int failed;
} decapsulation_race_context;

static void run_decapsulation_race(decapsulation_race_context *context) {
  uint8_t output[LG_MLKEM768_SHARED_SECRET_BYTES];
  size_t iteration;
  for (iteration = 0; iteration < 4096U; iteration++) {
    int32_t status = lg_mlkem768_decapsulate(
        context->private_key, context->ciphertext, sizeof(context->ciphertext),
        output, sizeof(output));
    if ((status == LG_MLKEM_OK &&
         memcmp(output, context->expected_secret, sizeof(output)) != 0) ||
        (status == LG_MLKEM_ERR_INVALID_HANDLE &&
         !all_zero(output, sizeof(output))) ||
        (status != LG_MLKEM_OK && status != LG_MLKEM_ERR_INVALID_HANDLE)) {
      context->failed = 1;
      break;
    }
  }
  memset(output, 0, sizeof(output));
}

#if defined(_WIN32)
static DWORD WINAPI decapsulation_race_thread(LPVOID value) {
  run_decapsulation_race((decapsulation_race_context *)value);
  return 0;
}
#else
static void *decapsulation_race_thread(void *value) {
  run_decapsulation_race((decapsulation_race_context *)value);
  return NULL;
}
#endif

int main(void) {
  uint8_t seed[LG_MLKEM768_KEYGEN_SEED_BYTES];
  uint8_t encaps_seed[LG_MLKEM768_ENCAPS_SEED_BYTES];
  uint8_t public_key[LG_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t invalid_public_key[LG_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t ciphertext[LG_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t shared_secret[LG_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t decapsulated[LG_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t rejected[LG_MLKEM768_SHARED_SECRET_BYTES];
  lg_mlkem768_private_key *private_key = NULL;
  lg_mlkem768_private_key *invalid_handle =
      (lg_mlkem768_private_key *)(uintptr_t)UINTPTR_MAX;
  decapsulation_race_context race_context;
  uint64_t destroyed_before;
  size_t index;

  CHECK(lg_mlkem768_abi_version() == LG_MLKEM768_ABI_VERSION);
  CHECK(lg_mlkem768_public_key_bytes() == LG_MLKEM768_PUBLIC_KEY_BYTES);
  CHECK(lg_mlkem768_private_key_bytes() == LG_MLKEM768_PRIVATE_KEY_BYTES);
  CHECK(lg_mlkem768_ciphertext_bytes() == LG_MLKEM768_CIPHERTEXT_BYTES);
  CHECK(lg_mlkem768_shared_secret_bytes() == LG_MLKEM768_SHARED_SECRET_BYTES);
  CHECK(lg_mlkem768_keygen_seed_bytes() == LG_MLKEM768_KEYGEN_SEED_BYTES);
  CHECK(lg_mlkem768_encaps_seed_bytes() == LG_MLKEM768_ENCAPS_SEED_BYTES);
  CHECK(lg_mlkem768_self_test() == LG_MLKEM_OK);

  memset(public_key, 0xa5, sizeof(public_key));
  CHECK(lg_mlkem768_keypair_from_seed(
            seed, sizeof(seed) - 1, public_key, sizeof(public_key),
            &private_key) == LG_MLKEM_ERR_INVALID_ARGUMENT);
  CHECK(private_key == NULL);
  CHECK(all_zero(public_key, sizeof(public_key)));

  for (index = 0; index < sizeof(seed); index++) {
    seed[index] = (uint8_t)index;
  }
  for (index = 0; index < sizeof(encaps_seed); index++) {
    encaps_seed[index] = (uint8_t)(0xa0U + index);
  }
  CHECK(lg_mlkem768_keypair_from_seed(seed, sizeof(seed), public_key,
                                      sizeof(public_key),
                                      &private_key) == LG_MLKEM_OK);
  CHECK(private_key != NULL);
  CHECK(lg_mlkem768_test_live_handle_count() == 1);
  CHECK(lg_mlkem768_validate_public_key(public_key, sizeof(public_key)) ==
        LG_MLKEM_OK);

  memset(invalid_public_key, 0xff, sizeof(invalid_public_key));
  memset(ciphertext, 0xa5, sizeof(ciphertext));
  memset(shared_secret, 0xa5, sizeof(shared_secret));
  CHECK(lg_mlkem768_test_encapsulate_from_seed(
            invalid_public_key, sizeof(invalid_public_key), encaps_seed,
            sizeof(encaps_seed), ciphertext, sizeof(ciphertext), shared_secret,
            sizeof(shared_secret)) == LG_MLKEM_ERR_INVALID_PUBLIC_KEY);
  CHECK(all_zero(ciphertext, sizeof(ciphertext)));
  CHECK(all_zero(shared_secret, sizeof(shared_secret)));

  CHECK(lg_mlkem768_test_encapsulate_from_seed(
            public_key, sizeof(public_key), encaps_seed, sizeof(encaps_seed),
            ciphertext, sizeof(ciphertext), shared_secret,
            sizeof(shared_secret)) == LG_MLKEM_OK);
  CHECK(lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                                decapsulated, sizeof(decapsulated)) ==
        LG_MLKEM_OK);
  CHECK(memcmp(shared_secret, decapsulated, sizeof(shared_secret)) == 0);

  CHECK(lg_mlkem768_encapsulate(public_key, sizeof(public_key), ciphertext,
                                sizeof(ciphertext), shared_secret,
                                sizeof(shared_secret)) == LG_MLKEM_OK);
  CHECK(lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                                decapsulated, sizeof(decapsulated)) ==
        LG_MLKEM_OK);
  CHECK(memcmp(shared_secret, decapsulated, sizeof(shared_secret)) == 0);

  ciphertext[0] ^= 1;
  CHECK(lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                                rejected, sizeof(rejected)) == LG_MLKEM_OK);
  CHECK(memcmp(shared_secret, rejected, sizeof(shared_secret)) != 0);

  memset(decapsulated, 0xa5, sizeof(decapsulated));
  CHECK(lg_mlkem768_decapsulate(invalid_handle, ciphertext, sizeof(ciphertext),
                                decapsulated, sizeof(decapsulated)) ==
        LG_MLKEM_ERR_INVALID_HANDLE);
  CHECK(all_zero(decapsulated, sizeof(decapsulated)));
  lg_mlkem768_private_key_destroy(invalid_handle);
  CHECK(lg_mlkem768_test_live_handle_count() == 1);

  destroyed_before = lg_mlkem768_test_destroyed_handle_count();
  lg_mlkem768_private_key_destroy(private_key);
  CHECK(lg_mlkem768_test_destroyed_handle_count() == destroyed_before + 1);
  CHECK(lg_mlkem768_test_last_destroy_was_zero() == 1);
  CHECK(lg_mlkem768_test_live_handle_count() == 0);
  memset(decapsulated, 0xa5, sizeof(decapsulated));
  CHECK(lg_mlkem768_decapsulate(private_key, ciphertext, sizeof(ciphertext),
                                decapsulated, sizeof(decapsulated)) ==
        LG_MLKEM_ERR_INVALID_HANDLE);
  CHECK(all_zero(decapsulated, sizeof(decapsulated)));
  lg_mlkem768_private_key_destroy(private_key);
  CHECK(lg_mlkem768_test_destroyed_handle_count() == destroyed_before + 1);

  CHECK(lg_mlkem768_keypair_from_seed(seed, sizeof(seed), public_key,
                                      sizeof(public_key),
                                      &private_key) == LG_MLKEM_OK);
  CHECK(lg_mlkem768_encapsulate(public_key, sizeof(public_key), ciphertext,
                                sizeof(ciphertext), shared_secret,
                                sizeof(shared_secret)) == LG_MLKEM_OK);
  race_context.private_key = private_key;
  memcpy(race_context.ciphertext, ciphertext, sizeof(ciphertext));
  memcpy(race_context.expected_secret, shared_secret, sizeof(shared_secret));
  race_context.failed = 0;
#if defined(_WIN32)
  {
    HANDLE thread =
        CreateThread(NULL, 0, decapsulation_race_thread, &race_context, 0, NULL);
    CHECK(thread != NULL);
    lg_mlkem768_private_key_destroy(private_key);
    CHECK(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0);
    CHECK(CloseHandle(thread) != 0);
  }
#else
  {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, decapsulation_race_thread,
                         &race_context) == 0);
    lg_mlkem768_private_key_destroy(private_key);
    CHECK(pthread_join(thread, NULL) == 0);
  }
#endif
  CHECK(race_context.failed == 0);
  CHECK(lg_mlkem768_test_live_handle_count() == 0);
  return 0;
}
