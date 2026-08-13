// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#include "layergram_mlkem.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

  destroyed_before = lg_mlkem768_test_destroyed_handle_count();
  lg_mlkem768_private_key_destroy(private_key);
  private_key = NULL;
  CHECK(lg_mlkem768_test_destroyed_handle_count() == destroyed_before + 1);
  CHECK(lg_mlkem768_test_last_destroy_was_zero() == 1);
  return 0;
}
