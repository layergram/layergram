// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#include "layergram_scka.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "SCKA ABI check failed at line %d\n", __LINE__);         \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static uint8_t state_out[LG_SCKA_V1_MAX_STATE_BYTES];

static int is_all_zero(const uint8_t *bytes, uint64_t length) {
  uint8_t aggregate = 0;
  uint64_t index;
  for (index = 0; index < length; index++) {
    aggregate = (uint8_t)(aggregate | bytes[index]);
  }
  return aggregate == 0;
}

int main(void) {
  uint8_t session_id[LG_SCKA_V1_SESSION_ID_BYTES];
  uint8_t state_key[LG_SCKA_V1_STATE_KEY_BYTES];
  uint8_t shared_secret[LG_SCKA_V1_SHARED_SECRET_BYTES];
  uint8_t state_in[LG_SCKA_V1_MIN_STATE_BYTES];
  uint64_t state_out_len = UINT64_MAX;

  CHECK(lg_scka_v1_abi_version() == LG_SCKA_V1_ABI_VERSION);
  CHECK(lg_scka_v1_protocol_revision() == LG_SCKA_V1_PROTOCOL_REVISION);
  CHECK(lg_scka_v1_state_format_version() ==
        LG_SCKA_V1_STATE_FORMAT_VERSION);
  CHECK(strcmp(lg_scka_v1_implementation_id(),
               "layergram-scka-scaffold-r1-abi1") == 0);
  CHECK(lg_scka_v1_session_id_bytes() == LG_SCKA_V1_SESSION_ID_BYTES);
  CHECK(lg_scka_v1_state_key_bytes() == LG_SCKA_V1_STATE_KEY_BYTES);
  CHECK(lg_scka_v1_epoch_secret_bytes() == LG_SCKA_V1_EPOCH_SECRET_BYTES);
  CHECK(lg_scka_v1_state_header_bytes() == LG_SCKA_V1_STATE_HEADER_BYTES);
  CHECK(lg_scka_v1_state_tag_bytes() == LG_SCKA_V1_STATE_TAG_BYTES);
  CHECK(lg_scka_v1_min_state_bytes() == LG_SCKA_V1_MIN_STATE_BYTES);
  CHECK(lg_scka_v1_max_state_bytes() == LG_SCKA_V1_MAX_STATE_BYTES);
  CHECK(lg_scka_v1_max_message_bytes() == LG_SCKA_V1_MAX_MESSAGE_BYTES);
  CHECK(lg_scka_v1_self_test() == LG_SCKA_V1_ERR_NOT_READY);

  memset(session_id, 0x11, sizeof(session_id));
  memset(state_key, 0x22, sizeof(state_key));
  memset(shared_secret, 0x33, sizeof(shared_secret));
  memset(state_in, 0x44, sizeof(state_in));
  memset(state_out, 0xa5, sizeof(state_out));

  CHECK(lg_scka_v1_initialize(
            LG_SCKA_V1_ROLE_INITIATOR, session_id, sizeof(session_id),
            state_key, sizeof(state_key), shared_secret, sizeof(shared_secret),
            state_out, sizeof(state_out), &state_out_len) ==
        LG_SCKA_V1_ERR_NOT_READY);
  CHECK(state_out_len == 0);
  CHECK(is_all_zero(state_out, sizeof(state_out)));

  CHECK(lg_scka_v1_state_validate(
            LG_SCKA_V1_ROLE_RESPONDER, session_id, sizeof(session_id), state_key,
            sizeof(state_key), 0, state_in, sizeof(state_in)) ==
        LG_SCKA_V1_ERR_NOT_READY);
  CHECK(lg_scka_v1_state_validate(
            0, session_id, sizeof(session_id), state_key, sizeof(state_key), 0,
            state_in, sizeof(state_in)) == LG_SCKA_V1_ERR_INVALID_ARGUMENT);

  puts("LAYERGRAM_SCKA_SCAFFOLD_ABI_OK");
  return 0;
}
