// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#ifndef LAYERGRAM_SCKA_H
#define LAYERGRAM_SCKA_H

#include <stdint.h>

#if defined(_WIN32)
#if defined(LG_SCKA_BUILD)
#define LG_SCKA_EXPORT __declspec(dllexport)
#else
#define LG_SCKA_EXPORT __declspec(dllimport)
#endif
#else
#define LG_SCKA_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
  LG_SCKA_V1_ABI_VERSION = 1,
  LG_SCKA_V1_PROTOCOL_REVISION = 1,
  LG_SCKA_V1_STATE_FORMAT_VERSION = 2,
  LG_SCKA_V1_SESSION_ID_BYTES = 16,
  LG_SCKA_V1_STATE_KEY_BYTES = 32,
  LG_SCKA_V1_SHARED_SECRET_BYTES = 32,
  LG_SCKA_V1_EPOCH_SECRET_BYTES = 32,
  LG_SCKA_V1_STATE_HEADER_BYTES = 80,
  LG_SCKA_V1_STATE_TAG_BYTES = 16,
  LG_SCKA_V1_MIN_STATE_BYTES = 97,
  LG_SCKA_V1_MAX_STATE_BYTES = 196608,
  LG_SCKA_V1_MAX_MESSAGE_BYTES = 512
};

enum lg_scka_v1_role {
  LG_SCKA_V1_ROLE_INITIATOR = 1,
  LG_SCKA_V1_ROLE_RESPONDER = 2
};

enum lg_scka_v1_status {
  LG_SCKA_V1_OK = 0,
  LG_SCKA_V1_ERR_INVALID_ARGUMENT = -1,
  LG_SCKA_V1_ERR_NOT_READY = -2,
  LG_SCKA_V1_ERR_AUTHENTICATION = -3,
  LG_SCKA_V1_ERR_STATE_FORMAT = -4,
  LG_SCKA_V1_ERR_STATE_REVISION = -5,
  LG_SCKA_V1_ERR_BACKEND = -6,
  LG_SCKA_V1_ERR_ENTROPY = -7,
  LG_SCKA_V1_ERR_SELF_TEST = -8,
  LG_SCKA_V1_ERR_ALLOCATION = -9
};

LG_SCKA_EXPORT uint32_t lg_scka_v1_abi_version(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_protocol_revision(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_state_format_version(void);
LG_SCKA_EXPORT const char *lg_scka_v1_implementation_id(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_session_id_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_state_key_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_epoch_secret_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_state_header_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_state_tag_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_min_state_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_max_state_bytes(void);
LG_SCKA_EXPORT uint32_t lg_scka_v1_max_message_bytes(void);

// The scaffold intentionally returns LG_SCKA_V1_ERR_NOT_READY. A future
// implementation may return OK only after immutable primitive, state-machine,
// and serialization self-tests all pass in the current process and binary.
LG_SCKA_EXPORT int32_t lg_scka_v1_self_test(void);

// All state operations are non-mutating. A successful transition writes a new
// authenticated state export and never modifies state_in. Every non-OK result
// invalidates all outputs. Callers must provide valid pointers for every
// non-zero length. state_out_capacity must equal LG_SCKA_V1_MAX_STATE_BYTES;
// message_out_capacity must equal LG_SCKA_V1_MAX_MESSAGE_BYTES; and
// epoch_secret_out_len must equal LG_SCKA_V1_EPOCH_SECRET_BYTES.
//
// The state key is a stable, independently derived session secret. It must not
// be stored inside the state export itself. expected_state_revision binds the
// native candidate to the exact outer TR3 revision selected by the serialized
// Layergram session authority.
LG_SCKA_EXPORT int32_t lg_scka_v1_state_validate(
    uint32_t role, const uint8_t *session_id, uint64_t session_id_len,
    const uint8_t *state_key, uint64_t state_key_len,
    uint64_t expected_state_revision, const uint8_t *state_in,
    uint64_t state_in_len);

LG_SCKA_EXPORT int32_t lg_scka_v1_initialize(
    uint32_t role, const uint8_t *session_id, uint64_t session_id_len,
    const uint8_t *state_key, uint64_t state_key_len,
    const uint8_t *shared_secret, uint64_t shared_secret_len,
    uint8_t *state_out, uint64_t state_out_capacity,
    uint64_t *state_out_len);

LG_SCKA_EXPORT int32_t lg_scka_v1_send(
    uint32_t role, const uint8_t *session_id, uint64_t session_id_len,
    const uint8_t *state_key, uint64_t state_key_len,
    uint64_t expected_state_revision, const uint8_t *state_in,
    uint64_t state_in_len, uint8_t *state_out, uint64_t state_out_capacity,
    uint64_t *state_out_len, uint8_t *message_out,
    uint64_t message_out_capacity, uint64_t *message_out_len,
    uint64_t *sending_epoch_out, uint32_t *has_epoch_secret_out,
    uint64_t *epoch_secret_epoch_out, uint8_t *epoch_secret_out,
    uint64_t epoch_secret_out_len);

// message_in may be NULL only when message_in_len is zero. The returned
// receiving epoch must equal the visible SK3 sending epoch before Layergram may
// commit the candidate.
LG_SCKA_EXPORT int32_t lg_scka_v1_receive(
    uint32_t role, const uint8_t *session_id, uint64_t session_id_len,
    const uint8_t *state_key, uint64_t state_key_len,
    uint64_t expected_state_revision, const uint8_t *state_in,
    uint64_t state_in_len, const uint8_t *message_in,
    uint64_t message_in_len, uint8_t *state_out,
    uint64_t state_out_capacity, uint64_t *state_out_len,
    uint64_t *receiving_epoch_out, uint32_t *has_epoch_secret_out,
    uint64_t *epoch_secret_epoch_out, uint8_t *epoch_secret_out,
    uint64_t epoch_secret_out_len);

#ifdef __cplusplus
}
#endif

#endif
