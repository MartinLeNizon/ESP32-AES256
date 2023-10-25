#ifndef GUARD_APP_COMMAND_H
#define GUARD_APP_COMMAND_H

#include "lownet.h"

#define COMMAND_RESERVED_LENGTH		3
#define COMMAND_DATA_LENGTH			180

#define HASH_LENGTH					32

#define CMD_TYPE_TIME				0x01
#define CMD_TYPE_TEST				0x02

#define LOWNET_FRAME_UNSIGNED		0b00
#define LOWNET_FRAME_SIGNED			0b01
#define LOWNET_FIRST_SIGNATURE		0b10
#define LOWNET_SECOND_SIGNATURE		0b11

#define SIGNATURE_MAX_DELAY			10000		// 10000 ms = 10 seconds.

#define NB_SIMULTANEOUS_FRAMES		1 			// Number of frames that can be handled waiting the signature simultaneously.

#define STATE_IDLE					0
#define STATE_LISTENING				1

#define SIGNATURE_LENGTH			256 		// Depends on the hash, here 256 because SHA256.

#define SIGNATURE_UNVERIFIED		0
#define SIGNATURE_VERIFIED 			1

#define ADDITIONNAL_PAYLOAD_PING_LENGTH 	COMMAND_DATA_LENGTH

typedef struct __attribute__((__packed__)) {
	uint64_t sequence;
	uint8_t type;
	uint8_t undefined[COMMAND_RESERVED_LENGTH];
	uint8_t data[COMMAND_DATA_LENGTH];
} command_payload_t;

typedef struct __attribute__((__packed__)) {
	uint8_t listening_and_signature_verified;		// lxxxxxfs; l: listening bit; x: unused bits; f: first part of the signature verified; s: second part of the signature verified.
	uint64_t sequence_number;
	lownet_frame_t frame_buffer[NB_SIMULTANEOUS_FRAMES];
	char signature_buffer[SIGNATURE_LENGTH];
	uint64_t start_time;	// In µs.
} state_t;

void calculate_sha256_hash(const char *input, const size_t input_length, unsigned char *output);

void set_nth_bit(uint8_t *var, const uint8_t pos, const uint8_t value);

void state_init(state_t *s);

void command_init();

void command_finish();

uint8_t check_signature(const lownet_frame_t* signature_frame, const char *key);

void cmd_process_time(const command_payload_t* cmd);

void cmd_process_test(const command_payload_t* cmd);

void process_command_frame(const command_payload_t* cmd);

void handle_command_frame(const lownet_frame_t* frame);

#endif