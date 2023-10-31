#ifndef GUARD_APP_COMMAND_H
#define GUARD_APP_COMMAND_H

#include "lownet.h"

#define CMD_SEQUENCE_SIZE				8
#define CMD_TYPE_SIZE					1
#define CMD_RESERVED_SIZE				3
#define CMD_DATA_SIZE					180

#define CMD_HASH_SIZE 32
#define CMD_BLOCK_SIZE 256

#define CMD_TYPE_TIME					0x01
#define CMD_TYPE_TEST					0x02

#define CMD_FRAME_UNSIGNED				0b00
#define CMD_FRAME_SIGNED				0b01
#define CMD_FIRST_SIGNATURE				0b10
#define CMD_SECOND_SIGNATURE			0b11

typedef struct __attribute__((__packed__)) {
	uint64_t sequence;
	uint8_t type;
	uint8_t undefined[CMD_RESERVED_SIZE];
	uint8_t data[CMD_DATA_SIZE];
} cmd_payload_t;

typedef struct __attribute__((__packed__)) {
	uint8_t		hash_key[CMD_HASH_SIZE];
	uint8_t		hash_msg[CMD_HASH_SIZE];
	uint8_t		sig_part[CMD_BLOCK_SIZE / 2];
} cmd_signature_t;

typedef struct __attribute__((__packed__)) {
	uint8_t nb_elements_initialized;	// 3 when everything is initialized. Set to 0 when a frame is processed.
	lownet_frame_t frame;
	cmd_signature_t first_signature;
	cmd_signature_t second_signature;
} cmd_buffer_t;

typedef struct __attribute__((__packed__)) {
	uint8_t length;
	uint8_t data[CMD_DATA_SIZE];
} additionnal_ping_payload_t;

void cmd_init();

void cmd_process_time(const lownet_frame_t* frame);

void cmd_process_test(const lownet_frame_t* frame);

void process_command_frame(const lownet_frame_t* frame);

void handle_command_frame(const lownet_frame_t* frame);

#endif