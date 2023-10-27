#ifndef GUARD_APP_COMMAND_H
#define GUARD_APP_COMMAND_H

#include "lownet.h"

#define COMMAND_SEQUENCE_SIZE				8
#define COMMAND_TYPE_SIZE					1
#define COMMAND_RESERVED_SIZE				3
#define COMMAND_DATA_SIZE					180

#define HASH_LENGTH							32

#define CMD_TYPE_TIME						0x01
#define CMD_TYPE_TEST						0x02

#define LOWNET_FRAME_UNSIGNED				0b00
#define LOWNET_FRAME_SIGNED					0b01
#define LOWNET_FIRST_SIGNATURE				0b10
#define LOWNET_SECOND_SIGNATURE				0b11

#define ADDITIONNAL_PAYLOAD_PING_SIZE 	COMMAND_DATA_SIZE

typedef struct __attribute__((__packed__)) {
	uint64_t sequence;
	uint8_t type;
	uint8_t undefined[COMMAND_RESERVED_SIZE];
	uint8_t data[COMMAND_DATA_SIZE];
} command_payload_t;

typedef struct __attribute__((__packed__)) {
	uint8_t length;		// NEED TO INIT TO 0.
	uint8_t data[ADDITIONNAL_PAYLOAD_PING_SIZE];
} additionnal_ping_payload_t;

void cmd_process_time(const lownet_frame_t* frame);

void cmd_process_test(const lownet_frame_t* frame);

void process_command_frame(const lownet_frame_t* frame);

void handle_command_frame(const lownet_frame_t* frame);

void command_init();

#endif