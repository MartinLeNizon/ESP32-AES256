#ifndef GUARD_APP_COMMAND_H
#define GUARD_APP_COMMAND_H

#include "lownet.h"

#define COMMAND_RESERVED_LENGTH		3
#define COMMAND_DATA_LENGTH			180

#define CMD_TYPE_TIME				0x01
#define CMD_TYPE_TEST				0x02

#define LOWNET_FRAME_NO_SIGNATURE	0b00
#define LOWNET_FRAME_SIGNATURE		0b01
#define LOWNET_FIRST_SIGNATURE		0b10
#define LOWNET_SECOND_SIGNATURE		0b11

typedef struct __attribute__((__packed__)) {
	uint64_t sequence;
	uint8_t type;
	uint8_t undefined[COMMAND_RESERVED_LENGTH];
	uint8_t data[COMMAND_DATA_LENGTH];
} command_payload_t;

void command_init();

void cmd_handle_time(const command_payload_t* cmd);
void cmd_handle_test(const command_payload_t* cmd);

void handle_command_frame(const lownet_frame_t* frame);

#endif