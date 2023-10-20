// #include <thread>
// #include <chrono>
#include <stdint.h>

#include "app_command.h"

#include "lownet.h"

#define STATE_IDLE			0
#define STATE_LISTENING		1
#define STATE_FRONT			2

// const int delayMilliseconds = 10000; // 10 seconds.

static uint8_t state;

void command_init() {
	state = STATE_IDLE;
}

void cmd_handle_time(const command_payload_t* cmd) {

}

void cmd_handle_test(const command_payload_t* cmd){

}

void handle_command_frame(const lownet_frame_t* frame) {

	if (!frame) return;

	const command_payload_t* cmd = (const command_payload_t*) frame->payload;

	uint8_t frame_type = frame->protocol >> 6;

	switch(cmd->type) {
		case CMD_TYPE_TIME:
			cmd_handle_time(cmd);
			break;

		case CMD_TYPE_TEST:
			cmd_handle_test(cmd);
			break;
	}
}
