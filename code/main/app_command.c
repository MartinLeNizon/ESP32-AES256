#define DBG

#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <esp_timer.h>

#include "mbedtls/sha256.h"
# include "mbedtls/rsa.h"
# include "mbedtls/pk.h"

#include "app_command.h"

#include "serial_io.h"
#include "lownet.h"

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";
const char* ERROR_SIGNATURE_ORDER = "ERROR // SECOND PART OF THE SIGNATURE RECEIVE BEFORE THE FIRST ONE";
const char* ERROR_PARSE_KEY = "ERROR // PARSE KEY";
const char* ERROR_SIGNATURE = "ERROR // WRONG SIGNATURE";

// static uint8_t optionnal_payload_ping [ADDITIONNAL_PAYLOAD_PING_LENGTH];

void cmd_process_time(const command_payload_t* cmd) {
	lownet_time_t time;
	memcpy(&time, cmd->data, sizeof(lownet_time_t));
	lownet_set_time(&time);
}

void cmd_process_test(const command_payload_t* cmd){
	#ifdef DBG
		serial_write_line("command_process_test");
	#endif
}

void process_command_frame(const command_payload_t* cmd) {
	switch (cmd->type) {
		case CMD_TYPE_TIME:
			cmd_process_time(cmd);
			break;

		case CMD_TYPE_TEST:
			cmd_process_test(cmd);
			break;
	}
}

void handle_command_frame(const lownet_frame_t* frame) {
	
	if (!frame) return;

	uint8_t frame_type = frame->protocol >> 6;

	switch (frame_type) {
	case LOWNET_FRAME_UNSIGNED:
		return;		// Ignore non-signed frames.
		break;
	case LOWNET_FRAME_SIGNED:
		const command_payload_t* cmd = (const command_payload_t*) frame->payload;
		process_command_frame(cmd);
		break;
	default:
		return;
	}
}
