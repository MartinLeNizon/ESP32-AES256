#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <esp_timer.h>

#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"

#include "app_command.h"

#include "serial_io.h"
#include "lownet.h"
#include "app_ping.h"

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";
const char* ERROR_PARSE_KEY = "ERROR // PARSE KEY";
const char* ERROR_HASH_PUB_KEY = "ERROR // WRONG HASH OF THE PUBLIC KEY";
const char* ERROR_HASH_MSG = "ERROR // WRONG HASH OF THE MESSAGE";
const char* ERROR_SIGNATURE = "ERROR // WRONG SIGNATURE";

static additionnal_ping_payload_t additionnal_ping_payload;

static cmd_buffer_t buffer;

void cmd_init() {
	memset(&buffer.stored_items, 0, sizeof(buffer.stored_items));
}

uint8_t signature_is_correct(const lownet_frame_t* frame, const cmd_signature_t* first_signature, const cmd_signature_t* second_signature) {
	if (0) {	// Different hash of public key
		serial_write_line(ERROR_HASH_PUB_KEY);
		return 0;
	}

	if (0) {	// Different hash of the message
		serial_write_line(ERROR_HASH_MSG);
		return 0;
	}

	if (0) {	// Wrong hash of the public key
		serial_write_line(ERROR_HASH_PUB_KEY);
		return 0;
	}

	if (0) {	// Wrong hash of the message
		serial_write_line(ERROR_HASH_MSG);
		return 0;
	}

	if (0) {	// Wrong signature
		serial_write_line(ERROR_SIGNATURE);
		return 0;
	}

	return 1;
}

void cmd_process_time(const lownet_frame_t* frame) {
	const cmd_payload_t* cmd = (const cmd_payload_t*) frame->payload;
	lownet_time_t time;
	memcpy(&time, cmd->data, sizeof(lownet_time_t));
	lownet_set_time(&time);
}

void cmd_process_test(const lownet_frame_t* frame){
	const cmd_payload_t* cmd = (const cmd_payload_t*) frame->payload;
	additionnal_ping_payload.length = frame->length - (CMD_SEQUENCE_SIZE + CMD_TYPE_SIZE + CMD_RESERVED_SIZE);
	memcpy(additionnal_ping_payload.data, cmd->data, additionnal_ping_payload.length);
	ping_additionnal_content(frame->source, &additionnal_ping_payload);
}

void process_command_frame(const lownet_frame_t* frame) {
	const cmd_payload_t* cmd = (const cmd_payload_t*) frame->payload;
	switch (cmd->type) {
		case CMD_TYPE_TIME:
			cmd_process_time(frame);
			break;

		case CMD_TYPE_TEST:
			cmd_process_test(frame);
			break;
	}
}

void handle_command_frame(const lownet_frame_t* frame) {
	
	if (!frame) return;

	uint8_t frame_type = frame->protocol >> 6;

	uint8_t frame_header_size = LOWNET_SOURCE_SIZE + LOWNET_DEST_SIZE + LOWNET_PROTOCOL_SIZE + LOWNET_LENGTH_SIZE;

	switch (frame_type) {
	case CMD_FRAME_UNSIGNED:
		return;		// Ignore non-signed frames.
		break;
	case CMD_FRAME_SIGNED:
		if (memcpy(&buffer.frame, frame + frame_header_size, sizeof(lownet_frame_t)) == &buffer.frame) {
			set_frame_bit(buffer.stored_items);
		}
		break;
	case CMD_FIRST_SIGNATURE:
		if (memcpy(&buffer.first_signature, frame + frame_header_size, sizeof(cmd_signature_t)) == &buffer.first_signature) {
			set_first_signature_bit(buffer.stored_items);
		}
		break;
	case CMD_SECOND_SIGNATURE:
		if (memcpy(&buffer.second_signature, frame + frame_header_size, sizeof(cmd_signature_t)) == &buffer.second_signature) {
			set_second_signature_bit(buffer.stored_items);
		}
		break;
	default:
		return;
	}

	if ((get_frame_bit(buffer.stored_items) == 1) && (get_first_signature_bit(buffer.stored_items) == 1) && (get_second_signature_bit(buffer.stored_items) == 1)) {
		if (signature_is_correct(&buffer.frame, &buffer.first_signature, &buffer.second_signature)) {
			process_command_frame(&buffer.frame);
		}
	}

	
}
