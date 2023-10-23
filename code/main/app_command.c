#include <time.h>
#include <stdint.h>
#include <string.h>

#include <esp_timer.h>

#include "app_command.h"

#include "serial_io.h"
#include "lownet.h"

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";

state_t * state;

void setNthBit(uint8_t *var, const uint8_t pos, const uint8_t value) {
	if (value) {
        *var |= (1 << pos);
    } else {
        *var &= ~(1 << pos);
    }
}

void initializeState(state_t *s) {
	setNthBit(&state->listening_and_signature_verified, 7, STATE_IDLE);
    setNthBit(&state->listening_and_signature_verified, 1, SIGNATURE_UNVERIFIED);
    setNthBit(&state->listening_and_signature_verified, 0, SIGNATURE_UNVERIFIED);
    s->sequence_number = 0;
    memset(s->buffer, 0, LOWNET_FRAME_SIZE * NB_SIMULTANEOUS_FRAMES);
    s->start_time = 0;
}

void command_init() {
	initializeState(state);
}

void cmd_process_time(const command_payload_t* cmd) {
	// lownet_time_t time;
	// memcpy(&time, cmd->data, sizeof(lownet_time_t));
	// lownet_set_time(&time);
}

void cmd_process_test(const command_payload_t* cmd){

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
	
	if (cmd->sequence <= state->sequence_number) {
		serial_write_line(ERROR_SEQUENCE);
		return;
	} else {
		state->sequence_number = cmd->sequence;
	}
}

void handle_command_frame(const lownet_frame_t* frame) {
	if (!frame) return;

	const command_payload_t* cmd = (const command_payload_t*) frame->payload;

	uint8_t frame_type = frame->protocol >> 6;

	switch (state->listening_and_signature_verified & (1<<7)) {
	case STATE_IDLE:
		switch (frame_type) {
		case LOWNET_FRAME_UNSIGNED:
			return;		// Ignore non-signed frames.
			break;
		case LOWNET_FRAME_SIGNED:
			memcpy(state->buffer, frame, LOWNET_FRAME_SIZE);
			setNthBit(&state->listening_and_signature_verified, 8, STATE_LISTENING);
			state->start_time = esp_timer_get_time();
			break;
		default:
			return;		// Ignore signature frames if STATE_IDLE
		}
		break;
	case STATE_LISTENING:
		switch (frame_type) {
		case LOWNET_FIRST_SIGNATURE:
			// TO COMPLETE.
		}
		break;
	}
}
