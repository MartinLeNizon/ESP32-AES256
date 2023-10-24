#include <time.h>
#include <stdint.h>
#include <string.h>

#include <esp_timer.h>

#include "mbedtls/sha256.h"


#include "app_command.h"

#include "serial_io.h"
#include "lownet.h"

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";

state_t * state;

void calculate_sha256_hash(const char *input, const size_t input_length, unsigned char *output) {
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)input, input_length);
    mbedtls_sha256_finish(&sha256_ctx, output);
    mbedtls_sha256_free(&sha256_ctx);
}

void set_nth_bit(uint8_t *var, const uint8_t pos, const uint8_t value) {
	if (value) {
        *var |= (1 << pos);
    } else {
        *var &= ~(1 << pos);
    }
}

void state_init(state_t *s) {
	set_nth_bit(&state->listening_and_signature_verified, 7, STATE_IDLE);
    set_nth_bit(&state->listening_and_signature_verified, 1, SIGNATURE_UNVERIFIED);
    set_nth_bit(&state->listening_and_signature_verified, 0, SIGNATURE_UNVERIFIED);
    s->sequence_number = 0;
    memset(s->buffer, 0, LOWNET_FRAME_SIZE * NB_SIMULTANEOUS_FRAMES);
    s->start_time = 0;
}

void command_init() {
	state_init(state);
}

uint8_t check_signature(const lownet_frame_t* msg_frame, const lownet_frame_t* signature_frame, const char *key, const size_t key_length) {
	unsigned char key_sha256_hash[HASH_LENGTH];
	calculate_sha256_hash(key, key_length, key_sha256_hash);
	if ( memcmp(&signature_frame->payload, key_sha256_hash, HASH_LENGTH) )	{	// Wrong key hash value.
		return 0;
	}

	unsigned char msg_sha256_hash[HASH_LENGTH];
	char msg_string[LOWNET_FRAME_SIZE];
	memcpy(msg_string, msg_frame, LOWNET_FRAME_SIZE);
	calculate_sha256_hash(msg_string, LOWNET_FRAME_SIZE, msg_sha256_hash);
	if ( memcmp(&signature_frame->payload + HASH_LENGTH, msg_sha256_hash, HASH_LENGTH) )	{	// Wrong msg hash value.
		return 0;
	}

	// -->> TO COMPLETE / SIGNATURE...

	return 1;
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

	if ( ( (state->listening_and_signature_verified & (1<<7)) == (STATE_LISTENING << 7) ) && ( (esp_timer_get_time() - state->start_time)/1000 >= SIGNATURE_MAX_DELAY) ) {		// Convert μs to ms.
		state_init(state);
	}

	switch (state->listening_and_signature_verified & (1<<7)) {
	case STATE_IDLE:
		switch (frame_type) {
		case LOWNET_FRAME_UNSIGNED:
			return;		// Ignore non-signed frames.
			break;
		case LOWNET_FRAME_SIGNED:
			memcpy(state->buffer, frame, LOWNET_FRAME_SIZE);
			set_nth_bit(&state->listening_and_signature_verified, 8, STATE_LISTENING);
			state->start_time = esp_timer_get_time();
			break;
		default:
			return;		// Ignore signature frames if STATE_IDLE
		}
		break;
	case STATE_LISTENING:
		switch (frame_type) {
		case LOWNET_FIRST_SIGNATURE:
			// -->> check_signature();
			// TO COMPLETE.
			break;
		case LOWNET_SECOND_SIGNATURE:
			break;
		default:
			return;
		}
		break;
	}
}
