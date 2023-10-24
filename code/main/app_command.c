#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <esp_timer.h>

#include "mbedtls/sha256.h"

#include "app_command.h"

#include "serial_io.h"
#include "lownet.h"

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";
const char* ERROR_SIGNATURE_ORDER = "ERROR // SECOND PART OF THE SIGNATURE RECEIVE BEFORE THE FIRST ONE";

state_t * state = NULL;

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
	if (s) {
		set_nth_bit(&state->listening_and_signature_verified, 7, STATE_IDLE);
	    set_nth_bit(&state->listening_and_signature_verified, 1, SIGNATURE_UNVERIFIED);
	    set_nth_bit(&state->listening_and_signature_verified, 0, SIGNATURE_UNVERIFIED);
	    s->sequence_number = 0;
	    memset(s->frame_buffer, 0, LOWNET_FRAME_SIZE * NB_SIMULTANEOUS_FRAMES);
	    s->start_time = 0;
	}
}

void command_init() {
	state = (state_t *) malloc(sizeof(state_t));
	state_init(state);
}

void command_finish() {
	free(state);
	state = NULL;
}

uint8_t check_signature(const lownet_frame_t* signature_frame, const char *key, const size_t key_length) {
	unsigned char key_sha256_hash[HASH_LENGTH];
	calculate_sha256_hash(key, key_length, key_sha256_hash);
	if ( memcmp(&signature_frame->payload, key_sha256_hash, HASH_LENGTH) )	{	// Wrong key hash value.
		return 1;
	}

	unsigned char msg_sha256_hash[HASH_LENGTH];
	char msg_string[LOWNET_FRAME_SIZE];
	memcpy(msg_string, state->frame_buffer, LOWNET_FRAME_SIZE);
	calculate_sha256_hash(msg_string, LOWNET_FRAME_SIZE, msg_sha256_hash);
	if ( memcmp(&signature_frame->payload + HASH_LENGTH, msg_sha256_hash, HASH_LENGTH) )	{	// Wrong msg hash value.
		return 1;
	}

	switch (signature_frame->protocol >> 6) {
	case LOWNET_FIRST_SIGNATURE:
		set_nth_bit(&state->listening_and_signature_verified, 7, SIGNATURE_VERIFIED);
		memcpy(state->signature_buffer, signature_frame + 2*HASH_LENGTH, SIGNATURE_LENGTH/2);
		break;
	case LOWNET_SECOND_SIGNATURE:
		if ( (state->listening_and_signature_verified & (1<<1)) ==  SIGNATURE_UNVERIFIED) {		// If first part of the signature non verified.
			serial_write_line(ERROR_SIGNATURE_ORDER);
			return 1;
		}
		memcpy(state->signature_buffer + SIGNATURE_LENGTH/2, signature_frame + 2*HASH_LENGTH, SIGNATURE_LENGTH/2);

		// Decrypt the received signature using the sender's public key to get a hash of the message.
		// Compare this hash with the hash of the real message.


		break;
	}

	// -->> TO COMPLETE / SIGNATURE...

	return 0;
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
			memcpy(state->frame_buffer, frame, LOWNET_FRAME_SIZE);
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
