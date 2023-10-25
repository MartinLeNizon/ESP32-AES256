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

// static state_t * cmd_state = NULL;

// static uint8_t optionnal_payload_ping [ADDITIONNAL_PAYLOAD_PING_LENGTH];

void calculate_sha256_hash(const char *msg, const size_t msg_length, unsigned char *hash) {
    // mbedtls_sha256_context sha256_ctx;
    // mbedtls_sha256_init(&sha256_ctx);
    // mbedtls_sha256_starts(&sha256_ctx, 0);
    // mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) msg, msg_length);
    // mbedtls_sha256_finish(&sha256_ctx, hash);
    // mbedtls_sha256_free(&sha256_ctx);
}

/*void decrypt_rsa(const char *cipher, char *plain, const char *rsa_key) {
	// mbedtls_pk_context pk;
	// mbedtls_pk_init(&pk);

	// mbedtls_rsa_context rsa;

	// if (mbedtls_pk_parse_key(&pk, (unsigned char *) rsa_key, strlen(rsa_key), NULL, 0, NULL, 0)) {
	// 	mbedtls_rsa_free(&rsa);
	// 	serial_write_line(ERROR_PARSE_KEY);
	// 	return;
	// }

	// memcpy(&rsa, mbedtls_pk_rsa(pk), sizeof(rsa));

	// // Decrypt the signature with the public key.
	// mbedtls_rsa_private(&rsa, 0, 0, (unsigned char *) cipher, (unsigned char *) plain);
	// mbedtls_rsa_free(&rsa);
}*/

void set_nth_bit(uint8_t *var, const uint8_t pos, const uint8_t value) {
	/*if (value) {
        *var |= (1 << pos);
    } else {
        *var &= ~(1 << pos);
    }*/
}

void state_init(state_t *s) {
	/*if (s) {
		set_nth_bit(&cmd_state->listening_and_signature_verified, 7, STATE_IDLE);
	    set_nth_bit(&cmd_state->listening_and_signature_verified, 1, SIGNATURE_UNVERIFIED);
	    set_nth_bit(&cmd_state->listening_and_signature_verified, 0, SIGNATURE_UNVERIFIED);
	    s->sequence_number = 0;
	    memset(s->frame_buffer, 0, LOWNET_FRAME_SIZE * NB_SIMULTANEOUS_FRAMES);
	    s->start_time = 0;
	}*/
}

void command_init() {
	/*cmd_state = (state_t *) malloc(sizeof(state_t));
	state_init(cmd_state);*/
}

void command_finish() {
	/*free(cmd_state);
	cmd_state = NULL;*/
}

uint8_t check_signature(const lownet_frame_t* signature_frame, const char *key) {
	// unsigned char key_sha256_hash[HASH_LENGTH];
	// calculate_sha256_hash(key, strlen(key), key_sha256_hash);
	// if ( memcmp(&signature_frame->payload, key_sha256_hash, HASH_LENGTH) )	{	// Wrong key hash value.
	// 	return 1;
	// }

	// unsigned char msg_sha256_hash[HASH_LENGTH];
	// char msg_string[LOWNET_FRAME_SIZE];
	// memcpy(msg_string, cmd_state->frame_buffer, LOWNET_FRAME_SIZE);
	// calculate_sha256_hash(msg_string, LOWNET_FRAME_SIZE, msg_sha256_hash);
	// if ( memcmp(&signature_frame->payload + HASH_LENGTH, msg_sha256_hash, HASH_LENGTH) )	{	// Wrong msg hash value.
	// 	return 1;
	// }

	// switch (signature_frame->protocol >> 6) {
	// case LOWNET_FIRST_SIGNATURE:
	// 	set_nth_bit(&cmd_state->listening_and_signature_verified, 7, SIGNATURE_VERIFIED);
	// 	memcpy(cmd_state->signature_buffer, signature_frame + 2*HASH_LENGTH, SIGNATURE_LENGTH/2);
	// 	break;
	// case LOWNET_SECOND_SIGNATURE:
	// 	if ( (cmd_state->listening_and_signature_verified & (1<<1)) ==  SIGNATURE_UNVERIFIED) {		// If first part of the signature non verified.
	// 		serial_write_line(ERROR_SIGNATURE_ORDER);
	// 		return 1;
	// 	}
	// 	memcpy(cmd_state->signature_buffer + SIGNATURE_LENGTH/2, signature_frame + 2*HASH_LENGTH, SIGNATURE_LENGTH/2);

	// 	// Compare the hash from the signature with the hash of the message.
	// 	// The hash from the signature is the plain text of the signature, decrypted with RSA using the public key.
	// 	char msg_sha256_hash_from_signature[HASH_LENGTH];
	// 	decrypt_rsa(cmd_state->signature_buffer, msg_sha256_hash_from_signature, lownet_public_key);

	// 	if (memcmp(msg_sha256_hash, msg_sha256_hash_from_signature, HASH_LENGTH)) {		// If hashes are different
	// 		serial_write_line(ERROR_SIGNATURE);
	// 		return 1;
	// 	} else {	// Everything's fine, process the command.
	// 		return 0;
	// 	}

	// 	break;
	// }

	return 0;	// No error.
}

void cmd_process_time(const command_payload_t* cmd) {
	// lownet_time_t time;
	// memcpy(&time, cmd->data, sizeof(lownet_time_t));
	// lownet_set_time(&time);
}

void cmd_process_test(const command_payload_t* cmd){

}

void process_command_frame(const command_payload_t* cmd) {
	// switch (cmd->type) {
	// 	case CMD_TYPE_TIME:
	// 		cmd_process_time(cmd);
	// 		break;

	// 	case CMD_TYPE_TEST:
	// 		cmd_process_test(cmd);
	// 		break;
	// }
	
	// if (cmd->sequence <= cmd_state->sequence_number) {
	// 	serial_write_line(ERROR_SEQUENCE);
	// 	return;
	// } else {
	// 	cmd_state->sequence_number = cmd->sequence;
	// }
}

void handle_command_frame(const lownet_frame_t* frame) {
	
	if (!frame) return;

	uint8_t frame_type = frame->protocol >> 6;

	// if ( ( (cmd_state->listening_and_signature_verified & (1<<7)) == (STATE_LISTENING << 7) ) && ( (esp_timer_get_time() - cmd_state->start_time)/1000 >= SIGNATURE_MAX_DELAY) ) {		// Convert μs to ms.
	// 	state_init(cmd_state);
	// }

	// switch (cmd_state->listening_and_signature_verified & (1<<7)) {
	// case STATE_IDLE:
	// 	switch (frame_type) {
	// 	case LOWNET_FRAME_UNSIGNED:
	// 		return;		// Ignore non-signed frames.
	// 		break;
	// 	case LOWNET_FRAME_SIGNED:
	// 		memcpy(cmd_state->frame_buffer, frame, LOWNET_FRAME_SIZE);
	// 		set_nth_bit(&cmd_state->listening_and_signature_verified, 8, STATE_LISTENING);
	// 		cmd_state->start_time = esp_timer_get_time();
	// 		break;
	// 	default:
	// 		return;		// Ignore signature frames if STATE_IDLE
	// 	}
	// 	break;
	// case STATE_LISTENING:
	// 	switch (frame_type) {
	// 	case LOWNET_FIRST_SIGNATURE:
	// 		check_signature(frame, lownet_public_key);
	// 		// -->> check_signature();
	// 		// TO COMPLETE.
	// 		break;
	// 	case LOWNET_SECOND_SIGNATURE:
	// 		if (!check_signature(frame, lownet_public_key)) {
	// 			const command_payload_t* cmd = (const command_payload_t*) frame->payload;
	// 			process_command_frame(cmd);
	// 		}
	// 		break;
	// 	default:
	// 		return;
	// 	}

	// 	break;
	// }
}
