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

#define RSA_INPUT_SIZE	256
#define RSA_INPUT_NB_0	220
#define RSA_INPUT_NB_1	(RSA_INPUT_SIZE - RSA_INPUT_NB_0 - CMD_HASH_SIZE)

const char* ERROR_SEQUENCE = "ERROR // SEQUENCE NUMBER";
const char* ERROR_PARSE_KEY = "ERROR // PARSE KEY";
const char* ERROR_HASH_PUB_KEY = "ERROR // WRONG HASH OF THE PUBLIC KEY";
const char* ERROR_HASH_MSG = "ERROR // WRONG HASH OF THE MESSAGE";
const char* ERROR_SIGNATURE = "ERROR // WRONG SIGNATURE";
const char* ERROR_RSA = "ERROR // ERROR WHEN ENCRYPTING WITH RSA";


static additionnal_ping_payload_t additionnal_ping_payload;

static cmd_buffer_t buffer;

void cmd_init() {
	memset(&buffer.stored_items, 0, sizeof(buffer.stored_items));
}

uint8_t key_hash_is_correct(const cmd_signature_t* signature) {
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, (unsigned char *) lownet_public_key, LOWNET_KEY_SIZE_RSA);
	uint8_t hash[CMD_HASH_SIZE];
  	mbedtls_sha256_finish(&ctx, hash);
	mbedtls_sha256_free(&ctx);

  	return !memcmp(signature->hash_key, hash, CMD_HASH_SIZE);
}

uint8_t msg_hash_is_correct(const lownet_frame_t* frame, const cmd_signature_t* signature) {
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	unsigned char msg [LOWNET_FRAME_SIZE];
	memcpy(msg, frame, LOWNET_FRAME_SIZE);
	mbedtls_sha256_update(&ctx, msg, LOWNET_FRAME_SIZE);
	uint8_t hash[CMD_HASH_SIZE];
  	mbedtls_sha256_finish(&ctx, hash);
	mbedtls_sha256_free(&ctx);

  	return !memcmp(signature->hash_msg, hash, CMD_HASH_SIZE);
}

int encrypt_rsa(const unsigned char* rsa_input, unsigned char* rsa_output) {
    mbedtls_pk_context pk;
	mbedtls_rsa_context rsa;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_parse_key(&pk, (unsigned char *) lownet_public_key, LOWNET_KEY_SIZE_RSA, NULL, 0, NULL ,0))	{
		mbedtls_rsa_free(&rsa);
		return -1;
	}

	memcpy(&rsa, mbedtls_pk_rsa(pk), sizeof(rsa));

	if (mbedtls_rsa_public(&rsa, rsa_input, rsa_output)) {
		mbedtls_rsa_free(&rsa);
		return -1;
	}

	mbedtls_rsa_free(&rsa);

	return 0;
}

uint8_t signature_is_correct(const lownet_frame_t* frame, const cmd_signature_t* first_signature, const cmd_signature_t* second_signature) {
	if (memcmp(first_signature->hash_key, second_signature->hash_key, CMD_HASH_SIZE)) {	// Different hash of public key.
		serial_write_line(ERROR_HASH_PUB_KEY);
		return 0;
	}

	if (memcmp(first_signature->hash_msg, second_signature->hash_msg, CMD_HASH_SIZE)) {	// Different hash of the message.
		serial_write_line(ERROR_HASH_MSG);
		return 0;
	}

	if (!key_hash_is_correct(first_signature)) {	// Wrong hash of the public key.
		serial_write_line(ERROR_HASH_PUB_KEY);
		return 0;
	}

	if (!msg_hash_is_correct(frame, first_signature)) {	// Wrong hash of the message.
		serial_write_line(ERROR_HASH_MSG);
		return 0;
	}

	// CHECK SIGNATURE.

	// Join the two parts of the signature.
	uint8_t signature[CMD_BLOCK_SIZE];
	memcpy(signature, first_signature->sig_part, CMD_BLOCK_SIZE / 2);
	memcpy(signature + (CMD_BLOCK_SIZE / 2), second_signature->sig_part, CMD_BLOCK_SIZE / 2);

	unsigned char rsa_input [RSA_INPUT_SIZE];
	memset(rsa_input, 0, RSA_INPUT_NB_0);
	memset(rsa_input + RSA_INPUT_NB_0, 1, RSA_INPUT_NB_1);

	// Add the hash of the message.
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	unsigned char msg [LOWNET_FRAME_SIZE];
	memcpy(msg, frame, LOWNET_FRAME_SIZE);
	mbedtls_sha256_update(&ctx, msg, LOWNET_FRAME_SIZE);
	uint8_t hash[CMD_HASH_SIZE];
  	mbedtls_sha256_finish(&ctx, hash);
	mbedtls_sha256_free(&ctx);

	memcpy(rsa_input + RSA_INPUT_NB_0 + RSA_INPUT_NB_1, hash, CMD_HASH_SIZE);

	// Calculate the signature with RSA.
	uint8_t right_signature[CMD_BLOCK_SIZE];
	if (encrypt_rsa(rsa_input, right_signature)) {
		serial_write_line(ERROR_RSA);
		return 0;
	}

	// Compare the two signatures.
	if (!memcmp(signature, right_signature, CMD_BLOCK_SIZE)) {	// Wrong signature
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

	uint8_t bite = 0;

	switch (frame_type) {
	case CMD_FRAME_UNSIGNED:
		return;		// Ignore non-signed frames.
		break;
	case CMD_FRAME_SIGNED:
		if (memcpy(&buffer.frame, frame + frame_header_size, sizeof(lownet_frame_t)) == &buffer.frame) {
			set_frame_bit(buffer.stored_items);
		}
		if (bite % 2 == 0) {
			process_command_frame(frame);
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
			// process_command_frame(&buffer.frame);
			serial_write_line("Signature verified, should process the frame");
			memset(&buffer.stored_items, 0, sizeof(buffer.stored_items));
		}
	}

	
}
