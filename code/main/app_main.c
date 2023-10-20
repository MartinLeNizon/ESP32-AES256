/* ----------------------------------------------
Lim. 10 s for the 3 frames when signed
-----------------------------------------------*/

/* -------------------------------------------------- TO-DO -----------------------------------------------

Set the timer of 10 seconds when receiving a signed frame

Check that a command is valid if:
i) signature is valid
ii) no valid command with equal or higher sequence number has been received

Should the input be too short, it will be padded with zeroes. (2.7)

----------------------------------------------------------------------------------------------------------*/

// CSTDLIB includes.
#include <stdio.h>
#include <string.h>

#include <esp_log.h>
#include <esp_random.h>

#include <aes/esp_aes.h>

// LowNet includes.
#include "lownet.h"

#include "serial_io.h"
#include "utility.h"

#include "app_chat.h"
#include "app_ping.h"
#include "app_command.h"

const char* ERROR_OVERRUN = "ERROR // INPUT OVERRUN";
const char* ERROR_UNKNOWN = "ERROR // PROCESSING FAILURE";

const char* ERROR_COMMAND = "Command error";
const char* ERROR_ARGUMENT = "Argument error";

void app_frame_dispatch(const lownet_frame_t* frame) {
	// Mask the signing bits.
	switch(frame->protocol & 0b00111111) {
		case LOWNET_PROTOCOL_TIME:
			// Ignore TIME packets, deprecated.
			break;

		case LOWNET_PROTOCOL_CHAT:
			chat_receive(frame);
			break;

		case LOWNET_PROTOCOL_PING:
			ping_receive(frame);
			break;

		case LOWNET_PROTOCOL_COMMAND:
			handle_command_frame(frame);
			break;
	}
}

void lownet_decrypt(const lownet_secure_frame_t* cipher, lownet_secure_frame_t* plain) {
	const uint8_t* aes_key = lownet_get_key()->bytes;
	uint8_t aes_ivt[LOWNET_IVT_SIZE];
	memcpy(aes_ivt, cipher->ivt, LOWNET_IVT_SIZE);

	esp_aes_context aes_ctx;
	esp_aes_init(&aes_ctx);

	if (esp_aes_setkey(&aes_ctx, aes_key, 256))
		return;

	memcpy(plain->ivt, cipher->ivt, LOWNET_IVT_SIZE);

	unsigned char cipher_string [ENCRYPTED_LENGTH];
	unsigned char plain_string [ENCRYPTED_LENGTH];
	memcpy(cipher_string, &cipher->frame, ENCRYPTED_LENGTH);
	esp_aes_crypt_cbc(&aes_ctx, ESP_AES_DECRYPT, ENCRYPTED_LENGTH, aes_ivt, cipher_string, plain_string);
	memcpy(&plain->frame, plain_string, ENCRYPTED_LENGTH);

	esp_aes_free(&aes_ctx);
}

void lownet_encrypt(const lownet_secure_frame_t* plain, lownet_secure_frame_t* cipher) {
	const uint8_t* aes_key = lownet_get_key()->bytes;
	uint8_t aes_ivt[LOWNET_IVT_SIZE];
	memcpy(aes_ivt, plain->ivt, LOWNET_IVT_SIZE);

	esp_aes_context aes_ctx;
	esp_aes_init(&aes_ctx);

	if (esp_aes_setkey(&aes_ctx, aes_key, 256))
		return;

	memcpy(cipher->ivt, plain->ivt, LOWNET_IVT_SIZE);

	unsigned char plain_string [ENCRYPTED_LENGTH];
	unsigned char cipher_string [ENCRYPTED_LENGTH];
	memcpy(plain_string, &plain->frame, ENCRYPTED_LENGTH);
	esp_aes_crypt_cbc(&aes_ctx, ESP_AES_ENCRYPT, ENCRYPTED_LENGTH, aes_ivt, plain_string, cipher_string);
	memcpy(&cipher->frame, cipher_string, ENCRYPTED_LENGTH);

	esp_aes_free(&aes_ctx);
}

void two_way_test() {
	// Encrypts and then decrypts a string, can be used to sanity check your
	//	implementation.
	lownet_secure_frame_t plain;
	lownet_secure_frame_t cipher;
	lownet_secure_frame_t back;

	memset(&plain, 0, sizeof(lownet_secure_frame_t));
	memset(&cipher, 0, sizeof(lownet_secure_frame_t));
	memset(&back, 0, sizeof(lownet_secure_frame_t));

	*((uint32_t*)plain.ivt) = 123456789;
	const char* message = "some_text";
	strcpy((char*)plain.frame.payload, message);

	lownet_encrypt(&plain, &cipher);
	lownet_decrypt(&cipher, &back);

	if (strlen((char*)back.frame.payload) != strlen(message)) {
		ESP_LOGE("APP", "Length violation");
	} else {
		serial_write_line((char*)back.frame.payload);
	}
}

void app_main(void) {
	char msg_in[MSG_BUFFER_LENGTH];
	char msg_out[MSG_BUFFER_LENGTH];

	// Generate 32 bytes of noise up front and dump the HEX out.  No explicit purpose except
	//	convenience if you want an arbitrary 32 bytes.
	// uint32_t rand = esp_random();
	uint32_t key_buffer[8];
	for (int i = 0; i < 8; ++i) {
		key_buffer[i] = esp_random();
	}
	ESP_LOG_BUFFER_HEX("Hex", key_buffer, 32);
	
	// Initialize the serial services.
	init_serial_service();

	// Initialize the LowNet services, pass in function pointers for encrypt and
	//	decrypt functions (defined above, TO BE IMPLEMENTED BY STUDENTS).
	lownet_init(app_frame_dispatch, lownet_encrypt, lownet_decrypt);


	// Dummy implementation -- this isn't true network time!  Following 2
	//	lines are not needed when an actual source of network time is present.
	lownet_time_t init_time = {1, 0};
	lownet_set_time(&init_time);

	while (true) {
		memset(msg_in, 0, MSG_BUFFER_LENGTH);
		memset(msg_out, 0, MSG_BUFFER_LENGTH);

		if (!serial_read_line(msg_in)) {
			// Quick & dirty input parse.  Presume input length > 0.
			if (msg_in[0] == '/') {
				// Some kind of command.
				if (!strncmp(msg_in, "/ping 0x", 8) && strlen(msg_in) == 10) {
					// Ping command, extract destination.
					uint32_t target = hex_to_dec(msg_in + 8);
					if (!target || target > 0xFF) {
						serial_write_line(ERROR_COMMAND);
						continue;
					} else {
						ping((uint8_t)(target & 0x000000FF));
					}

				} else if (!strcmp(msg_in, "/date")) {
					// Date command, get the network time and write it to serial somehow.
					lownet_time_t net_time = lownet_get_time();
					// Hack the parts field into a fixed point number of milliseconds.
					uint32_t milli = ((uint32_t)net_time.parts * 1000) / 256;
					sprintf(msg_out, "%lu.%03lu sec since the course started.", net_time.seconds, milli);
					serial_write_line(msg_out);

				} else if (!strncmp(msg_in, "/enc", 4) && strlen(msg_in) == 6) {
					// Real quick and dirty swapper between pre-established AES keys.
					//	Usage: '/enc 0' or '/enc 1' or '/enc x' (clears encryption key).
					if (msg_in[5] == '0') {
						lownet_key_t use_key = lownet_keystore_read(0);
						lownet_set_key(&use_key);
						serial_write_line("Set lownet stored key 0.");
					} else if (msg_in[5] == '1') {
						lownet_key_t use_key = lownet_keystore_read(1);
						lownet_set_key(&use_key);
						serial_write_line("Set lownet stored key 1.");
					} else if (msg_in[5] == 'x') {
						lownet_set_key(NULL);
						serial_write_line("Disabled lownet encryption.");
					}

				} else if (!strcmp(msg_in, "/dbg") && lownet_get_key() != NULL) {
					// Tiny little debugging helper -- see two_way_test(..) implementation above.
					two_way_test();
				} else {
					serial_write_line(ERROR_COMMAND);

				}
			} else if (msg_in[0] == '@' && strlen(msg_in) > 6 && !strncmp(msg_in, "@0x", 3) && msg_in[5] == ' ') {
				// Probably a chat 'tell' command.
				char address[3] = {msg_in[3], msg_in[4], 0};
				uint8_t target = (uint8_t)(hex_to_dec(address));
				// Sanitize message for printable characters, replace every nonprintable with '?'
				for (int i = 6; i < strlen(msg_in); ++i) {
					if (!util_printable(msg_in[i])) {
						msg_in[i] = '?';
					}
				}
				chat_tell(msg_in + 6, target);

			} else {
				// Default, chat broadcast message.
				// Sanitize message for printable characters, replace every nonprintable with '?'
				for (int i = 0; i < strlen(msg_in); ++i) {
					if (!util_printable(msg_in[i])) {
						msg_in[i] = '?';
					}
				}
				chat_shout(msg_in);
			}
		}
	}
}
