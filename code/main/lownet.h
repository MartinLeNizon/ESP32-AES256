#ifndef GUARD_LOWNET_H
#define GUARD_LOWNET_H

#include <stdint.h>

#define LOWNET_SERVICE_CORE		1
#define LOWNET_SERVICE_PRIO		10

#define LOWNET_PROTOCOL_RESERVE	0x00
#define LOWNET_PROTOCOL_TIME	0x01
#define LOWNET_PROTOCOL_CHAT	0x02
#define LOWNET_PROTOCOL_PING	0x03
#define LOWNET_PROTOCOL_COMMAND	0x04

#define LOWNET_FRAME_SIZE		200
#define LOWNET_SOURCE_SIZE		1
#define LOWNET_DEST_SIZE		1
#define LOWNET_PROTOCOL_SIZE	1
#define LOWNET_LENGTH_SIZE		1
#define LOWNET_HEAD_SIZE		(LOWNET_SOURCE_SIZE + LOWNET_DEST_SIZE + LOWNET_PROTOCOL_SIZE + LOWNET_LENGTH_SIZE)	// 4 bytes.
#define LOWNET_CRC_SIZE			4
#define LOWNET_PAYLOAD_SIZE		(LOWNET_FRAME_SIZE - (LOWNET_HEAD_SIZE + LOWNET_CRC_SIZE))	// 192 bytes.

#define LOWNET_IVT_SIZE			16
#define LOWNET_CRYPTPAD_SIZE	8

#define ENCRYPTED_LENGTH 		(LOWNET_FRAME_SIZE + LOWNET_CRYPTPAD_SIZE)

#define LOWNET_KEY_SIZE_AES		32
#define LOWNET_KEY_SIZE_RSA		256

// Lownet basic frame structure.
typedef struct __attribute__((__packed__))
{
	uint8_t		source;
	uint8_t		destination;
	uint8_t		protocol;
	uint8_t		length;
	uint8_t		payload[LOWNET_PAYLOAD_SIZE];
	uint32_t	crc;
} lownet_frame_t;

// Lownet encrypted frame structure.
typedef struct __attribute__((__packed__))
{
	uint8_t			ivt[LOWNET_IVT_SIZE];
	lownet_frame_t	frame;
	uint8_t			padding[LOWNET_CRYPTPAD_SIZE];
} lownet_secure_frame_t;

// Lownet timestamp structure.
typedef struct {
	uint32_t	seconds;	// Seconds since UNIX epoch.
	uint8_t		parts;		// Milliseconds, 1000/256 resolution.
} lownet_time_t;

// Lownet key structure.  Bytes member MUST point to a usable contiguous
//	region of memory of AT LEAST 'size' bytes.
typedef struct {
	uint8_t* 	bytes;
	uint32_t 	size;
} lownet_key_t;

typedef void (*lownet_recv_fn)(const lownet_frame_t* frame);
typedef void (*lownet_cipher_fn)(const lownet_secure_frame_t* in_frame, lownet_secure_frame_t* out_frame);

void lownet_init(
	lownet_recv_fn receive_cb,
	lownet_cipher_fn encrypt_fn,
	lownet_cipher_fn decrypt_fn
);
void lownet_send(const lownet_frame_t* frame);


lownet_time_t	lownet_get_time();
void 			lownet_set_time(const lownet_time_t* time);

uint8_t			lownet_get_device_id();

const lownet_key_t*	lownet_get_key();
void				lownet_set_key(const lownet_key_t* key);
void				lownet_set_stored_key(uint8_t key_id);

const char*			lownet_get_signing_key();

#include "lownet_crypt.h"
#include "lownet_util.h"

// Some pre-shared lownet AES keys.
static const lownet_input_key_t base_shared_key = {{
	0xc0c71cc5, 0x748ce81a, 0x4b0e4aa7, 0x70c0d55e,
	0x58957e01, 0xed51d8cc, 0x26b844c4, 0x49c50530
}};
static const lownet_input_key_t alt_shared_key = {{
	0x0b7b9b81, 0x350ecef1, 0x7a7b0fbb, 0xe9f134d2,
	0x33bffa82, 0xc7c82730, 0x4861bba3, 0x44e44aba
}};

// Master node signing key.
static const char lownet_public_key[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG9VF9wuocepQnwBkxUb\n"
"4YxCo1NJ1MAKAGoaK2csfPABSRkjlESev42rFVzejGtOp2pxKcyihDXVe1BEzD0q\n"
"HXxEgtkRy0/bJNhGxoMmWTbikO3BmIMIO9zIk3leaNtyy49U27CKDgUHOPp6zd3c\n"
"dgD3nE4fIE7tU3mCJ4xh5xMHeyoqa/MV3EkE9VDV2vCTP3KyKDFObYqig6XWydeQ\n"
"CPmSAr0rRYiriguOvQGGxPeaCWPaUAG+t2W7ydpeju+Dkzl6NHm0q9JdLfpg8zje\n"
"BgLekdFxyM4jAK2hCX+vswUrYqbm5m9rptxQUuSYpk27Ew7uWRaomAWWeMLIg+zt\n"
"rwIDAQAB\n"
"-----END PUBLIC KEY-----";

#endif