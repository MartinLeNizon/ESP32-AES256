#ifndef GUARD_APP_PING_H
#define GUARD_APP_PING_H

#include <stdint.h>

#include "lownet.h"
#include "app_command.h"

void ping(uint8_t node);

void ping_additionnal_content(uint8_t node, additionnal_ping_payload_t* content);

void ping_receive(const lownet_frame_t* frame);

#endif