/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018 - 2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef __SENTINEL_PROXY_ZMQ_H__
#define __SENTINEL_PROXY_ZMQ_H__

#include <czmq.h>

#include "proxy_mqtt.h"
#include "con_peer_list.h"

struct zmq {
	zsock_t *data_sock;
	zactor_t *monitor;
	zloop_t *zloop;
	struct mqtt *mqtt;
	struct con_peer_list *con_peer_list;
};

// NOTE: This is private API exposed just for the testing.
// It is NOT supposed to be used anywhere else.

// Checks whether received ZMQ message has correct number of frames and
// correct topic. In case a message is OK returns 0 otherwise -1 is returned.
int check_msg(size_t frames, unsigned char *topic, size_t topic_len);

// NOTE: This is public API intended for normal use.

// Initializes given zmq struct. It allocates memory, binds to given ZMQ
// endpoint, starts ZMQ socket monitor and adds appropriate callbacks to event 
// loop. If any of these fails the whole process is aborted.
// DOES assert check for zmq, mqtt, zloop and sock_path.
// For the subsequent data PULLing from ZMQ endpoint and forwarding them to given
// MQTT client, passed event loop MUST be started after calling this. 
void init_zmq(struct zmq *zmq, struct mqtt *mqtt, zloop_t *zloop,
	const char *sock_path);

// If zmq is not NULL, removes all callbacks from event loop, destroys ZMQ
// PULL socket and ZMQ socket monitor and frees all the memory hold by zmq.
void destroy_zmq(struct zmq *zmq);

#endif /*__SENTINEL_PROXY_ZMQ_H__*/

