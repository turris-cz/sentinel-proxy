/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018-2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#ifndef __SENTINEL_PROXY_ZMQ_MSG_H__
#define __SENTINEL_PROXY_ZMQ_MSG_H__

#include <stdbool.h>
#include <zmq.h>

struct proxy_zmq_msg {
	size_t alloc_parts;
	size_t recv_parts;
	zmq_msg_t *msg_parts;
	// zmq_msg_t *recv_ptr;
	bool is_complete;
};

void proxy_zmq_msg_init(struct proxy_zmq_msg *msg, size_t init_size);
bool proxy_zmq_msg_rdy_recv(void *zmq_sock);
int proxy_zmq_msg_recv(void *zmq_sock, struct proxy_zmq_msg *msg);
void proxy_zmq_msg_close(struct proxy_zmq_msg *msg);
void proxy_zmq_msg_destroy(struct proxy_zmq_msg *msg);
bool proxy_zmq_msg_is_complete(struct proxy_zmq_msg *msg);

#endif /*__SENTINEL_PROXY_ZMQ_MSG_H__*/




