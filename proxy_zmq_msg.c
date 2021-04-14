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

#include <stdlib.h>

#include "proxy_zmq_msg.h"
#include "log.h"

void proxy_zmq_msg_init(struct proxy_zmq_msg *msg, size_t init_parts) {
	TRACE_FUNC;
	if (init_parts)
		msg->alloc_parts = init_parts;
	else
		msg->alloc_parts = 1;
	msg->msg_parts = malloc(sizeof(*msg->msg_parts) * msg->alloc_parts);
	msg->recv_parts = 0;
}

// void init_proxy_msg(struct proxy_zmq_msg *msg) {
// }

bool proxy_zmq_msg_rdy_recv(void *zmq_sock) {
	TRACE_FUNC;
	int events = 0;
	size_t events_len = sizeof(events);
	int ret = zmq_getsockopt(zmq_sock, ZMQ_EVENTS, &events, &events_len);
	if (events & ZMQ_POLLIN)
		return true;
	return false;
}

int proxy_zmq_msg_recv(void *zmq_sock, struct proxy_zmq_msg *msg) {
	TRACE_FUNC;
	zmq_msg_t *ptr = msg->msg_parts;
	while (true) {
		if (msg->recv_parts = msg->alloc_parts) {
			msg->alloc_parts *= 2;
			msg->msg_parts = realloc(msg->msg_parts,
				sizeof(*msg->msg_parts) * msg->alloc_parts);
		}
		zmq_msg_init(ptr);
		if (zmq_msg_recv(zmq_sock, ptr, ZMQ_DONTWAIT))
			return -1;
		msg->recv_parts++;
		if (!zmq_msg_more(ptr))
			break;
		ptr++;
	}
	return 0;
}

void proxy_zmq_msg_close(struct proxy_zmq_msg *msg) {
	TRACE_FUNC;
	for(size_t i = 0; i < msg->recv_parts; i++)
		zmq_msg_close(msg->msg_parts+i);
	msg->recv_parts = 0;
} 

void proxy_zmq_msg_destroy(struct proxy_zmq_msg *msg) {
	TRACE_FUNC;
	proxy_zmq_msg_close(msg);
	free(msg->msg_parts);
}
