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

#ifndef __SENTINEL_PROXY_ZMQ_H__
#define __SENTINEL_PROXY_ZMQ_H__

#include <event2/event.h>
#include <zmq.h>

#include "proxy_zmq_msg.h"

struct proxy_zmq {
	void *ctx;
	void *data_sock;
	void *mon_sock;
	struct event *recv_data_sock_ev;
	struct event *recv_mon_sock_ev;
	struct proxy_zmq_msg *msg_buff;
};

int proxy_zmq_init(struct proxy_zmq *zmq, struct event_base *ev_base,
	const char *sock_addr);
void proxy_zmq_destroy(struct proxy_zmq *zmq);

#endif /*__SENTINEL_PROXY_ZMQ_H__*/
