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

#include "proxy_zmq.h"
#include "log.h"

#define MONITOR "inproc://monitor"
#define MSG_INIT_SIZE 2

static void proc_data_sock_data(struct proxy_zmq *zmq) {
	TRACE_FUNC;
}

static void proc_mon_sock_data(struct proxy_zmq *zmq) {
	TRACE_FUNC;
}

static void recv_data_sock_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
	if(proxy_zmq_msg_rdy_recv(zmq->data_sock)) {
		if (proxy_zmq_msg_recv(zmq->data_sock, zmq->msg_buff)) {
			// TODO handle error
		} else {
			proc_data_sock_data(zmq);
		}
		proxy_zmq_msg_close(zmq->msg_buff);
	}
}

static void recv_mon_sock_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
	if(proxy_zmq_msg_rdy_recv(zmq->data_sock)) {
		if (proxy_zmq_msg_recv(zmq->mon_sock, zmq->msg_buff)) {
			// TODO handle error
		} else {
			proc_mon_sock_data(zmq);
		}
		proxy_zmq_msg_close(zmq->msg_buff);
	}
}

int proxy_zmq_init(struct proxy_zmq *zmq, struct event_base *ev_base,
		const char *sock_addr) {
	TRACE_FUNC;
	zmq->ctx = zmq_ctx_new();
	
	printf("a\n");

	int ret;
	zmq->data_sock = zmq_socket(zmq->ctx, ZMQ_PULL);
	// maybe set ZMQ_RCVTIMEO
	// maybe set max msg size
	printf("b\n");
    ret = zmq_bind(zmq->data_sock, sock_addr);
	
	printf("c\n");
	ret = zmq_socket_monitor(zmq->data_sock, MONITOR, ZMQ_EVENT_ALL);
	zmq->mon_sock = zmq_socket(zmq->ctx, ZMQ_PAIR);
	// maybe set ZMQ_RCVTIMEO
	ret = zmq_connect(zmq->mon_sock, MONITOR);


	printf("f\n");
	zmq->msg_buff = malloc(sizeof(*zmq->msg_buff));
	proxy_zmq_msg_init(zmq->msg_buff, MSG_INIT_SIZE);

	printf("d\n");
	int fd;
	size_t fd_size = sizeof(fd);
	ret = zmq_getsockopt(zmq->data_sock, ZMQ_FD, &fd, &fd_size);
	printf("fd %d\n", fd);

	zmq->recv_data_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
		recv_data_sock_cb, zmq);
	ret = event_add(zmq->recv_data_sock_ev, NULL);

	ret = zmq_getsockopt(zmq->mon_sock, ZMQ_FD, &fd, &fd_size);
	printf("fd %d\n", fd);


	zmq->recv_mon_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
		recv_mon_sock_cb, zmq);
	ret = event_add(zmq->recv_mon_sock_ev, NULL);

	return 0;
}

void proxy_zmq_destroy(struct proxy_zmq *zmq) {
	TRACE_FUNC;
	event_free(zmq->recv_data_sock_ev);
	event_free(zmq->recv_mon_sock_ev);

	zmq_close(zmq->data_sock);
	zmq_close(zmq->mon_sock);
	zmq_ctx_term(zmq->ctx);

	proxy_zmq_msg_destroy(zmq->msg_buff);
	free(zmq->msg_buff);
}
