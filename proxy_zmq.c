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
	// zmq_msg_t *part = malloc(sizeof(*part));
	// while (true) {
	// 	// Create an empty ØMQ message to hold the message part
	// 	int rc = zmq_msg_init (part);
	// 	assert (rc == 0);
	// 	// Block until a message is available to be received from socket
	// 	rc = zmq_msg_recv(part, zmq->data_sock, ZMQ_DONTWAIT);
	// 	assert (rc != -1);
	// 	rc = zmq_msg_more (part);
	// 	zmq_msg_close (part);
		
	// 	if (rc) {
	// 		fprintf (stderr, "more\n");
	// 	}
	// 	else {
	// 		fprintf (stderr, "end\n");
	// 		break;
	// 	}
	// }
	// free(part);
	// printf("msg has %d parts\n", zmq->msg_buff->recv_parts);


}

static void proc_mon_sock_data(struct proxy_zmq *zmq) {
	TRACE_FUNC;
	// zmq_msg_t part;
	// while (true) {
	// 	// Create an empty ØMQ message to hold the message part
	// 	int rc = zmq_msg_init (&part);
	// 	assert (rc == 0);
	// 	// Block until a message is available to be received from socket
	// 	rc = zmq_msg_recv(&part, zmq->mon_sock, ZMQ_DONTWAIT);
	// 	assert (rc != -1);
	// 	if (zmq_msg_more (&part))
	// 	fprintf (stderr, "more\n");
	// 	else {
	// 	fprintf (stderr, "end\n");
	// 	break;
	// }
	// zmq_msg_close (&part); }
	// printf("msg has %d parts\n", zmq->msg_buff->recv_parts);
	// zmq_msg_t *part1 = malloc(sizeof(*part1));
	// int rc = zmq_msg_init (part1);
	// assert (rc == 0);
	// // Block until a message is available to be received from socket
	// rc = zmq_msg_recv(part1, zmq->mon_sock, ZMQ_DONTWAIT);
	// assert (rc != -1);
	// zmq_msg_t *part2 = malloc(sizeof(*part2));
	// rc = zmq_msg_init (part2);
	// assert (rc == 0);
	// // Block until a message is available to be received from socket
	// rc = zmq_msg_recv(part2, zmq->mon_sock, ZMQ_DONTWAIT);
	// assert (rc != -1);
	// proxy_zmq_msg_recv(zmq->mon_sock, zmq->msg_buff);

	
}

static void recv_data_sock_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
	while(proxy_zmq_msg_rdy_recv(zmq->data_sock)) {
		if (proxy_zmq_msg_recv(zmq->data_sock, zmq->msg_buff)) {
			// TODO handle error
			printf("data\n");
		} else {
			proc_data_sock_data(zmq);
		}
		proxy_zmq_msg_close(zmq->msg_buff);
		// proc_data_sock_data(zmq);
	}
}

static void recv_mon_sock_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
	while(proxy_zmq_msg_rdy_recv(zmq->mon_sock)) {
		if (proxy_zmq_msg_recv(zmq->mon_sock, zmq->msg_buff)) {
			// TODO handle error
			printf("mon\n");
		} else {
			proc_mon_sock_data(zmq);
		}
		proxy_zmq_msg_close(zmq->msg_buff);
		// proc_mon_sock_data(zmq);
	}
}

int proxy_zmq_init(struct proxy_zmq *zmq, struct event_base *ev_base,
		const char *sock_addr) {
	TRACE_FUNC;
	
	int ret;

	zmq->ctx = zmq_ctx_new();	
	assert(zmq->ctx);
	printf("a\n");

	zmq->data_sock = zmq_socket(zmq->ctx, ZMQ_PULL);
	assert(zmq->data_sock);
	// maybe set ZMQ_RCVTIMEO
	// maybe set max msg size
	printf("b\n");

	ret = zmq_socket_monitor(zmq->data_sock, MONITOR, ZMQ_EVENT_ALL);
	assert(ret == 0);
	zmq->mon_sock = zmq_socket(zmq->ctx, ZMQ_PAIR);
	assert(zmq->mon_sock);

	// maybe set ZMQ_RCVTIMEO
	
	
	printf("c\n");
	ret = zmq_connect(zmq->mon_sock, MONITOR);
	assert(ret == 0);




	int fd;
	size_t fd_size = sizeof(fd);

	ret = zmq_getsockopt(zmq->mon_sock, ZMQ_FD, &fd, &fd_size);
	assert(ret == 0);

	printf("ret: %d\n", ret);
	printf("fd %d\n", fd);



	zmq->recv_mon_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
		recv_mon_sock_cb, zmq);
	assert(zmq->recv_mon_sock_ev);
	ret = event_add(zmq->recv_mon_sock_ev, NULL);
	assert(ret == 0);

	// this MUST be done before starting to poll on minitor socket FD
	// there are no event notifications otherwise
	// https://github.com/flux-framework/flux-core/issues/524
	// https://github.com/chu11/flux-core/blob/issue524-reproducerexample/src/common/libutil/test/zmqinproc.c
	uint32_t events = 0;
	size_t events_len = sizeof(events);
	ret = zmq_getsockopt(zmq->mon_sock, ZMQ_EVENTS, &events, &events_len);



	printf("f\n");
    ret = zmq_bind(zmq->data_sock, sock_addr);
	assert(ret == 0);
	

	ret = zmq_getsockopt(zmq->data_sock, ZMQ_FD, &fd, &fd_size);
	assert(ret == 0);

	printf("ret: %d\n", ret);
	printf("fd %d\n", fd);

	zmq->recv_data_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
		recv_data_sock_cb, zmq);
	assert(zmq->recv_data_sock_ev);
	ret = event_add(zmq->recv_data_sock_ev, NULL);
	assert(ret == 0);

	// while (true) {
	// 	zmq_msg_t part;
	// 	while (true) {
	// 		// Create an empty ØMQ message to hold the message part
	// 		int rc = zmq_msg_init (&part);
	// 		assert (rc == 0);
	// 		// Block until a message is available to be received from socket
	// 		rc = zmq_msg_recv(&part, zmq->mon_sock, 0);
	// 		assert (rc != -1);
	// 		if (zmq_msg_more (&part))
	// 		fprintf (stderr, "more\n");
	// 		else {
	// 		fprintf (stderr, "end\n");
	// 		break;
	// 	}
	// 	zmq_msg_close (&part); }
	// }


	// printf("d\n");
	zmq->msg_buff = malloc(sizeof(*zmq->msg_buff));
	proxy_zmq_msg_init(zmq->msg_buff, MSG_INIT_SIZE);

	// printf("alloc parts: %d\n", zmq->msg_buff->alloc_parts);
	// printf("recv parts: %d\n", zmq->msg_buff->recv_parts);
	// printf("msg parts: %p\n",zmq->msg_buff->msg_parts);


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
