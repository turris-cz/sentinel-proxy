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

#include <event2/event_struct.h>

#include "proxy_zmq.h"
#include "common.h"

#define MONITOR "inproc://monitor"
#define MSG_INIT_SIZE 2

static void proc_data_sock_data(struct proxy_zmq *zmq) {
	TRACE_FUNC;
	CHECK_ERR_VOID_LOG(zmq->msg_buff->recv_parts != 2,
		"Received malformed ZMQ message - message has %ld parts instead of two",
		zmq->msg_buff->recv_parts);

	uint8_t *topic = zmq_msg_data(&zmq->msg_buff->msg_parts[0]);
	size_t topic_len = zmq_msg_size(&zmq->msg_buff->msg_parts[0]);
	CHECK_ERR_VOID_LOG(topic_len < TOPIC_PREFIX_LEN
		|| topic_len > ZMQ_MAX_TOPIC_LEN
		|| strncmp(TOPIC_PREFIX, topic, TOPIC_PREFIX_LEN),
		"Received malformed ZMQ message - wrong message topic");

	uint8_t *data = zmq_msg_data(&zmq->msg_buff->msg_parts[1]);
	size_t data_len = zmq_msg_size(&zmq->msg_buff->msg_parts[1]);

	proxy_mqtt_send_data(zmq->mqtt, topic, topic_len, data, data_len);
}

static void proc_mon_sock_data(struct proxy_zmq *zmq) {
	TRACE_FUNC;

}

// static void recv_data_sock_cb(evutil_socket_t fd, short events, void *arg) {
// 	TRACE_FUNC;
// 	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
// 	while(proxy_zmq_msg_rdy_recv(zmq->data_sock)) {
// 		if (!proxy_zmq_msg_recv(zmq->data_sock, zmq->msg_buff))
// 			proc_data_sock_data(zmq);
// 		proxy_zmq_msg_close(zmq->msg_buff);
// 	}
// }

// static void recv_mon_sock_cb(evutil_socket_t fd, short events, void *arg) {
// 	TRACE_FUNC;
// 	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;
// 	// ZMQ FDs are by design edge-triggered
// 	while(proxy_zmq_msg_rdy_recv(zmq->mon_sock)) {
// 		if (!proxy_zmq_msg_recv(zmq->mon_sock, zmq->msg_buff))
// 			proc_mon_sock_data(zmq);
// 		proxy_zmq_msg_close(zmq->msg_buff);
// 	}
// }


static void prep_watch_cb(struct evwatch *evwatch,
		const struct evwatch_prepare_cb_info *cb_info, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;

	if (proxy_zmq_msg_rdy_recv(zmq->data_sock))
		printf("can receive\n");

}

static void check_watch_cb(struct evwatch *evwatch,
		const struct evwatch_check_cb_info *cb_info, void *arg) {
	TRACE_FUNC;
	struct proxy_zmq *zmq = (struct proxy_zmq *)arg;

	if (proxy_zmq_msg_rdy_recv(zmq->data_sock))
		printf("can receive\n");

}

int proxy_zmq_init(struct proxy_zmq *zmq, struct event_base *ev_base,
		const char *sock_addr) {
	TRACE_FUNC;
	
	int ret;

	zmq->ctx = zmq_ctx_new();	
	assert(zmq->ctx);
	// printf("a\n");

	zmq->data_sock = zmq_socket(zmq->ctx, ZMQ_PULL);
	assert(zmq->data_sock);
	// maybe set ZMQ_RCVTIMEO
	// maybe set max msg size
	// printf("b\n");

	ret = zmq_socket_monitor(zmq->data_sock, MONITOR, ZMQ_EVENT_ALL);
	assert(ret == 0);
	zmq->mon_sock = zmq_socket(zmq->ctx, ZMQ_PAIR);
	assert(zmq->mon_sock);

	// maybe set ZMQ_RCVTIMEO
	
	
	// printf("c\n");
	ret = zmq_connect(zmq->mon_sock, MONITOR);
	assert(ret == 0);




	int fd;
	size_t fd_size = sizeof(fd);

	ret = zmq_getsockopt(zmq->mon_sock, ZMQ_FD, &fd, &fd_size);
	assert(ret == 0);

	// printf("ret: %d\n", ret);
	// printf("fd %d\n", fd);


	// zmq->recv_mon_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
	// 	recv_mon_sock_cb, zmq);
	// assert(zmq->recv_mon_sock_ev);
	// ret = event_add(zmq->recv_mon_sock_ev, NULL);
	// assert(ret == 0);

	// this MUST be done before starting to poll on minitor socket FD
	// there are no event notifications otherwise
	// https://github.com/flux-framework/flux-core/issues/524
	// https://github.com/chu11/flux-core/blob/issue524-reproducerexample/src/common/libutil/test/zmqinproc.c
	uint32_t events = 0;
	size_t events_len = sizeof(events);
	ret = zmq_getsockopt(zmq->mon_sock, ZMQ_EVENTS, &events, &events_len);



	// printf("f\n");
    ret = zmq_bind(zmq->data_sock, sock_addr);
	assert(ret == 0);
	

	// ret = zmq_getsockopt(zmq->data_sock, ZMQ_FD, &fd, &fd_size);
	// assert(ret == 0);

	// printf("ret: %d\n", ret);
	// printf("fd %d\n", fd);

	// zmq->recv_data_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST,
	// 	recv_data_sock_cb, zmq);
	// assert(zmq->recv_data_sock_ev);
	// ret = event_add(zmq->recv_data_sock_ev, NULL);
	// assert(ret == 0);

	zmq->msg_buff = malloc(sizeof(*zmq->msg_buff));
	proxy_zmq_msg_init(zmq->msg_buff, MSG_INIT_SIZE);


	zmq->prep_watch = evwatch_prepare_new(ev_base, prep_watch_cb, zmq);
	assert(zmq->prep_watch);

	zmq->check_watch = evwatch_check_new(ev_base, check_watch_cb, zmq);
	assert(zmq->check_watch);


	return 0;
}

void proxy_zmq_destroy(struct proxy_zmq *zmq) {
	TRACE_FUNC;
	// event_free(zmq->recv_data_sock_ev);
	// event_free(zmq->recv_mon_sock_ev);

	zmq_close(zmq->data_sock);
	zmq_close(zmq->mon_sock);
	zmq_ctx_term(zmq->ctx);

	proxy_zmq_msg_destroy(zmq->msg_buff);
	free(zmq->msg_buff);
}
