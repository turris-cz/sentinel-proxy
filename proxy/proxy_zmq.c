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

#include "proxy_zmq.h"
#include "common.h"
#include "log.h"

int check_msg(size_t frames, unsigned char *topic, size_t topic_len) {
	TRACE_FUNC;
	if (topic == NULL) {
		error("topic is NULL");
		return -1;
	}
	if (frames < 1 || frames > 2) {
		error("Received and ignoring %ld parts malformed message", frames);
		return -1;
	}
	if(topic_len <= TOPIC_PREFIX_LEN
			|| topic_len > ZMQ_MAX_TOPIC_LEN
			|| strncmp(TOPIC_PREFIX, topic, TOPIC_PREFIX_LEN)) {
		error("Wrong message topic");
		return -1;
	}
	return 0;
}

int recv_data_cb(zloop_t *loop, zsock_t *reader, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	TRACE_FUNC;
	zmsg_t *msg = zmsg_recv(reader);
	if (!msg) {
		error("Cannot receive from data socket");
		return 0;
	}
	// A message is supposed to have exactly one or two frames.
	// The first frame MUST be always a message topic.
	size_t msg_size = zmsg_size(msg);
	zframe_t *topic_frame = zmsg_first(msg);
	size_t topic_len = zframe_size(topic_frame);
	unsigned char *topic = zframe_data(topic_frame);
	if (check_msg(msg_size, topic, topic_len))
		goto ret;
	struct zmq *zmq = (struct zmq *)arg;
	if (msg_size == 1) {
		// First welcome message
		// WARNING: __fd is NOT official nor documented use of czmq API !!!
		// It can potentionally change at any time.  
		add_peer(zmq->con_peer_list, atoi(zframe_meta(topic_frame, "__fd")),
			(char *)topic, topic_len);
	}
	if (msg_size == 2) {
		// Normal message with data
		zframe_t *payload_frame = zmsg_last(msg);
		mqtt_send_data(zmq->mqtt, (uint8_t *)topic, topic_len,
			(uint8_t *)zframe_data(payload_frame), zframe_size(payload_frame));
	}
ret:
	zmsg_destroy(&msg);
	return 0;
}

int monitor_cb(zloop_t *loop, zsock_t *reader, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	TRACE_FUNC;
	zmsg_t *msg = zmsg_recv(reader);
	zmsg_first(msg);
	// Message from the monitor has two parts. The first is DISCONNECTED string
	// and the second is session/connection file descriptor string.
	zframe_t *frame = zmsg_next(msg);
	del_peer(((struct zmq *)arg)->con_peer_list, atoi(zframe_data(frame)));
	zmsg_destroy(&msg);
	return 0;
}

int init_zmq(struct zmq *zmq, struct mqtt *mqtt ,zloop_t *zloop,
		const char *sock_path) {
	TRACE_FUNC;
	assert(zmq);
	assert(mqtt);
	assert(zloop);
	assert(sock_path);
	zmq->data_sock = zsock_new(ZMQ_PULL);
	assert(zmq->data_sock);
	zmq->monitor = zactor_new(zmonitor, zmq->data_sock);
	assert(zmq->monitor);
	assert(zstr_sendx(zmq->monitor, "LISTEN", "DISCONNECTED", NULL) == 0);
	assert(zstr_sendx(zmq->monitor, "START", NULL) == 0);
	assert(zsock_wait(zmq->monitor) == 0);
	assert(zsock_bind(zmq->data_sock, "%s", sock_path) == 0);
	assert(zloop_reader(zloop, zmq->data_sock, recv_data_cb, zmq) == 0);
	assert(zloop_reader(zloop, (zsock_t*)zmq->monitor, monitor_cb, zmq) == 0);
	zmq->mqtt = mqtt;
	zmq->zloop = zloop;
	zmq->con_peer_list = malloc(sizeof(*zmq->con_peer_list));
	init_con_peer_list(zmq->con_peer_list);
	return 0;
}

void destroy_zmq(struct zmq *zmq) {
	TRACE_FUNC;
	if (zmq) {
		zloop_reader_end(zmq->zloop, zmq->data_sock);
		zloop_reader_end(zmq->zloop, (zsock_t*)zmq->monitor);
		zactor_destroy(&zmq->monitor);
		zsock_destroy(&zmq->data_sock);
		destroy_con_peer_list(zmq->con_peer_list);
	}
}
