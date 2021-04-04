#include <event2/event.h>
#include <zmq.h>

#define MONITOR "inproc://monitor"


void *ctx;
void *data_sock;
void *mon_sock;

struct event *recv_data_sock_ev;
struct event *recv_mon_sock_ev;


void recv_data_sock() {
	// message from data collector must have 2 parts
	zmq_msg_t msg;
	int ret = zmq_msg_init(&msg);

	// first part - collector type/id
	ret = zmq_msg_recv(&msg, mon_sock, 0);
	if (!zmq_msg_more(&msg))
		// error - must have the second part
		return;

	size_t fp_size = zmq_msg_size(&msg);
	// shouldnt be empty
	uint8_t *fp_data = (uint8_t*) zmq_msg_data(&msg);




	zmq_msg_close(&msg);
	
	// second part - data
	ret = zmq_msg_init(&msg);
	ret = zmq_msg_recv(&msg, mon_sock, 0);
	size_t sp_size = zmq_msg_size(&msg);
	// TODO shouldn't be empty
	uint8_t *sp_data = (uint8_t*) zmq_msg_data(&msg);
	if (zmq_msg_more(&msg))
		// error - must NOT have another part
		return;
	zmq_msg_close(&msg);

}

void recv_mon_sock() {
	// message from monitor must have 2 parts

	zmq_msg_t msg;
	int ret = zmq_msg_init(&msg);

	// first part
	ret = zmq_msg_recv(&msg, mon_sock, 0);

	if (!zmq_msg_more(&msg))
		// error - must have the second part
		return;

	// must have 6 bytes
	// first 2 bytes - event type
	// another 4 bytes - event value
	size_t size = zmq_msg_size(&msg);
	// TODO check
	uint8_t *data = (uint8_t*) zmq_msg_data(&msg);
	uint16_t event = *(uint16_t *)(data);
	uint32_t value = *(uint32_t *)(data + 2);


	zmq_msg_close(&msg);
	
	// second part
	// contains socket address
	// but we already knew it
	ret = zmq_msg_init(&msg);

	// TODO maybe check the address to be sure ??

	ret = zmq_msg_recv(&msg, mon_sock, 0);
	if (zmq_msg_more(&msg))
		// error - must NOT have another part
		return;
	zmq_msg_close(&msg);

	// message from monitor is valid at this point
	// process data

}

void recv_data_sock_cb(evutil_socket_t fd, short events, void *arg) {
	int events;
	size_t events_len = sizeof(events);
	int ret = zmq_getsockopt(data_sock, ZMQ_EVENTS, &events, &events_len);
	if (events & ZMQ_POLLIN)
		recv_data_sock();
}

void recv_mon_sock_cb(evutil_socket_t fd, short events, void *arg) {
	int events;
	size_t events_len = sizeof(events);
	int ret = zmq_getsockopt(mon_sock, ZMQ_EVENTS, &events, &events_len);
	if (events & ZMQ_POLLIN)
		recv_mon_sock();
}

int zmq_setup(const char *sock_addr, const struct event_base *ev_base) {
	ctx = zmq_ctx_new();

	data_sock = zmq_socket(ctx, ZMQ_PULL);
	// maybe set ZMQ_RCVTIMEO
	
	int ret = zmq_socket_monitor(data_sock, MONITOR, ZMQ_EVENT_ALL);
	mon_sock = zmq_socket(ctx, ZMQ_PAIR);
	// maybe set ZMQ_RCVTIMEO

	int fd;
	size_t fd_size = sizeof(fd);

	ret = zmq_getsockopt(data_sock, ZMQ_FD, &fd, &fd_size);

	recv_data_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST, recv_data_sock_cb, NULL);
	ret = event_add(recv_data_sock_ev, NULL);

	ret = zmq_getsockopt(mon_sock, ZMQ_FD, &fd, &fd_size);

	recv_mon_sock_ev = event_new(ev_base, fd, EV_READ | EV_PERSIST, recv_mon_sock_cb, NULL);
	ret = event_add(recv_mon_sock_ev, NULL);

    ret = zmq_bind(data_sock, sock_addr);
	ret = zmq_connect(mon_sock, MONITOR);

	return 0;
}

void zmq_free() {
	event_free(recv_data_sock_ev);
	event_free(recv_mon_sock_ev);

	zmq_close(data_sock);
	zmq_close(mon_sock);
	zmq_ctx_term(ctx);
}
