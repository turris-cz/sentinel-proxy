/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <czmq.h>
#include <MQTTClient.h>
#include <msgpack.h>

#include "config.h"
#include "proxy_conf.h"

#define CERT_NAME_MAX_LEN 64
#define TOPIC_PREFIX "sentinel/collect/"
#define HEARTBEAT_TIMEOUT (60 * 5) // seconds
#define ZMQ_MAX_TOPIC_LEN 256
#define ZMQ_MAX_MSG_SIZE (1024 * 1024 * 2)
#define ZMQ_MAX_WAITING_MESSAGES 50
// QoS levels - see here:
// https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS 0
#define MQTT_KEEPALIVE_INTERVAL 60  // seconds
#define MQTT_KEEPALIVE_TIMEOUT (MQTT_KEEPALIVE_INTERVAL / 2) //seconds

#define CHECK_ERR(CMD, ...)               \
	do {                                  \
		if (CMD) {                        \
			fprintf(stderr, __VA_ARGS__); \
		}                                 \
	} while (0)

#define CHECK_ERR_FATAL(CMD, ...)         \
	do {                                  \
		if (CMD) {                        \
			fprintf(stderr, __VA_ARGS__); \
			exit(EXIT_FAILURE);           \
		}                                 \
	} while (0)

// WARNING: be aware of goto !!
#define CHECK_ERR_GT(CMD, LABEL, ...)        \
	do {                                  \
		if (CMD) {                        \
			fprintf(stderr, __VA_ARGS__); \
			goto LABEL;                   \
		}                                 \
	} while (0)

#define PACK_STR(packer, str) do { \
	msgpack_pack_str(packer, strlen(str)); \
	msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);

struct reader_arg {
	MQTTClient *mqtt_client;
	char *mqtt_topic_buff;
	char *mqtt_topic_prefix_end;
};

struct keep_alive_arg {
	MQTTClient *client;
	MQTTClient_connectOptions *conn_opts;
	char *status_topic;
};

struct status_mesg {
	char *action;
	long long int ts;
};

static inline void compose_status_mesg(msgpack_sbuffer *sbuff, struct status_mesg *mesg) {
	msgpack_sbuffer_init(sbuff);
	msgpack_packer pk;
	msgpack_packer_init(&pk, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(&pk, 2);
	PACK_STR(&pk, "action");
	PACK_STR(&pk, mesg->action);
	PACK_STR(&pk, "ts");
	msgpack_pack_long_long(&pk, mesg->ts);
}

static inline void mqtt_disconnect(MQTTClient *client, const char *status_topic) {
	msgpack_sbuffer buff;
	struct status_mesg mesg = { .action = "disconnect", .ts = time(NULL) };
	compose_status_mesg(&buff, &mesg);
	MQTTClient_publish(*client, status_topic, buff.size, buff.data, MQTT_QOS, 0,
		NULL);
	msgpack_sbuffer_destroy(&buff);
	// leave some time to deliver in-flight messages
	MQTTClient_disconnect(*client, 5000); // 5s
}

static inline void send_heartbeat(struct keep_alive_arg *arg) {
	msgpack_sbuffer buff;
	struct status_mesg mesg = { .action = "heartbeat", .ts = time(NULL) };
	compose_status_mesg(&buff, &mesg);
	MQTTClient_publish(*arg->client, arg->status_topic, buff.size, buff.data,
		MQTT_QOS, 0, NULL);
	msgpack_sbuffer_destroy(&buff);
}

static void mqtt_connect(struct keep_alive_arg *arg) {
	int ret = MQTTClient_connect(*arg->client, arg->conn_opts);
	CHECK_ERR(ret != MQTTCLIENT_SUCCESS,
		"Could't connect to server\nReconnect in %d s\n", MQTT_KEEPALIVE_TIMEOUT);
	send_heartbeat(arg);
};

static int heartbeat_handler(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	send_heartbeat((struct keep_alive_arg *) arg);
	return 0;
};

static int mqtt_keep_alive_timer_handler(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	struct keep_alive_arg *keep_al_arg = (struct keep_alive_arg *)arg;
	if (MQTTClient_isConnected(*keep_al_arg->client))
		MQTTClient_yield();
	else
		mqtt_connect(keep_al_arg);
	return 0;
}

static int zmq_reader_handler(zloop_t *loop, zsock_t *reader, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	struct reader_arg *read_arg = (struct reader_arg *)arg;
	zmsg_t *msg = zmsg_recv(reader);
	CHECK_ERR_GT(!msg, err, "receiving ZMQ message was interrupted\n");
	CHECK_ERR_GT(zmsg_size(msg) != 2, err ,
		"ignoring mallformed message (%ld parts)\n", zmsg_size(msg));
	// extract zmq topic
	zframe_t *topic_frame = zmsg_first(msg);

	char *meta = zframe_meta(topic_frame, "Peer-Address");
	printf("%s\n", meta);
	// char *meta1 = zframe_meta(topic_frame, "User-Id");
	// printf("%s\n", meta1);
	char *meta2 = zframe_meta(topic_frame, "Socket-Type");
	printf("%s\n", meta2);
	// char *meta3 = zframe_meta(topic_frame, "Routing-Id");
	// printf("%s\n", meta3);

	size_t msg_topic_len = zframe_size(topic_frame);
	unsigned char *msg_topic = zframe_data(topic_frame);
	// check zmq topic
	CHECK_ERR_GT(msg_topic_len < strlen(TOPIC_PREFIX)
		|| msg_topic_len > ZMQ_MAX_TOPIC_LEN
		|| strncmp(TOPIC_PREFIX, msg_topic, strlen(TOPIC_PREFIX)), err,
		"wrong zmq message topic\n");
	// compose mqtt topic
	strncpy(read_arg->mqtt_topic_prefix_end, msg_topic + strlen(TOPIC_PREFIX),
		msg_topic_len - strlen(TOPIC_PREFIX));
	read_arg->mqtt_topic_prefix_end[msg_topic_len - strlen(TOPIC_PREFIX)] = 0;
	// send
	zframe_t *payload_frame = zmsg_last(msg);
	int ret = MQTTClient_publish(*read_arg->mqtt_client, read_arg->mqtt_topic_buff,
		(int)zframe_size(payload_frame), zframe_data(payload_frame), MQTT_QOS, 0, NULL);
	if (ret != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "message was not published, err code:%d\n", ret);
		// TODO buffer message
		// try to send again later
	}
err:
	zmsg_destroy(&msg);
	return 0;
}

static int zmq_monitor_reader_handler(zloop_t *loop, zsock_t *reader, void *arg) {
	// printf("aaaaa\n");
	zmsg_t *msg = zmsg_recv(reader);

	size_t size = zmsg_size(msg);
	// printf("size: %d\n", size);

	// it has 3 parts
	// https://github.com/zeromq/cppzmq/commit/1f05e0d111197c64be32ad5aecd59f4d1b05a819
	// - name - TYP eventu - ACCEPTED, HANDSHAKE_SUCCEDED, DISCONNECTED - tyhle vraci minipoty
	// typ sledovanych udalosti se da nastavit 
	// - value - error code  OR fd OR reconnect interval
	// - address - adresa socketu

	for(size_t i = 0; i < size ; i++) {
		printf("-----------------------------\n");
		zframe_t *f = zmsg_next(msg);
		size_t f_data_len = zframe_size(f);
		unsigned char *f_data = zframe_data(f);

		for (int i = 0; i < f_data_len; i++) {
			printf("%c", *f_data);
			f_data++;
		}
		printf("\n");
	}

	zmsg_destroy(&msg);
	return 0;
}


// It alocates memory and returns pointer to it.
// Caller is responsible for its freeing.
static char *get_name_from_cert(const char *filename) {
	// get common name from subject of X509 certificate
	// this function must return valid name or exit the program
	X509 *cert = NULL;
	FILE *fp = fopen(filename, "r");
	CHECK_ERR_FATAL(!fp, "cannot open certificate file\n");
	PEM_read_X509(fp, &cert, NULL, NULL);
	fclose(fp);
	CHECK_ERR_FATAL(!cert, "cannot read X509 certificate\n");
	// TODO: maybe do some aditional checks if it's sentinel CA? check issuer?
	char *ret = malloc(CERT_NAME_MAX_LEN);
	ret[0] = 0;
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
		ret, CERT_NAME_MAX_LEN);
	X509_free(cert);
	CHECK_ERR_FATAL(!strlen(ret), "couldn't get name from cert\n");
	return ret;
}

static inline void prep_last_will(msgpack_sbuffer *payload) {
	msgpack_sbuffer_init(payload);
	msgpack_packer pk;
	msgpack_packer_init(&pk, payload, msgpack_sbuffer_write);
	msgpack_pack_map(&pk, 1);
	PACK_STR(&pk, "action");
	PACK_STR(&pk, "last_will_disconnect");
	// No time stamp here
	// This message is sent by MQTT broker
}

static inline void mqtt_setup(MQTTClient_connectOptions *conn_opts,
		const struct proxy_conf *conf, const char *status_topic,
		msgpack_sbuffer *lwt_payload) {
	conn_opts->retryInterval = 5;
	conn_opts->keepAliveInterval = MQTT_KEEPALIVE_INTERVAL;
	conn_opts->reliable = 0;
	conn_opts->cleansession = 1;
	conn_opts->ssl->enableServerCertAuth = 1;
	conn_opts->ssl->trustStore = conf->ca_file;
	conn_opts->ssl->keyStore = conf->client_cert_file;
	conn_opts->ssl->privateKey = conf->client_key_file;
	conn_opts->ssl->verify = 1;
	conn_opts->will->topicName = status_topic;
	conn_opts->will->message = NULL; // must be NULL to allow binary payload
	prep_last_will(lwt_payload);
	conn_opts->will->payload.len = lwt_payload->size;
	conn_opts->will->payload.data = lwt_payload->data;
}

static void run_proxy(const struct proxy_conf *conf) {
	char *client_id = get_name_from_cert(conf->client_cert_file);
	// TODO: client_id length should be checked (once its format is fixed)
	fprintf(stderr, "got name from certificate: %s\n", client_id);

	// mqtt setup
	char *data_topic = NULL;
	size_t data_topic_prefix_len = 0;
	FILE *tmp = open_memstream(&data_topic, &data_topic_prefix_len);
	fprintf(tmp, "%s%s/%s/", TOPIC_PREFIX, client_id, conf->device_token);
	fclose(tmp);
	// we need more space for topic suffix from received ZMQ message
	data_topic = realloc(data_topic, data_topic_prefix_len + ZMQ_MAX_TOPIC_LEN);

	char *status_topic = NULL;
	size_t status_topic_len = 0;
	tmp = open_memstream(&status_topic, &status_topic_len);
	fprintf(tmp, "%s%s/%s/status", TOPIC_PREFIX, client_id, conf->device_token);
	fclose(tmp);

	MQTTClient client;
	int ret = MQTTClient_create(&client, conf->upstream_srv, client_id,
		MQTTCLIENT_PERSISTENCE_NONE, NULL);
	CHECK_ERR_FATAL(ret != MQTTCLIENT_SUCCESS, "Couldn't create mqtt client\n");
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	MQTTClient_willOptions lw_opts = MQTTClient_willOptions_initializer;
	conn_opts.ssl = &ssl_opts;
	conn_opts.will = &lw_opts;
	msgpack_sbuffer last_will_payload;
	mqtt_setup(&conn_opts, conf, status_topic, &last_will_payload);

	// zmq setup
	zsock_t *receiver = zsock_new(ZMQ_PULL);
	CHECK_ERR_FATAL(!receiver, "Couldn't create zmq socket\n");
	zsock_set_maxmsgsize(receiver, ZMQ_MAX_MSG_SIZE);
	zsock_set_rcvhwm(receiver, ZMQ_MAX_WAITING_MESSAGES);
	ret = zsock_bind(receiver, "%s", conf->local_socket);
	CHECK_ERR_FATAL(ret == -1, "Couldn't bind to local ZMQ socket\n");

	//zmq monitor
	zactor_t *recv_monitor = zactor_new(zmonitor, receiver);
	// prints logs to stdout/stderr
	zstr_sendx(recv_monitor, "VERBOSE", NULL);

	zstr_sendx(recv_monitor, "LISTEN", "ALL", NULL);
	zstr_sendx(recv_monitor, "START", NULL);
	// zstr_sendx(recv_monitor, "VERBOSE", "LISTEN", "ALL", "START", NULL);
	zsock_wait(recv_monitor);

	zloop_t *loop = zloop_new();
	CHECK_ERR_FATAL(!loop, "couldn't create zloop\n");
	struct reader_arg read_arg = {
		.mqtt_client = &client,
		.mqtt_topic_buff = data_topic,
		.mqtt_topic_prefix_end = data_topic + data_topic_prefix_len
	};
	ret = zloop_reader(loop, receiver, zmq_reader_handler, &read_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop reader\n");


	ret = zloop_reader(loop, (zsock_t*)recv_monitor, zmq_monitor_reader_handler, NULL);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop monitor reader\n");



	struct keep_alive_arg keep_al_arg = {
		.client = &client,
		.conn_opts = &conn_opts,
		.status_topic = status_topic
	};
	ret = zloop_timer(loop, MQTT_KEEPALIVE_TIMEOUT * 1000, 0,
		mqtt_keep_alive_timer_handler, &keep_al_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop keep alive handler\n");

	ret = zloop_timer(loop, HEARTBEAT_TIMEOUT * 1000, 0, heartbeat_handler,
		&keep_al_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop heartbeat handler\n");

	// start
	fprintf(stderr, "connecting to %s, listening on %s\n", conf->upstream_srv,
		conf->local_socket);
	mqtt_connect(&keep_al_arg);
	zloop_start(loop);
	// teardown
	zloop_destroy(&loop);
	zsock_destroy(&receiver);

	zactor_destroy(&recv_monitor);

	mqtt_disconnect(&client, status_topic);
	MQTTClient_destroy(&client);
	free(data_topic);
	free(status_topic);
	free(client_id);
	msgpack_sbuffer_destroy(&last_will_payload);
}

int main(int argc, char *argv[]) {
	struct proxy_conf proxy_conf = {
		.upstream_srv = DEFAULT_SERVER,
		.local_socket = DEFAULT_LOCAL_SOCKET,
		.ca_file = DEFAULT_CA_FILE,
		.client_cert_file = DEFAULT_CERT_FILE,
		.client_key_file = DEFAULT_KEY_FILE,
		.device_token[0] = '\0',
		.config_file = DEFAULT_CONFIG_FILE,
		.custom_conf_file = false
	};
	load_conf(argc, argv, &proxy_conf);
	run_proxy(&proxy_conf);
	return 0;
}
