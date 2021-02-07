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
#include <zlib.h>
#include <czmq.h>
#include <MQTTClient.h>

#include "config.h"
#include "proxy_conf.h"

#define CERT_NAME_MAX_LEN 64
#define DATA_TOPIC_PREFIX "sentinel/collect/"
#define STATUS_TOPIC_PREFIX "sentinel/status/"
#define HEARTBEAT_PAYLOAD "heartbeat"
#define DISCONN_PAYLOAD "disconnect"
#define HEARTBEAT_TIMEOUT (60 * 5) // seconds
#define ZMQ_MAX_TOPIC_LEN 256
#define ZMQ_MAX_MSG_SIZE (1024 * 1024 * 2)
#define ZMQ_MAX_WAITING_MESSAGES 50
// QoS levels - see here:
// https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS 0
#define MQTT_KEEPALIVE_INTERVAL 60  // seconds
#define MQTT_KEEPALIVE_TIMEOUT (MQTT_KEEPALIVE_INTERVAL / 2) //seconds
// zlib compression levels: 1 is lowest (fastest), 9 is biggest (slowest)
#define COMPRESS_LEVEL 9
// buffer for compressed data
// zlib doc: "Upon entry, destLen is the total size of the destination
// buffer, which must be at least 0.1% larger than sourceLen plus 12 bytes."
#define COMPRESS_BUF_SIZE ((ZMQ_MAX_MSG_SIZE * 1001) / 1000 + 12 + 1)

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

struct heartbeat_arg {
	MQTTClient *client;
	char *topic_buff;
};

static inline void send_heartbeat(MQTTClient *client, const char *topic) {
	MQTTClient_publish(*client, topic, strlen(HEARTBEAT_PAYLOAD),
	HEARTBEAT_PAYLOAD, MQTT_QOS, 0, NULL);
}

static void mqtt_connect(MQTTClient *client, MQTTClient_connectOptions *conn_opts,
	const char *status_topic) {
	int ret = MQTTClient_connect(*client, conn_opts);
	CHECK_ERR(ret != MQTTCLIENT_SUCCESS,
		"Could't connect to server\nReconnect in %d s\n", MQTT_KEEPALIVE_TIMEOUT);
	send_heartbeat(client, status_topic);
};

static void mqtt_disconnect(MQTTClient *client, const char *status_topic) {
	MQTTClient_publish(*client, status_topic, strlen(DISCONN_PAYLOAD),
		DISCONN_PAYLOAD, MQTT_QOS, 0, NULL);
	// leave some time to deliver in-flight messages
	MQTTClient_disconnect(*client, 5000); // 5s
}

static int heartbeat_handler(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	struct heartbeat_arg *heart_arg = (struct heartbeat_arg *)arg;
	send_heartbeat(heart_arg->client, heart_arg->topic_buff);
	return 0;
};

static int mqtt_keep_alive_timer_handler(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	struct keep_alive_arg *keep_al_arg = (struct keep_alive_arg *)arg;
	if (MQTTClient_isConnected(*keep_al_arg->client))
		MQTTClient_yield();
	else
		mqtt_connect(keep_al_arg->client, keep_al_arg->conn_opts,
			keep_al_arg->status_topic);
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
	size_t msg_topic_len = zframe_size(topic_frame);
	unsigned char *msg_topic = zframe_data(topic_frame);
	// check zmq topic
	CHECK_ERR_GT(msg_topic_len < strlen(DATA_TOPIC_PREFIX)
		|| msg_topic_len > ZMQ_MAX_TOPIC_LEN
		|| strncmp(DATA_TOPIC_PREFIX, msg_topic, strlen(DATA_TOPIC_PREFIX)), err,
		"wrong zmq message topic\n");
	// compose mqtt topic
	strncpy(read_arg->mqtt_topic_prefix_end, msg_topic + strlen(DATA_TOPIC_PREFIX),
		msg_topic_len - strlen(DATA_TOPIC_PREFIX));
	read_arg->mqtt_topic_prefix_end[msg_topic_len - strlen(DATA_TOPIC_PREFIX)] = 0;
	// compress data
	zframe_t *payload_frame = zmsg_last(msg);
	static unsigned char compress_buf[COMPRESS_BUF_SIZE];
	unsigned long compress_len = COMPRESS_BUF_SIZE;
	int ret = compress2(compress_buf, &compress_len, zframe_data(payload_frame),
		zframe_size(payload_frame), COMPRESS_LEVEL);
	CHECK_ERR_GT(ret != Z_OK, err, "compress2 error - result: %d\n", ret);
	// send
	ret = MQTTClient_publish(*read_arg->mqtt_client, read_arg->mqtt_topic_buff,
		(int)compress_len, compress_buf, MQTT_QOS, 0, NULL);
	if (ret != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "message was not published, err code:%d\n", ret);
		// TODO buffer message
		// try to send again later
	}
err:
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

static void mqtt_setup(MQTTClient_connectOptions *conn_opts,
	const struct proxy_conf *conf, const char *status_topic) {
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
	conn_opts->will->message = DISCONN_PAYLOAD;
}

static void run_proxy(const struct proxy_conf *conf) {
	char *client_id = get_name_from_cert(conf->client_cert_file);
	// TODO: client_id length should be checked (once its format is fixed)
	fprintf(stderr, "got name from certificate: %s\n", client_id);

	// mqtt setup
	char *data_topic = NULL;
	size_t data_topic_prefix_len = 0;
	FILE *tmp = open_memstream(&data_topic, &data_topic_prefix_len);
	fprintf(tmp, "%s%s/%s/", DATA_TOPIC_PREFIX, client_id, conf->device_token);
	fclose(tmp);
	// we need more space for topic suffix from received ZMQ message
	data_topic = realloc(data_topic, data_topic_prefix_len + ZMQ_MAX_TOPIC_LEN);

	char *status_topic = NULL;
	size_t status_topic_len = 0;
	tmp = open_memstream(&status_topic, &status_topic_len);
	fprintf(tmp, "%s%s/%s", STATUS_TOPIC_PREFIX, client_id, conf->device_token);
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
	mqtt_setup(&conn_opts, conf, status_topic);

	// zmq setup
	zsock_t *receiver = zsock_new(ZMQ_PULL);
	CHECK_ERR_FATAL(!receiver, "Couldn't create zmq socket\n");
	zsock_set_maxmsgsize(receiver, ZMQ_MAX_MSG_SIZE);
	zsock_set_rcvhwm(receiver, ZMQ_MAX_WAITING_MESSAGES);
	ret = zsock_bind(receiver, "%s", conf->local_socket);
	CHECK_ERR_FATAL(ret == -1, "Couldn't bind to local ZMQ socket\n");

	zloop_t *loop = zloop_new();
	CHECK_ERR_FATAL(!loop, "couldn't create zloop\n");
	struct reader_arg read_arg = {
		.mqtt_client = &client,
		.mqtt_topic_buff = data_topic,
		.mqtt_topic_prefix_end = data_topic + data_topic_prefix_len
	};
	ret = zloop_reader(loop, receiver, zmq_reader_handler, &read_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop reader\n");

	struct keep_alive_arg keep_al_arg = {
		.client = &client,
		.conn_opts = &conn_opts,
		.status_topic = status_topic
	};
	ret = zloop_timer(loop, MQTT_KEEPALIVE_TIMEOUT * 1000, 0,
		mqtt_keep_alive_timer_handler, &keep_al_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop keep alive handler\n");

	struct heartbeat_arg heart_arg = {
		.client = &client,
		.topic_buff = status_topic
	};
	ret = zloop_timer(loop, HEARTBEAT_TIMEOUT * 1000, 0, heartbeat_handler,
		&heart_arg);
	CHECK_ERR_FATAL(ret == -1, "couldn't register zloop heartbeat handler\n");

	// start
	fprintf(stderr, "connecting to %s, listening on %s\n", conf->upstream_srv,
		conf->local_socket);
	mqtt_connect(&client, &conn_opts, status_topic);
	zloop_start(loop);
	// teardown
	zloop_destroy(&loop);
	zsock_destroy(&receiver);
	mqtt_disconnect(&client, status_topic);
	MQTTClient_destroy(&client);
	free(data_topic);
	free(status_topic);
	free(client_id);
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
