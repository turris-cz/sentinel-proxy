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

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "proxy_mqtt.h"
#include "common.h"

#define MQTT_CLIENT_ID_MAX_LEN 64
// https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS_LEVEL 0
#define MQTT_KEEPALIVE_INTERVAL 60  // seconds
#define MQTT_KEEPALIVE_TIMEOUT (MQTT_KEEPALIVE_INTERVAL / 2) //seconds
#define MQTT_DISCONNECT_TIMEOUT 5000 // miliseconds

// #define SENTINEL_HEARTBEAT_TIMEOUT (60 * 5) // seconds
#define SENTINEL_HEARTBEAT_TIMEOUT 30 // seconds
#define HEARTBEAT_EV "heartbeat"
#define DISCONNECT_EV "disconnect"
#define LAST_WILL_DISCONNECT_EV "last_will_disconnect"


#define PACK_STR(packer, str) do { \
	msgpack_pack_str(packer, strlen(str)); \
	msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);

static void compose_sentinel_mesg(msgpack_sbuffer *sbuff, msgpack_packer *pk,
		const struct sentinel_status_mesg *mesg) {
	TRACE_FUNC;
	// msgpack_sbuffer_init(sbuff);
	// msgpack_packer pk;
	msgpack_packer_init(pk, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(pk, 2);
	PACK_STR(pk, "action");
	PACK_STR(pk, mesg->action);
	PACK_STR(pk, "ts");
	msgpack_pack_long_long(pk, mesg->ts);
}

static void send_heartbeat(struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	mqtt->status_mesg->action = HEARTBEAT_EV; 
	mqtt->status_mesg->ts = time(NULL);
	compose_sentinel_mesg(mqtt->sbuff, mqtt->packer, mqtt->status_mesg);
	int ret = MQTTClient_publish(mqtt->client, mqtt->status_topic,
		mqtt->sbuff->size, mqtt->sbuff->data, MQTT_QOS_LEVEL, 0, NULL);
	LOG_ERR(ret != MQTTCLIENT_SUCCESS, "Cannot send heartbeat");
	msgpack_sbuffer_clear(mqtt->sbuff);
}

static void send_disconnect(struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	mqtt->status_mesg->action = DISCONNECT_EV;
	mqtt->status_mesg->ts = time(NULL);
	compose_sentinel_mesg(mqtt->sbuff, mqtt->packer, mqtt->status_mesg);
	int ret = MQTTClient_publish(mqtt->client, mqtt->status_topic,
		mqtt->sbuff->size, mqtt->sbuff->data, MQTT_QOS_LEVEL, 0, NULL);
	LOG_ERR(ret != MQTTCLIENT_SUCCESS, "Cannot send disconnect");
	msgpack_sbuffer_clear(mqtt->sbuff);
}

static void mqtt_connect(struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	int ret = MQTTClient_connect(mqtt->client, mqtt->conn_opts);
	if (ret == MQTTCLIENT_SUCCESS) {
		INFO("Connected to MQTT broker");
		send_heartbeat(mqtt);
		struct timeval tm = {SENTINEL_HEARTBEAT_TIMEOUT, 0};
		event_add(mqtt->sentinel_heartbeat_ev, &tm);
	} else {
		ERROR("Cannot connect to MQTT broker\nReconnect in %d s",
			MQTT_KEEPALIVE_TIMEOUT);
	}
}

static void mqtt_disconnect(struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	send_disconnect(mqtt);
	// leave some time to deliver in-flight messages
	int ret = MQTTClient_disconnect(mqtt->client, MQTT_DISCONNECT_TIMEOUT);
	if (ret == MQTTCLIENT_SUCCESS) {
		INFO("Disconnected from MQTT broker");
		event_del(mqtt->sentinel_heartbeat_ev);
	}
	else
		ERROR("Cannot disconnect from MQTT broker");
}

static void sentinel_heartbeat_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	send_heartbeat((struct proxy_mqtt *)arg);
}

static void mqtt_client_yeld_cb(evutil_socket_t fd, short events, void *arg) {
	TRACE_FUNC;
	struct proxy_mqtt *mqtt = (struct proxy_mqtt *)arg;
	if (MQTTClient_isConnected(mqtt->client))
		MQTTClient_yield();
	else
		mqtt_connect(mqtt);
} 

static void compose_last_will(msgpack_sbuffer *sbuff, msgpack_packer *pk) {
	TRACE_FUNC;
	// msgpack_sbuffer_init(sbuff);
	// msgpack_packer pk;
	msgpack_packer_init(pk, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(pk, 1);
	PACK_STR(pk, "action");
	PACK_STR(pk, LAST_WILL_DISCONNECT_EV);
	// No time stamp here - this message is sent by MQTT broker
}

static void mqtt_setup(const struct proxy_conf *conf, struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	// Enables verification of the server certificate.
	ssl_opts.enableServerCertAuth = 1;
	// Enables post-connect checks, including that a server certificate
	// matches the given host name.
	ssl_opts.verify = 1;
	ssl_opts.trustStore = conf->ca_file;
	ssl_opts.keyStore = conf->client_cert_file;
	ssl_opts.privateKey = conf->client_key_file;

	compose_last_will(mqtt->last_will_payload, mqtt->packer);
	MQTTClient_willOptions lw_opts = MQTTClient_willOptions_initializer;
	lw_opts.topicName = mqtt->status_topic;
	lw_opts.message = NULL; // must be NULL to allow binary payload
	lw_opts.payload.len = mqtt->last_will_payload->size;
	lw_opts.payload.data = mqtt->last_will_payload->data;
	
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	// The time interval in seconds after which unacknowledged publish
	// requests are retried during a TCP session.
	conn_opts.retryInterval = 5;
	// Defines the maximum time in seconds that should pass without
	// communication between the client and the server.
	conn_opts.keepAliveInterval = MQTT_KEEPALIVE_INTERVAL;
	// Controls how many messages can be in-flight simultaneously.
	// Setting this flag to false allows up to 10 messages to be in-flight.
	conn_opts.reliable = 0;
	// When cleansession is true, the session state information is discarded at
	// connect and disconnect.
	conn_opts.cleansession = 1;

	memcpy(mqtt->conn_opts, &conn_opts, sizeof(*mqtt->conn_opts));
	memcpy(mqtt->ssl_opts, &ssl_opts, sizeof(*mqtt->ssl_opts));
	memcpy(mqtt->will_opts, &lw_opts, sizeof(*mqtt->will_opts));
	mqtt->conn_opts->ssl = mqtt->ssl_opts;
	mqtt->conn_opts->will = mqtt->will_opts;
}


static int get_name_from_cert(const char *filename, char **name, int name_len) {
	TRACE_FUNC;
	FILE *fp = fopen(filename, "r");
	CHECK_ERR_LOG(!fp, "Cannot open certificate file: %s", filename);
	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	CHECK_ERR_LOG(!cert, "Cannot read X509 certificate");
	X509_NAME *subject_name = X509_get_subject_name(cert);
	CHECK_ERR_LOG(!subject_name, "Cannot get subject name from X509 certificate");
	int ret = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
		*name, name_len);
	CHECK_ERR_LOG(ret == -1, "Cannot get subject name text");
	// TODO maybe check common name format
	// TODO maybe do some aditional checks if it's sentinel CA? check issuer?
	X509_free(cert);
	return 0;
}

int proxy_mqtt_init(struct proxy_mqtt *mqtt, struct event_base *ev_base,
		const struct proxy_conf *conf) {
	TRACE_FUNC;
	mqtt->client_id = malloc(sizeof(*mqtt->client_id) * MQTT_CLIENT_ID_MAX_LEN);
	CHECK_ERR(get_name_from_cert(conf->client_cert_file, &mqtt->client_id,
		MQTT_CLIENT_ID_MAX_LEN));
	
	size_t tmp_len = 0;
	FILE *tmp = open_memstream(&mqtt->data_topic, &tmp_len);
	fprintf(tmp, "%s%s/%s/", TOPIC_PREFIX, mqtt->client_id, conf->device_token);
	fclose(tmp);
	// we need more space for topic suffix from received ZMQ message
	mqtt->data_topic = realloc(mqtt->data_topic,
		tmp_len + ZMQ_MAX_TOPIC_LEN);
	mqtt->data_topic_prefix_end = mqtt->data_topic + tmp_len;

	tmp = open_memstream(&mqtt->status_topic, &tmp_len);
	fprintf(tmp, "%s%s/%s/status", TOPIC_PREFIX, mqtt->client_id,
		conf->device_token);
	fclose(tmp);

	mqtt->packer = msgpack_packer_new(NULL, NULL);
	mqtt->last_will_payload = msgpack_sbuffer_new();
	msgpack_sbuffer_init(mqtt->last_will_payload);
	mqtt->sbuff = msgpack_sbuffer_new();
	msgpack_sbuffer_init(mqtt->sbuff);
	mqtt->status_mesg = malloc(sizeof(*mqtt->status_mesg));

	mqtt->conn_opts = malloc(sizeof(*mqtt->conn_opts));
	mqtt->ssl_opts = malloc(sizeof(*mqtt->ssl_opts));
	mqtt->will_opts = malloc(sizeof(*mqtt->will_opts));
	mqtt_setup(conf, mqtt);

	int ret = MQTTClient_create(&mqtt->client, conf->upstream_srv,
		mqtt->client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
	CHECK_ERR_LOG(ret != MQTTCLIENT_SUCCESS, "Cannot create MQTT client");

	mqtt->mqtt_client_yeld_ev = event_new(ev_base, -1, EV_PERSIST,
		mqtt_client_yeld_cb, mqtt);
	struct timeval tm = {MQTT_KEEPALIVE_TIMEOUT, 0};
	event_add(mqtt->mqtt_client_yeld_ev, &tm);

	mqtt->sentinel_heartbeat_ev = event_new(ev_base, -1, EV_PERSIST,
		sentinel_heartbeat_cb, mqtt);

	mqtt_connect(mqtt);

	return 0;
}

void proxy_mqtt_destroy(struct proxy_mqtt *mqtt) {
	TRACE_FUNC;
	if (MQTTClient_isConnected(mqtt->client))
		mqtt_disconnect(mqtt);
	event_free(mqtt->sentinel_heartbeat_ev);
	event_free(mqtt->mqtt_client_yeld_ev);
	MQTTClient_destroy(&mqtt->client);
	free(mqtt->will_opts);
	free(mqtt->ssl_opts);
	free(mqtt->conn_opts);
	free(mqtt->status_mesg);
	msgpack_sbuffer_free(mqtt->sbuff);
	msgpack_sbuffer_free(mqtt->last_will_payload);
	msgpack_packer_free(mqtt->packer);
	free(mqtt->status_topic);
	free(mqtt->data_topic);
	free(mqtt->client_id);
}

void proxy_mqtt_send_data(struct proxy_mqtt *mqtt, uint8_t *topic,
		size_t topic_len, uint8_t *data, size_t data_len) {
	TRACE_FUNC;
	// complete MQTT data topic
	strncpy(mqtt->data_topic_prefix_end, topic + TOPIC_PREFIX_LEN,
		topic_len - TOPIC_PREFIX_LEN);
	mqtt->data_topic_prefix_end[topic_len - TOPIC_PREFIX_LEN] = '\0';
	int ret = MQTTClient_publish(mqtt->client, mqtt->data_topic, data_len, data,
		MQTT_QOS_LEVEL, 0, NULL);
	LOG_ERR(ret != MQTTCLIENT_SUCCESS, "Cannot send data");
}
