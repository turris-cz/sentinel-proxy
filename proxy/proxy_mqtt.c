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

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>

#include "proxy_mqtt.h"
#include "common.h"
#include "log.h"

#define MQTT_CLIENT_ID_MAX_LEN 64
// https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS_LEVEL 0
#define MQTT_KEEPALIVE_INTERVAL 60  // seconds
#define MQTT_KEEPALIVE_TIMEOUT_S (MQTT_KEEPALIVE_INTERVAL / 2) //seconds
#define MQTT_KEEPALIVE_TIMEOUT_MS (MQTT_KEEPALIVE_TIMEOUT_S * 1000) // miliseconds
#define MQTT_DISCONNECT_TIMEOUT (5 * 1000) // miliseconds
#define SENTINEL_HEARTBEAT_TIMEOUT (5 * 60 * 1000) // miliseconds

#define PACK_STR(packer, str) do { \
		msgpack_pack_str(packer, strlen(str)); \
		msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);

void compose_sentinel_mesg(msgpack_sbuffer *sbuff, msgpack_packer *pk,
		const struct sentinel_status_mesg *mesg) {
	TRACE_FUNC;
	msgpack_packer_init(pk, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(pk, 2);
	PACK_STR(pk, "action");
	PACK_STR(pk, mesg->action);
	PACK_STR(pk, "ts");
	msgpack_pack_long_long(pk, mesg->ts);
}

void mqtt_connect(struct mqtt *mqtt);

int mqtt_client_yeld_cb(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	TRACE_FUNC;
	struct mqtt *mqtt = (struct mqtt *)arg;
	if (MQTTClient_isConnected(mqtt->client))
		MQTTClient_yield();
	else
		mqtt_connect(mqtt);
	return 0;
}

void send_heartbeat(struct mqtt *mqtt) {
	TRACE_FUNC;
	mqtt->status_mesg->action = HEARTBEAT_EV;
	mqtt->status_mesg->ts = time(NULL);
	compose_sentinel_mesg(mqtt->sbuff, mqtt->packer, mqtt->status_mesg);
	if (MQTTClient_publish(mqtt->client, mqtt->status_topic, mqtt->sbuff->size,
			mqtt->sbuff->data, MQTT_QOS_LEVEL, 0, NULL) != MQTTCLIENT_SUCCESS)
		error("Cannot send heartbeat");
	msgpack_sbuffer_clear(mqtt->sbuff);
}

int sentinel_heartbeat_cb(zloop_t *loop, int timer_id, void *arg) {
	// It must return 0. If -1 is returned event loop is terminated.
	TRACE_FUNC;
	send_heartbeat((struct mqtt *)arg);
	return 0;
}

void mqtt_connect(struct mqtt *mqtt) {
	TRACE_FUNC;
	if (MQTTClient_connect(mqtt->client, mqtt->conn_opts) == MQTTCLIENT_SUCCESS) {
		info("Connected to MQTT broker");
		send_heartbeat(mqtt);
		// The first time the MQTT client is really connected we start timer
		// for sending Sentinel heartbeats
		if (mqtt->sentinel_heartbeat_timer_id == -1) {
			mqtt->sentinel_heartbeat_timer_id = zloop_timer(mqtt->zloop,
				SENTINEL_HEARTBEAT_TIMEOUT, 0, sentinel_heartbeat_cb, mqtt);
			assert(mqtt->sentinel_heartbeat_timer_id != -1);
		}
	} else {
		error("Cannot connect to MQTT broker\nReconnect in %d s",
			MQTT_KEEPALIVE_TIMEOUT_S);
	}
	// The first time mqtt_connect() is called we start timer for periodical
	// connection checks and reconnects if NOT connected
	// or periodical calls of MQTTClient_yield()
	// which the application must call regularly
	if (mqtt->mqtt_keep_alive_timer_id == -1) {
		mqtt->mqtt_keep_alive_timer_id = zloop_timer(mqtt->zloop,
			MQTT_KEEPALIVE_TIMEOUT_MS, 0, mqtt_client_yeld_cb, mqtt);
		assert(mqtt->mqtt_keep_alive_timer_id != -1);
	}
}

void send_disconnect(struct mqtt *mqtt) {
	TRACE_FUNC;
	mqtt->status_mesg->action = DISCONNECT_EV;
	mqtt->status_mesg->ts = time(NULL);
	compose_sentinel_mesg(mqtt->sbuff, mqtt->packer, mqtt->status_mesg);
	if (MQTTClient_publish(mqtt->client, mqtt->status_topic, mqtt->sbuff->size,
			mqtt->sbuff->data, MQTT_QOS_LEVEL, 0, NULL) != MQTTCLIENT_SUCCESS)
		error("Cannot send disconnect");
	msgpack_sbuffer_clear(mqtt->sbuff);
}

void mqtt_disconnect(struct mqtt *mqtt) {
	TRACE_FUNC;
	zloop_timer_end(mqtt->zloop, mqtt->sentinel_heartbeat_timer_id);
	zloop_timer_end(mqtt->zloop, mqtt->mqtt_keep_alive_timer_id);
	send_disconnect(mqtt);
	// leave some time to deliver in-flight messages
	if (MQTTClient_disconnect(mqtt->client, MQTT_DISCONNECT_TIMEOUT) 
			== MQTTCLIENT_SUCCESS) {
		info("Disconnected from MQTT broker");
	}
	else
		error("Cannot disconnect from MQTT broker");
}

void compose_last_will(msgpack_sbuffer *sbuff, msgpack_packer *pk) {
	TRACE_FUNC;
	msgpack_packer_init(pk, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(pk, 1);
	PACK_STR(pk, "action");
	PACK_STR(pk, LAST_WILL_DISCONNECT_EV);
	// No time stamp here - this message is sent by MQTT broker
	// Time stamp is added later by Sentinel Smash
}

void client_setup(const struct proxy_conf *conf, struct mqtt *mqtt) {
	TRACE_FUNC;
	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	// For client verification at server side
	// File in PEM format containing public certificate chain of the client.
	ssl_opts.keyStore = conf->mqtt_client_cert_file;
	// File in PEM format containing client's private key.
	ssl_opts.privateKey = conf->mqtt_client_key_file;
	if (conf->disable_serv_check) {
		// Disables verification of the server certificate.
		ssl_opts.enableServerCertAuth = false;
		// Disables post-connect checks, including that a server certificate
		// matches the given host name.
		ssl_opts.verify = false;
	} else {
		ssl_opts.enableServerCertAuth = true;
		ssl_opts.verify = true;
		// The file in PEM format containing the public digital certificates
		// trusted by the client.
		ssl_opts.trustStore = conf->ca_cert_file;
	}

	MQTTClient_willOptions lw_opts = MQTTClient_willOptions_initializer;
	lw_opts.topicName = mqtt->status_topic;
	// must be NULL to allow binary payload
	lw_opts.message = NULL;
	compose_last_will(mqtt->last_will_payload, mqtt->packer);
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

	mqtt->conn_opts = malloc(sizeof(*mqtt->conn_opts));
	mqtt->ssl_opts = malloc(sizeof(*mqtt->ssl_opts));
	mqtt->will_opts = malloc(sizeof(*mqtt->will_opts));
	memcpy(mqtt->conn_opts, &conn_opts, sizeof(*mqtt->conn_opts));
	memcpy(mqtt->ssl_opts, &ssl_opts, sizeof(*mqtt->ssl_opts));
	memcpy(mqtt->will_opts, &lw_opts, sizeof(*mqtt->will_opts));
	mqtt->conn_opts->ssl = mqtt->ssl_opts;
	mqtt->conn_opts->will = mqtt->will_opts;
}

void build_data_topic(char **topic_buf, char **topic_prefix_end,
		char *client_id, char *device_token) {
	TRACE_FUNC;
	size_t tmp_len = 0;
	FILE *tmp = open_memstream(topic_buf, &tmp_len);
	fprintf(tmp, "%s%s/%s/", TOPIC_PREFIX, client_id, device_token);
	fclose(tmp);
	// we need more space for topic suffix from received ZMQ message
	*topic_buf = realloc(*topic_buf, tmp_len + ZMQ_MAX_TOPIC_LEN);
	*topic_prefix_end = *topic_buf + tmp_len;
}

void update_data_topic(char *topic_prefix_end, char *topic, size_t topic_len) {
	TRACE_FUNC;
	strncpy(topic_prefix_end, topic + TOPIC_PREFIX_LEN,
		topic_len - TOPIC_PREFIX_LEN);
	topic_prefix_end[topic_len - TOPIC_PREFIX_LEN] = '\0';
}

void build_status_topic(char **topic_buf, char *client_id, char *device_token) {
	TRACE_FUNC;
	size_t tmp_len = 0;
	FILE *tmp = open_memstream(topic_buf, &tmp_len);
	fprintf(tmp, "%s%s/%s/status", TOPIC_PREFIX, client_id, device_token);
	fclose(tmp);
}

void build_server_uri(char **uri_buf, char *server, int port) {
	TRACE_FUNC;
	size_t tmp_len = 0;
	FILE *tmp = open_memstream(uri_buf, &tmp_len);
	fprintf(tmp, "ssl://%s:%d", server, port);
	fclose(tmp);
}

void get_client_id(const char *filename, char **id) {
	TRACE_FUNC;
	FILE *fp = fopen(filename, "r");
	assert(fp);
	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	assert(cert);
	X509_NAME *subject_name = X509_get_subject_name(cert);
	assert(subject_name);
	*id = malloc(sizeof(**id) * (MQTT_CLIENT_ID_MAX_LEN + 1));
	assert(X509_NAME_get_text_by_NID(subject_name, NID_commonName, *id,
		MQTT_CLIENT_ID_MAX_LEN) != -1);
	X509_free(cert);
}

void init_mqtt(struct mqtt *mqtt, zloop_t *zloop, const struct proxy_conf *conf) {
	TRACE_FUNC;
	assert(mqtt);
	assert(zloop);
	assert(conf);
	get_client_id(conf->mqtt_client_cert_file, &mqtt->client_id);
	build_data_topic(&mqtt->data_topic, &mqtt->data_topic_prefix_end,
		mqtt->client_id, conf->device_token);
	build_status_topic(&mqtt->status_topic, mqtt->client_id, conf->device_token);
	build_server_uri(&mqtt->server_uri, conf->mqtt_broker, conf->mqtt_port);

	mqtt->packer = msgpack_packer_new(NULL, NULL);
	assert(mqtt->packer);
	mqtt->sbuff = msgpack_sbuffer_new();
	assert(mqtt->sbuff);
	msgpack_sbuffer_init(mqtt->sbuff);
	mqtt->last_will_payload = msgpack_sbuffer_new();
	assert(mqtt->last_will_payload);
	msgpack_sbuffer_init(mqtt->last_will_payload);
	mqtt->status_mesg = malloc(sizeof(*mqtt->status_mesg));

	client_setup(conf, mqtt);
	assert(MQTTClient_create(&mqtt->client,
		mqtt->server_uri, mqtt->client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL)
		== MQTTCLIENT_SUCCESS);
	mqtt->zloop = zloop;
	mqtt->sentinel_heartbeat_timer_id = -1;
	mqtt->mqtt_keep_alive_timer_id = -1;
	mqtt_connect(mqtt);
}

void destroy_mqtt(struct mqtt *mqtt) {
	TRACE_FUNC;
	if (mqtt) {
		if (MQTTClient_isConnected(mqtt->client))
			mqtt_disconnect(mqtt);
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
		free(mqtt->server_uri);
	}
}

void mqtt_send_data(struct mqtt *mqtt, char *topic, size_t topic_len,
		char *data, size_t data_len) {
	TRACE_FUNC;
	// complete MQTT data topic
	update_data_topic(mqtt->data_topic_prefix_end, topic, topic_len);
	if (MQTTClient_publish(mqtt->client, mqtt->data_topic, (int)data_len, data,
			MQTT_QOS_LEVEL, 0, NULL) != MQTTCLIENT_SUCCESS)
		error("Cannot send data");
}
