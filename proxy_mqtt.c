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

#include <event2/event.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


#include "proxy_conf.h"
#include "proxy_mqtt.h"


#define CERT_NAME_MAX_LEN 64

#define PACK_STR(packer, str) do { \
	msgpack_pack_str(packer, strlen(str)); \
	msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);


static void prep_last_will(msgpack_sbuffer *payload) {
	msgpack_sbuffer_init(payload);
	msgpack_packer pk;
	msgpack_packer_init(&pk, payload, msgpack_sbuffer_write);
	msgpack_pack_map(&pk, 1);
	PACK_STR(&pk, "action");
	PACK_STR(&pk, "last_will_disconnect");
	// No time stamp here
	// This message is sent by MQTT broker
}


static void mqtt_setup(MQTTClient_connectOptions *conn_opts,
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



// It alocates memory and returns pointer to it.
// Caller is responsible for its freeing.
static char *get_name_from_cert(const char *filename) {

	// get common name from subject of X509 certificate
	// this function must return valid name or exit the program
	X509 *cert = NULL;
	FILE *fp = fopen(filename, "r");

	// CHECK_ERR_FATAL(!fp, "cannot open certificate file\n");

	PEM_read_X509(fp, &cert, NULL, NULL);
	fclose(fp);

	// CHECK_ERR_FATAL(!cert, "cannot read X509 certificate\n");

	// TODO: maybe do some aditional checks if it's sentinel CA? check issuer?
	char *ret = malloc(CERT_NAME_MAX_LEN);
	ret[0] = 0;
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
		ret, CERT_NAME_MAX_LEN);
	X509_free(cert);

	// CHECK_ERR_FATAL(!strlen(ret), "couldn't get name from cert\n");
	return ret;
}

int proxy_mqtt_init(struct proxy_mqtt *mqtt, struct event_base *event_base,
		const struct proxy_conf *conf) {
	
	char *client_id = get_name_from_cert(conf->client_cert_file);
	int ret = MQTTClient_create(mqtt->client, conf->upstream_srv, client_id,
		MQTTCLIENT_PERSISTENCE_NONE, NULL);
	free(client_id);

	mqtt->conn_opts = malloc(sizeof(*mqtt->conn_opts));
	mqtt->ssl_opts = malloc(sizeof(*mqtt->ssl_opts));
	mqtt->will_opts = malloc(sizeof(*mqtt->will_opts));

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	MQTTClient_willOptions lw_opts = MQTTClient_willOptions_initializer;

	memcpy(mqtt->conn_opts, &conn_opts, sizeof(*mqtt->conn_opts));
	memcpy(mqtt->conn_opts, &ssl_opts, sizeof(*mqtt->ssl_opts));
	memcpy(mqtt->conn_opts, &lw_opts, sizeof(*mqtt->will_opts));

	mqtt->conn_opts->ssl = mqtt->ssl_opts;
	mqtt->conn_opts->will = mqtt->will_opts;


	mqtt_setup(&conn_opts, conf, status_topic, &last_will_payload);




}


void proxy_mqtt_destroy(struct proxy_mqtt *mqtt) {

}



// mqtt setup
// mqtt connect

// mqtt send
// mqtt yeld

// mqtt disconnect
// mqtt free client



// mqtt get client
// mqtt connect

// mqtt send heart beat - connect, mqtt timer

// mqtt disconnect
// mqtt free client
