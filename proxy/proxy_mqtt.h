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
#ifndef __SENTINEL_PROXY_MQTT_H__
#define __SENTINEL_PROXY_MQTT_H__

#include <czmq.h>
#include <MQTTClient.h>
#include <msgpack.h>

#include  "proxy_conf.h"

#define HEARTBEAT_EV "heartbeat"
#define DISCONNECT_EV "disconnect"
#define LAST_WILL_DISCONNECT_EV "last_will_disconnect"

struct sentinel_status_mesg {
	char *action;
	long long int ts;
};

struct mqtt {
	char *client_id;
	char *status_topic;
	char *data_topic;
	char *data_topic_prefix_end;
	char *server_uri;
	MQTTClient client;
	MQTTClient_connectOptions *conn_opts;
	MQTTClient_SSLOptions *ssl_opts;
	MQTTClient_willOptions *will_opts;
	msgpack_sbuffer *last_will_payload;
	msgpack_sbuffer *sbuff;
	msgpack_packer *packer;
	struct sentinel_status_mesg *status_mesg;
	zloop_t *zloop;
	int sentinel_heartbeat_timer_id;
	int mqtt_keep_alive_timer_id;
};

// NOTE: This is private API exposed just for the testing.
// It is NOT supposed to be used anywhere else.

// Composes Sentinel message based on values given by mesg.
// It msgpacks map containing action and ts keys with appropriate values from mesg.
// sbuff and pk must be allocated before calling this.
// sbuff MUST be also initialized prior calling this.
// It is intended to be called multiple times on the same sbuff.
// Call msgpack_sbuffer_clear after the content of the buffer is not useful
// anymore and before any subsequent call of this.
void compose_sentinel_mesg(msgpack_sbuffer *sbuff, msgpack_packer *pk,
	const struct sentinel_status_mesg *mesg) __attribute__((nonnull));

// Composes MQTT last will payload.
// It msgpacks map containing action as a key and LAST_WILL_DISCONNECT_EV as a value.
// sbuff and pk must be allocated before calling this.
// sbuff MUST be also initialized prior calling this.
void compose_last_will(msgpack_sbuffer *sbuff, msgpack_packer *pk)
__attribute__((nonnull));

// Composes first part (without topic part coming from received ZMQ message)
// of MQTT data topic NULL terminated string from given  client_id and
// device_token and stores it at *topic_buf. Memory at *topic_buf is allocated
// first for THE WHOLE topic. *topic_buf is overwritten so it SHOULD NOT point
// to any dynamically allocated memory before calling this.
// The end of first part of the topic composed by this function is stored at
// topic_prefix_end. The second part of the topic is supposed to be updated by
// update_data_topic().
void build_data_topic(char **topic_buf, char **topic_prefix_end,
	char *client_id, char *device_token) __attribute__((nonnull));

// Updates the second part of MQTT data topic first composed by build_data_topic().
// Copies (topic_len - TOPIC_PREFIX_LEN) bytes from (topic + TOPIC_PREFIX_LEN)
// to topic_prefix_end and puts NULL string terminated character at the end
// of the whole topic string. Does NOT allocates any memory.
// It MUST be used only after calling build_data_topic().
void update_data_topic(char *topic_prefix_end, char *topic, size_t topic_len)
__attribute__((nonnull));

// Composes MQTT status topic NULL terminated string from given client_id and
// device_token and stores it at *topic_buf. Memory at *topic_buf is allocated first.
// *topic_buf is overwritten so it SHOULD NOT point to any dynamically
// allocated memory before calling this.
void build_status_topic(char **topic_buf, char *client_id, char *device_token)
__attribute__((nonnull));

// Composes server URI NULL terminated string from given server and port
// and stores it at *uri_buf. Memory at *uri_buf is allocated first.
// *uri_buf is overwritten so it SHOULD NOT point to any dynamically
// allocated memory before calling this.
void build_server_uri(char **uri_buf, char *server, int port)
__attribute__((nonnull));

// Gets Common Name from TLS certificate and stores it at *id.
// Memory at *id is allocated first. *id is overwritten by malloc() so
// it SHOULD NOT point to any dynamically allocated memory before calling this.
// If getting Common Name is NOT possible the whole process is aborted.
void get_client_id(const char *filename, char **id)
__attribute__((nonnull));

// NOTE: This is public API intended for normal use.

// Initializes given mqtt struct. It allocates memory, prepares all the
// configuration based on conf, connects to MQTT broker and adds appropriate
// callbacks to event loop. If any of these fails the whole process is aborted.
// DOES assert check for mqtt, zloop and conf.
// For the subsequent MQTT client functionality passed event loop MUST be
// started after calling this.
void init_mqtt(struct mqtt *mqtt, zloop_t *zloop, const struct proxy_conf *conf)
__attribute__((nonnull));

// If mqtt is not NULL, removes all callbacks from event loop, disconnects from 
// MQTT broker and frees all the memory hold by mqtt.
void destroy_mqtt(struct mqtt *mqtt);

// Sends given data to MQTT broker. topic is message topic received from ZMQ,
// which is internally transformed to MQTT data topic. Data are sent to MQTT
// broker as they are without any transformation.
void mqtt_send_data(struct mqtt *mqtt, char *topic, size_t topic_len,
	char *data, size_t data_len) __attribute__((nonnull));

#endif /*__SENTINEL_PROXY_MQTT_H__*/

