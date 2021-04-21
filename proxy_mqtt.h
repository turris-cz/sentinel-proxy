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

#ifndef __SENTINEL_PROXY_MQTT_H__
#define __SENTINEL_PROXY_MQTT_H__

#include <event2/event.h>
#include <MQTTClient.h>
#include <msgpack.h>

struct sentinel_status_mesg {
	char *action;
	long long int ts;
};

struct proxy_mqtt {
	char *client_id;
	char *status_topic;
	char *data_topic;
	size_t data_topic_prefix_len;
	MQTTClient client;
	MQTTClient_connectOptions *conn_opts;
	MQTTClient_SSLOptions *ssl_opts;
	MQTTClient_willOptions *will_opts;
	msgpack_sbuffer *last_will_payload;
	msgpack_sbuffer *sbuff;
	msgpack_packer *packer;
	struct sentinel_status_mesg *status_mesg;
	struct event *mqtt_client_yeld_ev;
	struct event *sentinel_heartbeat_ev;
};

int proxy_mqtt_init(struct proxy_mqtt *mqtt, struct event_base *ev_base,
	const struct proxy_conf *conf);


#endif /*__SENTINEL_PROXY_MQTT_H__*/
