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

#include <sys/prctl.h>
#include <signal.h>

#include "config.h"
#include "proxy_zmq.h"
#include "proxy_mqtt.h"
#include "common.h"

#define SENTINEL_PROXY "sentinel-proxy"

static void discard_cb(int severity, const char *msg) {}

static void loopbrake_cb(evutil_socket_t sig, short events, void *arg) {
	TRACE_FUNC;
	event_base_loopbreak((struct event_base *)arg);
}

static void run(const struct proxy_conf *conf) {
	TRACE_FUNC;
	event_set_log_callback(discard_cb);
	struct event_base *ev_base = event_base_new(); 
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL,
		loopbrake_cb, ev_base);
	event_add(sigint_ev, NULL);
	struct event *sigterm_ev = event_new(ev_base, SIGTERM, EV_SIGNAL,
		loopbrake_cb, ev_base);
	event_add(sigterm_ev, NULL);

	struct proxy_mqtt mqtt;
	proxy_mqtt_init(&mqtt, ev_base, conf);

	struct proxy_zmq proxy_zmq;
	proxy_zmq_init(&proxy_zmq, ev_base, conf->local_socket);
	proxy_zmq.mqtt = &mqtt;

	event_base_dispatch(ev_base);
	
	proxy_zmq_destroy(&proxy_zmq);
	proxy_mqtt_destroy(&mqtt);

	event_free(sigterm_ev);
	event_free(sigint_ev);
	event_base_free(ev_base);
}

int main(int argc, char *argv[]) {
	// set logger and process name for easier debuging
	prctl(PR_SET_NAME, SENTINEL_PROXY);
	log_sentinel_proxy->name = SENTINEL_PROXY;
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
	run(&proxy_conf);
	return 0;
}
