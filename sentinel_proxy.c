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

#include <signal.h>
#include <event2/event.h>

#include "config.h"
#include "proxy_conf.h"
#include "proxy_zmq.h"
#include "log.h"

static void discard_cb(int severity, const char *msg) {}

static void loopbrake_cd(evutil_socket_t sig, short events, void *arg) {
	TRACE_FUNC;
	event_base_loopbreak((struct event_base *)arg);
}

static void run(const struct proxy_conf *conf) {
	TRACE_FUNC;
	event_set_log_callback(discard_cb);
	struct event_base *ev_base = event_base_new(); 
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL,
		loopbrake_cd, ev_base);
	event_add(sigint_ev, NULL);
	struct event *sigterm_ev = event_new(ev_base, SIGTERM, EV_SIGNAL,
		loopbrake_cd, ev_base);
	event_add(sigterm_ev, NULL);

	// setup mqtt client
	printf("asa\n");
	struct proxy_zmq proxy_zmq;
	proxy_zmq_init(&proxy_zmq, ev_base, conf->local_socket);
	
	printf("dispatch\n");
	event_base_dispatch(ev_base);
	
	event_free(sigint_ev);
	event_free(sigterm_ev);

	// destroy mqtt client

	proxy_zmq_destroy(&proxy_zmq);

	event_base_free(ev_base);
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
	run(&proxy_conf);
	return 0;
}
