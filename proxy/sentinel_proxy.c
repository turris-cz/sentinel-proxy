/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018 - 2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <czmq_logc.h>

#include "proxy_conf.h"
#include "proxy_zmq.h"
#include "proxy_mqtt.h"
#include "log.h"

int main(int argc, char *argv[]) {
	log_bind(log_sentinel_proxy, log_czmq);
	logc_czmq_init();

	struct proxy_conf proxy_conf;
	init_conf(&proxy_conf);
	load_conf(argc, argv, &proxy_conf);

	struct mqtt mqtt;
	struct zmq zmq;
	zloop_t *zloop = zloop_new();
	assert(zloop);
	init_mqtt(&mqtt, zloop, &proxy_conf);
	init_zmq(&zmq, &mqtt, zloop, proxy_conf.zmq_sock_path);

	zloop_start(zloop);

	destroy_zmq(&zmq);
	destroy_mqtt(&mqtt);
	zloop_destroy(&zloop);

	logc_czmq_cleanup();
	log_unbind(log_czmq);
	return 0;
}
