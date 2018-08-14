/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#ifndef __SENTINEL_PROXY_CONST_H__
#define __SENTINEL_PROXY_CONST_H__

#define MAX_TOPIC_LEN 256
#define MAX_MSG_SIZE 1024 * 1024 * 2
#define MAX_WAITING_MESSAGES 50
// mandatory prefix for ZMQ topic (is discarded elsewhere)
#define TOPIC_PREFIX "sentinel/collect/"
#define TOPIC_PREFIX_LEN (int)strlen(TOPIC_PREFIX)
// zlib compression levels: 1 is lowest (fastest), 9 is biggest (slowest)
#define COMPRESS_LEVEL 9
// QoS levels - see here:
// https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS 0
#define MQTT_KEEPALIVE_INTERVAL 60  // seconds

#endif /*__SENTINEL_PROXY_CONST_H__*/
