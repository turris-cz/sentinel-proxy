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

#ifndef __SENTINEL_PROXY_DEFAULT_H__
#define __SENTINEL_PROXY_DEFAULT_H__

#define DEFAULT_UPSTREAM_SRV "ssl://sentinel.turris.cz:1883"
#define DEFAULT_LOCAL_SOCKET "ipc:///tmp/sentinel_pull.sock"
#define DEFAULT_CA_FILE "/etc/sentinel/ca.crt"
#define DEFAULT_CERT_FILE "/etc/sentinel/router.crt"
#define DEFAULT_KEY_FILE "/etc/sentinel/router.key"

#endif /*__SENTINEL_PROXY_DEFAULT_H__*/
