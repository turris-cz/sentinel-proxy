/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#ifndef __SENTINEL_PROXY_PROXY_CONF_H__
#define __SENTINEL_PROXY_PROXY_CONF_H__

#include <stdbool.h>
#include "device_token.h"
#include "const.h"

struct proxy_conf {
    const char *upstream_srv;
    const char *local_socket;
    const char *ca_file;
    const char *client_cert_file;
    const char *client_key_file;
    char device_token[DEVICE_TOKEN_LEN + 1];
    const char *config_file;
    bool custom_conf_file;
};

const struct proxy_conf *load_conf(int argc, char *argv[]);

#endif /*__SENTINEL_PROXY_PROXY_CONF_H__*/
