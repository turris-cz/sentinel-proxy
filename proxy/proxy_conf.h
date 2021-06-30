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

#ifndef __SENTINEL_PROXY_PROXY_CONF_H__
#define __SENTINEL_PROXY_PROXY_CONF_H__

#include <stdbool.h>
#include <string.h>
#include <device_token.h>

struct proxy_conf {
	bool disable_serv_check;
	int mqtt_port;
	char *mqtt_broker;
	char *mqtt_client_cert_file;
	char *mqtt_client_key_file;
	char *ca_cert_file;
	char *zmq_sock_path;
	char *config_file;
	char *device_token;
};

// NOTE: This is private API exposed just for the testing.
// It is NOT supposed to be used anywhere else.

// Converts C NULL terminated string representing port number (0 - 65535) to integer value .
// If string contains invalid port value it returns -1.
int parse_port(const char *str) __attribute__((nonnull));

// Loads configuration from CLI options and their arguments.
// conf struct MUST be first properly initialized by init_conf().
void load_cli_opts(int argc, char *argv[], struct proxy_conf *conf)
__attribute__((nonnull));

// Loads configuration from given configuration file.
// conf struct MUST be first properly initialized by init_conf().
void load_config_file(const char *path, struct proxy_conf *conf)
__attribute__((nonnull));


// NOTE: This is public API intended for normal use.

// Allocates memory for conf struct fields and initializes them with default values.
void init_conf(struct proxy_conf *conf) __attribute__((nonnull));

// Loads configuration from CLI options and configuration file.
// conf struct MUST be first properly initialized by init_conf().
// The priorities of configuration is following:
// CLi options > configuration file > default conf
// CLI options have higher priority than conf. file, which has higher priority
// than default configuration.
void load_conf(int argc, char *argv[], struct proxy_conf *conf)
__attribute__((nonnull));

#endif /*__SENTINEL_PROXY_PROXY_CONF_H__*/
