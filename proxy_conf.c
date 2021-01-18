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

#include "proxy_conf.h"

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>
#include <fcntl.h>
#include <libconfig.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "default.h"
#include "device_token.h"


bool is_accessible(const char *filename) {
	return (access(filename, R_OK) == 0);
}

void verify_access(const char *filename) {
	if (!is_accessible(filename)) {
		fprintf(stderr, "%s can't be accessed\n", filename);
		exit(EXIT_FAILURE);
	}
}

static struct proxy_conf proxy_conf = {
	.upstream_srv = DEFAULT_UPSTREAM_SRV,
	.local_socket = DEFAULT_LOCAL_SOCKET,
	.ca_file = DEFAULT_CA_FILE,
	.client_cert_file = DEFAULT_CERT_FILE,
	.client_key_file = DEFAULT_KEY_FILE,
	.device_token[0] = '\0',
	.config_file = DEFAULT_CONFIG_FILE,
	.custom_conf_file = false
};

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	struct proxy_conf *conf = state->input;

	switch (key) {
		case 'S':
			conf->upstream_srv = arg;
			break;
		case 's':
			conf->local_socket = arg;
			break;
		case 'c':
			conf->ca_file = arg;
			break;
		case 'C':
			conf->client_cert_file = arg;
			break;
		case 'K':
			conf->client_key_file = arg;
			break;
		case 't':
			strncpy(conf->device_token, arg, DEVICE_TOKEN_LEN + 1);
			break;
		case 'f':
			conf->config_file = arg;
			conf->custom_conf_file = true;
			break;
		case ARGP_KEY_ARG:
		  if (state->arg_num >= 1)
			/* Too many arguments. */
			argp_usage(state);
		  break;

		default:
		  return ARGP_ERR_UNKNOWN;
		}
	return 0;
}

void load_cli_opts(int argc, char *argv[], struct proxy_conf *conf) {
	// This function might be called multiple times and must be idempotent

	/* Program documentation. */
	static char doc[] = "Sentinel:Proxy - Turris:Sentinel data gateway";

	static struct argp_option options[] = {
		{"server",   'S', "server",       0,  "Sentinel server address" },
		{"socket",   's', "socket",       0,  "Local ZMQ socket" },
		{"ca",       'c', "ca_file",      0,  "Path to Sentinel CA file"},
		{"cert",     'C', "cert_file",    0,  "Path to MQTT cert file"},
		{"key",      'K', "key_file",     0,  "Path to MQTT key file"},
		{"token",    't', "device_token", 0,  "Sentinel device token"},
		{"config",   'f', "config_file",  0,  "Path to config file"},
		{ 0 }
	};

	/* Our argp parser. */
	static struct argp argp = { options, parse_opt, 0, doc };
	argp_parse(&argp, argc, argv, 0, 0, conf);
}

void load_config_file(const char *path, struct proxy_conf * conf) {
	config_t cfg;
	const char *tmp="";

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(&cfg, path)){
		fprintf(stderr, "error reading config file %s: %s:%d - %s\n",
			path,
			config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg)
		);
		config_destroy(&cfg);
		exit(EXIT_FAILURE);
	}

	config_lookup_string(&cfg, "device_token", &tmp);
	strncpy(conf->device_token, tmp, DEVICE_TOKEN_LEN + 1);

	config_destroy(&cfg);
}

const struct proxy_conf *load_conf(int argc, char *argv[]) {
	// We load cli params first (to get config file path most notably) Then we
	// load config file if exists end is readable. If that is succesfull we have
	// to load cli params once more - since they have higher priority.
	load_cli_opts(argc, argv, &proxy_conf);
	if (is_accessible(proxy_conf.config_file)) {
		load_config_file(proxy_conf.config_file, &proxy_conf);
		load_cli_opts(argc, argv, &proxy_conf);
	} else {
		fprintf(stderr, "WARN: config file %s can't be accessed\n",
				proxy_conf.config_file);
	}

	int verify_status = device_token_verify(proxy_conf.device_token);
	fprintf(stderr, "%s\n", device_token_state_msg(verify_status));
	if (verify_status)
		exit(EXIT_FAILURE);
	verify_access(proxy_conf.ca_file);
	verify_access(proxy_conf.client_cert_file);
	verify_access(proxy_conf.client_key_file);

	fprintf(
		stderr,
		"Using CA cert: %s, client cert: %s, client private key: %s\n",
		proxy_conf.ca_file,
		proxy_conf.client_cert_file,
		proxy_conf.client_key_file
	);

	return &proxy_conf;
}
