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

#include <stdlib.h>
#include <argp.h>
#include <fcntl.h>
#include <libconfig.h>
#include <string.h>
#include <unistd.h>
#include <logc_argp.h>

#include "proxy_conf.h"
#include "config.h"
#include "log.h"

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = "<packaging@turris.cz>";
static char doc[] = "Sentinel:Proxy - Turris:Sentinel data gateway";
static struct argp_option options[] = {
	{"server",   'S', "server",       0,  "Sentinel server address" },
	{"socket",   's', "socket",       0,  "Local ZMQ socket" },
	{"ca",       'c', "ca_file",      0,  "Path to Sentinel CA file"},
	{"cert",     'C', "cert_file",    0,  "Path to MQTT cert file"},
	{"key",      'K', "key_file",     0,  "Path to MQTT key file"},
	{"token",    't', "device_token", 0,  "Sentinel device token"},
	{"config",   'f', "config_file",  0,  "Path to config file"},
	{NULL}
};

static bool is_accessible(const char *filename) {
	TRACE_FUNC;
	return (access(filename, R_OK) == 0);
}

static void verify_access(const char *filename) {
	TRACE_FUNC;
	if (!is_accessible(filename)) {
		fprintf(stderr, "%s can't be accessed\n", filename);
		exit(EXIT_FAILURE);
	}
}

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	TRACE_FUNC;
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

static void load_cli_opts(int argc, char *argv[], struct proxy_conf *conf) {
	TRACE_FUNC;
	// This function might be called multiple times and must be idempotent
	logc_argp_log = log_sentinel_proxy; // set our log to be configured by logc_argp
	struct argp argp = {
		.options = options,
		.parser = parse_opt,
		.doc = doc,
		.children = (struct argp_child[]){{&logc_argp_parser, 0, "Logging", 2},
			{NULL}},
	};

	argp_parse(&argp, argc, argv, 0, 0, conf);
}

static void load_config_file(const char *path, struct proxy_conf *conf) {
	TRACE_FUNC;
	config_t cfg;
	const char *tmp="";
	config_init(&cfg);
	if(!config_read_file(&cfg, path)){
		fprintf(stderr, "error reading config file %s: %s:%d - %s\n",
			path, config_error_file(&cfg), config_error_line(&cfg),
			config_error_text(&cfg));
		config_destroy(&cfg);
		exit(EXIT_FAILURE);
	}
	config_lookup_string(&cfg, "device_token", &tmp);
	strncpy(conf->device_token, tmp, DEVICE_TOKEN_LEN + 1);
	config_destroy(&cfg);
}

void load_conf(int argc, char *argv[], struct proxy_conf *conf) {
	TRACE_FUNC;
	// We load cli params first (to get config file path most notably) Then we
	// load config file if exists end is readable. If that is succesfull we have
	// to load cli params once more - since they have higher priority.
	load_cli_opts(argc, argv, conf);
	if (is_accessible(conf->config_file)) {
		load_config_file(conf->config_file, conf);
		load_cli_opts(argc, argv, conf);
	} else {
		fprintf(stderr, "WARN: config file %s can't be accessed\n",
			conf->config_file);
	}
	int verify_status = device_token_verify(conf->device_token);
	fprintf(stderr, "%s\n", device_token_state_msg(verify_status));
	if (verify_status)
		exit(EXIT_FAILURE);
	verify_access(conf->ca_file);
	verify_access(conf->client_cert_file);
	verify_access(conf->client_key_file);
	fprintf(stderr, "Using:\nCA cert: %s\nclient cert: %s\nclient private key: %s\n",
		conf->ca_file, conf->client_cert_file, conf->client_key_file);
}
