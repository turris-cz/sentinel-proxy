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

#include <libconfig.h>
#include <logc_argp.h>
#include <unistd.h>

#include "proxy_conf.h"
#include "log.h"

#define xstr(s) str(s)
#define str(s) #s

#define CONF_FIELD_SERVER "server"
#define CONF_FIELD_PORT "port"
#define CONF_FIELD_CL_CERT_FILE "client_cert_file"
#define CONF_FIELD_CL_KEY_FILE "client_key_file"
#define CONF_FIELD_CA_CERT_FILE "ca_cert_file"
#define CONF_FIELD_ZMQ_SOCK_PATH "zmq_socket_path"
#define CONF_FIELD_DEVICE_TOKEN "device_token"

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = "<packaging@turris.cz>";
static const char doc[] = PACKAGE_NAME " - Turris Sentinel data gateway";
static const struct argp_option options[] = {
	{"server", 'S', "server", 0,
		"Sentinel server address - default is: " DEFAULT_SERVER},
	{"port", 'p', "port", 0,
		"Sentinel server port - default is: " xstr(DEFAULT_PORT)},
	{"zmq-sock", 's', "zmq_socket_path", 0,
		"ZMQ socket path - default is: " DEFAULT_ZMQ_SOCK_PATH},
	{"ca-cert", 'c', "ca_cert_file", 0,
		"Path to Sentinel CA certificate file - default is: " DEFAULT_CA_CERT_FILE},
	{"cl-cert", 'C', "client_cert_file", 0,
		"Path to Sentinel client certificate file - default is: " DEFAULT_MQTT_CLIENT_CERT_FILE},
	{"cl-key", 'K', "client_key_file", 0,
		"Path to Sentinel client key file - default is: " DEFAULT_MQTT_CLIENT_KEY_FILE},
	{"token", 't', "device_token", 0, "Sentinel device token"},
	{"config", 'f', "config_file", 0,
		"Path to configuration file - default is: " DEFAULT_CONFIG_FILE},
	// For development and testing only !!!
	{"disable-serv-check", 'd', NULL,  OPTION_HIDDEN, NULL},
	{NULL}
};
static bool port_once_parsed;

__attribute__((nonnull)) bool is_accessible(const char *filename) {
	TRACE_FUNC;
	return (access(filename, R_OK) == 0);
}

__attribute__((nonnull)) void verify_access(const char *filename) {
	TRACE_FUNC;
	if (!is_accessible(filename))
		critical("%s can't be accessed.", filename);
}

int parse_port(const char *str) {
	TRACE_FUNC;
	char *end_ptr;
	errno = 0;
	long result = strtol(str, &end_ptr, 10);
	if (errno || // conversion error
			end_ptr == str || // no digits
			*end_ptr != '\0' || // number in the begining of a text
			result < 1 || // negative value and zero
			result > 65335) // max port value
		return -1;
	return (int)result;
}

error_t parse_opt (int key, char *arg, struct argp_state *state) {
	TRACE_FUNC;
	int ret = 0;
	struct proxy_conf *conf = (struct proxy_conf *) state->input;
	int tmp;
	switch (key) {
		case 'S':
			conf->mqtt_broker = arg;
			break;
		case 'p':
			if ((tmp = parse_port(arg)) == -1) {
				if (!port_once_parsed)
					warning("Port has invalid value. Ignoring this option.\nUsing configuration file or further default port instead");
			} else
				conf->mqtt_port = tmp;
			port_once_parsed = true;
			break;
		case 's':
			conf->zmq_sock_path = arg;
			break;
		case 'c':
			conf->ca_cert_file = arg;
			break;
		case 'C':
			conf->mqtt_client_cert_file = arg;
			break;
		case 'K':
			conf->mqtt_client_key_file = arg;
			break;
		case 't':
			conf->device_token = arg;
			break;
		case 'f':
			conf->config_file = arg;
			break;
		case 'd':
			conf->disable_serv_check = true;
			break;
		default:
			ret = ARGP_ERR_UNKNOWN;
			break;
		}
	return ret;
}

void load_cli_opts(int argc, char *argv[], struct proxy_conf *conf) {
	// This function might be called multiple times and must be idempotent
	TRACE_FUNC;
	// set our log to be configured by logc_argp
	logc_argp_log = log_sentinel_proxy;
	struct argp argp = {
		.options = options,
		.parser = parse_opt,
		.doc = doc,
		.children = (struct argp_child[]){{&logc_argp_parser, 0, "Logging", 2},
			{NULL}},
	};
	argp_parse(&argp, argc, argv, 0, 0, conf);
}

void load_conf_str(const config_t *cf, const char *name, char **dest,
		const char *def) {
	TRACE_FUNC;
	const char *tmp = NULL;
	if (config_lookup_string(cf, name, &tmp) == CONFIG_TRUE
		&& (def == NULL || !strcmp(*dest, def)))
		*dest = strdup(tmp);
}

void load_config_file(const char *path, struct proxy_conf *conf) {
	TRACE_FUNC;
	config_t cfg;
	config_init(&cfg);
	if (config_read_file(&cfg, path) != CONFIG_TRUE) {
		warning("Wrong syntax in config file: %s on line %d: %s.\nIgnoring config file. Using CLI options or further default configuration instead.",
			path, config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return;
	}
	load_conf_str(&cfg, CONF_FIELD_DEVICE_TOKEN, &conf->device_token, NULL);
	load_conf_str(&cfg, CONF_FIELD_SERVER, &conf->mqtt_broker, DEFAULT_SERVER);
	load_conf_str(&cfg, CONF_FIELD_CL_CERT_FILE, &conf->mqtt_client_cert_file,
		DEFAULT_MQTT_CLIENT_CERT_FILE);
	load_conf_str(&cfg, CONF_FIELD_CL_KEY_FILE, &conf->mqtt_client_key_file,
		DEFAULT_MQTT_CLIENT_KEY_FILE);
	load_conf_str(&cfg, CONF_FIELD_CA_CERT_FILE, &conf->ca_cert_file,
		DEFAULT_CA_CERT_FILE);
	load_conf_str(&cfg, CONF_FIELD_ZMQ_SOCK_PATH, &conf->zmq_sock_path,
		DEFAULT_ZMQ_SOCK_PATH);
	if (conf->mqtt_port == DEFAULT_PORT)
		config_lookup_int(&cfg, CONF_FIELD_PORT, &conf->mqtt_port);
	config_destroy(&cfg);
}

void init_conf(struct proxy_conf *conf) {
	TRACE_FUNC;
	conf->disable_serv_check = false;
	conf->mqtt_port = DEFAULT_PORT;
	conf->device_token = NULL;
	conf->mqtt_broker = DEFAULT_SERVER;
	conf->zmq_sock_path =  DEFAULT_ZMQ_SOCK_PATH;
	conf->ca_cert_file =  DEFAULT_CA_CERT_FILE;
	conf->mqtt_client_cert_file =  DEFAULT_MQTT_CLIENT_CERT_FILE;
	conf->mqtt_client_key_file = DEFAULT_MQTT_CLIENT_KEY_FILE;
	conf->config_file =  DEFAULT_CONFIG_FILE;
}

void load_conf(int argc, char *argv[], struct proxy_conf *conf) {
	// We load cli params first (to get config file path most notably) Then we
	// load config file if exists end is readable. If that is succesfull we have
	// to load cli params once more - since they have higher priority.
	TRACE_FUNC;
	port_once_parsed = false;
	load_cli_opts(argc, argv, conf);
	if (is_accessible(conf->config_file)) {
		load_config_file(conf->config_file, conf);
		load_cli_opts(argc, argv, conf);
	} else
		warning("Config file %s can't be accessed.\nUsing CLI options or further default configuration instead.",
			conf->config_file);
	enum dt_state verify_status = device_token_verify(conf->device_token);
	if (verify_status != DT_OK)
		if (verify_status == DT_UNDEF)
			critical("Sentinel Device token must be specified\nUse CLI options or configuartion for that.");
		else
			critical("Failed to verify Sentinel Device Token: %s",
				device_token_state_msg(verify_status));
	verify_access(conf->mqtt_client_cert_file);
	verify_access(conf->mqtt_client_key_file);
	if (!conf->disable_serv_check)
		// we need CA cert only if server check is enabled
		verify_access(conf->ca_cert_file);
	info("Sentinel Device token check passed");
	info("Using following configuration:");
	info("Sentinel server: %s", conf->mqtt_broker);
	info("Sentinel server port: %d", conf->mqtt_port);
	info("ZMQ socket: %s", conf->zmq_sock_path);
	info("Sentinel client certificate: %s", conf->mqtt_client_cert_file);
	info("Sentinel client key: %s", conf->mqtt_client_key_file);
	if (conf->disable_serv_check)
		warning("Sentinel server verification disabled!!!");
	else
		// we need CA cert only if server check is enabled
		info("Sentinel CA certificate: %s", conf->ca_cert_file);
}
