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

#include <check.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../proxy/proxy_conf.h"

START_TEST(parse_port_test_valid) {
	ck_assert_int_eq(parse_port("12345"), 12345);
}

START_TEST(parse_port_test_invalid) {
	ck_assert_int_eq(parse_port("-1"), -1);
	ck_assert_int_eq(parse_port("0"), -1);
	ck_assert_int_eq(parse_port("65536"), -1);
	ck_assert_int_eq(parse_port("asasasas"), -1);
	ck_assert_int_eq(parse_port(""), -1);
	ck_assert_int_eq(parse_port("65hghg"), -1);
	ck_assert_int_eq(parse_port("65 hghg"), -1);
}

START_TEST(init_test) {
	struct proxy_conf proxy_conf;
	init_conf(&proxy_conf);

	ck_assert_int_eq(proxy_conf.disable_serv_check, false);
	ck_assert_int_eq(proxy_conf.mqtt_port, DEFAULT_PORT);
	ck_assert_str_eq(proxy_conf.mqtt_broker, DEFAULT_SERVER);
	ck_assert_str_eq(proxy_conf.mqtt_client_cert_file,
		DEFAULT_MQTT_CLIENT_CERT_FILE);
	ck_assert_str_eq(proxy_conf.mqtt_client_key_file,
		DEFAULT_MQTT_CLIENT_KEY_FILE);
	ck_assert_str_eq(proxy_conf.ca_cert_file, DEFAULT_CA_CERT_FILE);
	ck_assert_str_eq(proxy_conf.zmq_sock_path, DEFAULT_ZMQ_SOCK_PATH);
	ck_assert_str_eq(proxy_conf.config_file, DEFAULT_CONFIG_FILE);
	ck_assert_ptr_eq(proxy_conf.device_token, NULL);
}

static char *get_test_config_file_path() {
	char *dir = getenv("DATA_DIR");
	if (!dir)
		dir =  "./tests/unit/data/";
	char *path;
	asprintf(&path, "%s/%s", dir, "test_config.cfg");
	return path;
}

START_TEST(load_config_file_test) {
	struct proxy_conf proxy_conf;
	init_conf(&proxy_conf);

	char *config_file = get_test_config_file_path();
	// load_config_file("./tests/unit/test_config.cfg", &proxy_conf);
	load_config_file(config_file, &proxy_conf);
	// this is NOT changed by config file
	ck_assert_int_eq(proxy_conf.disable_serv_check, false);
	ck_assert_str_eq(proxy_conf.config_file, DEFAULT_CONFIG_FILE);
	// this is changed
	ck_assert_str_eq(proxy_conf.mqtt_broker, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	ck_assert_int_eq(proxy_conf.mqtt_port, 55555);
	ck_assert_str_eq(proxy_conf.mqtt_client_cert_file, "bbbbbbbbbbbbbbbbbbbbbbb");
	ck_assert_str_eq(proxy_conf.mqtt_client_key_file,
		"ccccccccccccccccccccccccccccccc");
	ck_assert_str_eq(proxy_conf.ca_cert_file, "dddddddddddddddddddddddddddddddd");
	ck_assert_str_eq(proxy_conf.zmq_sock_path, "eeeeeeeeeeeeeeeeeeeee");
	ck_assert_str_eq(proxy_conf.device_token,
		"fffffffffffffffffffffffffffffffffffffffffff");
	free(config_file);

	free(proxy_conf.device_token);
	free(proxy_conf.mqtt_broker);
	free(proxy_conf.mqtt_client_cert_file);
	free(proxy_conf.mqtt_client_key_file);
	free(proxy_conf.ca_cert_file);
	free(proxy_conf.zmq_sock_path);
}

START_TEST(load_cli_opts_test) {
	struct proxy_conf proxy_conf;
	init_conf(&proxy_conf);

	char server[] = "adsasdasdasdasdasdasd";
	char port[] = "12345";
	char socket[] = "iuhk";
	char ca[] = "aqqqqqqqqqqweqwrqr";
	char cert[] = "mkjlkjloppppppp";
	char key[] = "mnnbcvzlkjsdasdgjaskadl";
	char token[] = "bgjhfkualshdladl";
	char config[] = "r7yhhbvz80igiwg87wt8dyk";
	char *argv[] = {"cmd",
		"--server", server,
		"--port", port,
		"--zmq-sock", socket,
		"--ca-cert", ca,
		"--cl-cert", cert,
		"--cl-key", key,
		"--token", token,
		"--config", config,
		"--disable-serv-check",
	};
	int argc = sizeof(argv) / sizeof(*argv);
	load_cli_opts(argc, argv, &proxy_conf);
	ck_assert_int_eq(proxy_conf.disable_serv_check, true);
	ck_assert_int_eq(proxy_conf.mqtt_port, 12345);
	ck_assert_str_eq(proxy_conf.mqtt_broker, server);
	ck_assert_str_eq(proxy_conf.mqtt_client_cert_file, cert);
	ck_assert_str_eq(proxy_conf.mqtt_client_key_file, key);
	ck_assert_str_eq(proxy_conf.ca_cert_file, ca);
	ck_assert_str_eq(proxy_conf.zmq_sock_path, socket);
	ck_assert_str_eq(proxy_conf.config_file, config);
	ck_assert_str_eq(proxy_conf.device_token, token);
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("proxy_conf");
	
	TCase *parse_port_tc = tcase_create("parse_port");
	tcase_add_test(parse_port_tc, parse_port_test_valid);
	tcase_add_test(parse_port_tc, parse_port_test_invalid);
	suite_add_tcase(suite, parse_port_tc);

	TCase *conf_tc = tcase_create("conf");
	tcase_add_test(conf_tc, init_test);
	tcase_add_test(conf_tc, load_config_file_test);
	tcase_add_test(conf_tc, load_cli_opts_test);
	suite_add_tcase(suite, conf_tc);

	unittests_add_suite(suite);
}
