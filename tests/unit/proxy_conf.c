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

static struct proxy_conf proxy_conf;

static void setup() {
	init_conf(&proxy_conf);
}

static void teardown() {
	destroy_conf(&proxy_conf);
}

START_TEST(set_field_test1) {
	// initial memory size is greater than new string length
	size_t mem_len = 20;
	char *str = malloc(mem_len);
	memset(str, '7', mem_len);
	char *new_str = "abcds";
	set_field(&str, &mem_len, new_str, strlen(new_str));
	ck_assert_str_eq(str, new_str);
	ck_assert_uint_eq(mem_len, 20);
	free(str);
}

START_TEST(set_field_test2) {
	// initial memory size is lower than new string length
	size_t mem_len = 1;
	char *str = malloc(mem_len);
	memset(str, 'a', mem_len);
	char new_str[] = "abcds";
	set_field(&str, &mem_len, new_str, strlen(new_str));
	ck_assert_str_eq(str, new_str);
	ck_assert_uint_eq(mem_len, sizeof(new_str));
	free(str);
}

START_TEST(set_field_test3) {
	// initial memory size is same as new string length
	size_t mem_len = 6;
	char *str = malloc(mem_len);
	memset(str, 'c', mem_len);
	char new_str[] = "abcds";
	set_field(&str, &mem_len, new_str, strlen(new_str));
	ck_assert_str_eq(str, new_str);
	ck_assert_uint_eq(mem_len, sizeof(new_str));
	free(str);
}

START_TEST(parse_port_test_valid) {
	ck_assert_int_eq(parse_port("12345"), 12345);
}

START_TEST(parse_port_test_invalid) {
	ck_assert_int_eq(parse_port("-1"), -1);
	ck_assert_int_eq(parse_port("65536"), -1);
	ck_assert_int_eq(parse_port("asasasas"), -1);
	ck_assert_int_eq(parse_port(""), -1);
	ck_assert_int_eq(parse_port("65hghg"), -1);
	ck_assert_int_eq(parse_port("65 hghg"), -1);
}

START_TEST(init_test) {
	// init is done by setup() in proxy_conf_fixtures
	ck_assert_int_eq(proxy_conf.disable_serv_check, false);
	ck_assert_int_eq(proxy_conf.mqtt_port, DEFAULT_PORT);
	ck_assert_str_eq(proxy_conf.mqtt_broker, DEFAULT_SERVER);
	ck_assert_int_eq(proxy_conf.mqtt_broker_len, sizeof(DEFAULT_SERVER));
	ck_assert_str_eq(proxy_conf.mqtt_client_cert_file,
		DEFAULT_MQTT_CLIENT_CERT_FILE);
	ck_assert_int_eq(proxy_conf.mqtt_cl_cert_f_len,
		sizeof(DEFAULT_MQTT_CLIENT_CERT_FILE));
	ck_assert_str_eq(proxy_conf.mqtt_client_key_file,
		DEFAULT_MQTT_CLIENT_KEY_FILE);
	ck_assert_int_eq(proxy_conf.mqtt_cl_key_f_len,
		sizeof(DEFAULT_MQTT_CLIENT_KEY_FILE));
	ck_assert_str_eq(proxy_conf.ca_cert_file, DEFAULT_CA_CERT_FILE);
	ck_assert_int_eq(proxy_conf.ca_cert_f_len, sizeof(DEFAULT_CA_CERT_FILE));
	ck_assert_str_eq(proxy_conf.zmq_sock_path, DEFAULT_ZMQ_SOCK_PATH);
	ck_assert_int_eq(proxy_conf.zmq_sock_p_len, sizeof(DEFAULT_ZMQ_SOCK_PATH));
	ck_assert_str_eq(proxy_conf.config_file, DEFAULT_CONFIG_FILE);
	ck_assert_int_eq(proxy_conf.conf_f_len, sizeof(DEFAULT_CONFIG_FILE));
	ck_assert_str_eq(proxy_conf.device_token, "");
	ck_assert_int_eq(proxy_conf.dt_len, DEV_TOKEN_MEM_LEN);
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
}

START_TEST(load_cli_opts_test) {
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
	
	TCase *set_field_tc = tcase_create("set_field");
	tcase_add_test(set_field_tc, set_field_test1);
	tcase_add_test(set_field_tc, set_field_test2);
	tcase_add_test(set_field_tc, set_field_test3);
	suite_add_tcase(suite, set_field_tc);

	TCase *parse_port_tc = tcase_create("parse_port");
	tcase_add_test(parse_port_tc, parse_port_test_valid);
	tcase_add_test(parse_port_tc, parse_port_test_invalid);
	suite_add_tcase(suite, parse_port_tc);

	TCase *conf_tc = tcase_create("conf");
	tcase_add_checked_fixture(conf_tc, setup, teardown);
	tcase_add_test(conf_tc, init_test);
	tcase_add_test(conf_tc, load_config_file_test);
	tcase_add_test(conf_tc, load_cli_opts_test);
	suite_add_tcase(suite, conf_tc);

	unittests_add_suite(suite);
}
