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
#include <stdio.h>

#include "../../proxy/proxy_mqtt.h"
#include "../../proxy/common.h"

#define ck_assert_msgpack_str(msgpack, string) do { \
		ck_assert_int_eq(msgpack.type, MSGPACK_OBJECT_STR); \
		ck_assert_int_eq(msgpack.via.str.size, strlen(string)); \
		ck_assert_mem_eq(msgpack.via.str.ptr, string, strlen(string)); \
	} while (false)

#define ck_assert_msgpack_uint(msgpack, num) do { \
		ck_assert_int_eq(msgpack.type, MSGPACK_OBJECT_POSITIVE_INTEGER); \
		ck_assert_int_eq(msgpack.via.u64, num); \
	} while (false)


START_TEST(compose_sentinel_msg_test) {
	msgpack_sbuffer sbuf;
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer pk;
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	msgpack_unpacked upkd;
	msgpack_unpacked_init(&upkd);

	struct sentinel_status_mesg sentinel_msg = {
		.action = "sdfsdfsadf",
		.ts = 4686435445443445435,
	};
	compose_sentinel_mesg(&sbuf, &pk, &sentinel_msg);

	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuf.data, sbuf.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 2);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[0].val, sentinel_msg.action);
	ck_assert_msgpack_str(r.via.map.ptr[1].key, "ts");
	ck_assert_msgpack_uint(r.via.map.ptr[1].val, sentinel_msg.ts);

	msgpack_sbuffer_destroy(&sbuf);
	msgpack_unpacked_destroy(&upkd);
}

START_TEST(compose_last_will_test) {
	msgpack_sbuffer sbuf;
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer pk;
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	msgpack_unpacked upkd;
	msgpack_unpacked_init(&upkd);

	compose_last_will(&sbuf, &pk);

	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuf.data, sbuf.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 1);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[0].val, LAST_WILL_DISCONNECT_EV);

	msgpack_sbuffer_destroy(&sbuf);
	msgpack_unpacked_destroy(&upkd);
}

START_TEST(build_data_t_test) {
	char *id = "abcde";
	char *token = "124fgh";
	char *res = "sentinel/collect/abcde/124fgh/";

	char *buff = NULL;
	char *end = NULL;
	build_data_topic(&buff, &end, id, token);
	ck_assert_str_eq(buff, res);
	ck_assert_ptr_eq(end, buff + strlen(res));
	free(buff);
}

START_TEST(update_data_t_test) {
	char *topic = "fusfdslhfdiuhsdfhlshdflhsaldf sdfsdfsdhsdf sdfhshfdlhslhdfsdf4s21f2sf";
	size_t t_len = strlen(topic);

	char *buff = malloc(t_len);
	update_data_topic(buff, topic, t_len);
	ck_assert_str_eq(buff, topic + TOPIC_PREFIX_LEN);
	free(buff);
}

START_TEST(bild_status_t_tests) {
	char *id = "abcde";
	char *token = "124fgh";
	char *res = "sentinel/collect/abcde/124fgh/status";

	char *buff = NULL;
	build_status_topic(&buff, id, token);
	ck_assert_str_eq(buff, res);
	free(buff);
}

START_TEST(build_server_uri_test) {
	char *server = "example.com";
	int port = 12345;
	char *res = "ssl://example.com:12345";

	char *buff = NULL;
	build_server_uri(&buff, server, port);
	ck_assert_str_eq(buff, res);
	free(buff);
}

static char *get_test_cert_file_path() {
	char *dir = getenv("DATA_DIR");
	if (!dir)
		dir =  "./tests/unit/data/";
	char *path;
	asprintf(&path, "%s/%s", dir, "test_cert.pem");
	return path;
}

START_TEST(get_client_id_test) {
	// const char *cert_file = "./tests/unit/test_cert.pem";
	char *cert_file = get_test_cert_file_path();
	char *id = NULL;
	get_client_id(cert_file, &id);
	ck_assert_str_eq(id, "proxy");
	free(id);
	free(cert_file);
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("proxy_mqtt");
	
	TCase *get_name_from_cert_tc = tcase_create("get_client_id");
	tcase_add_test(get_name_from_cert_tc, get_client_id_test);
	suite_add_tcase(suite, get_name_from_cert_tc);

	TCase *data_topic_tc = tcase_create("data topic");
	tcase_add_test(data_topic_tc, build_data_t_test);
	tcase_add_test(data_topic_tc, update_data_t_test);
	suite_add_tcase(suite, data_topic_tc);

	TCase *status_topic_tc = tcase_create("status topic");
	tcase_add_test(status_topic_tc, bild_status_t_tests);
	suite_add_tcase(suite, status_topic_tc);

	TCase *server_uri_tc = tcase_create("server uri");
	tcase_add_test(server_uri_tc, build_server_uri_test);
	suite_add_tcase(suite, server_uri_tc);

	TCase *comp_last_will_tc = tcase_create("compose_last_will");
	tcase_add_test(comp_last_will_tc, compose_last_will_test);
	suite_add_tcase(suite, comp_last_will_tc);

	TCase *comp_sentinel_msg_tc = tcase_create("compose_sentinel_message");
	tcase_add_test(comp_sentinel_msg_tc, compose_sentinel_msg_test);
	suite_add_tcase(suite, comp_sentinel_msg_tc);

	unittests_add_suite(suite);
}

