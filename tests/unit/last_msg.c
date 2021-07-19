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

#include "../../proxy/last_msg_list.h"

static struct last_msg msg;

static void setup() {
	init_last_msg(&msg);
}

static void teardown() {
	destroy_last_msg(&msg);
}

START_TEST(init_last_msg_test) {
	// init is done by setup()
	ck_assert_uint_eq(msg.time_stamp, 0);
	ck_assert_ptr_ne(msg.topic, NULL);
	ck_assert_str_eq(msg.topic, "");
}

START_TEST(set_last_msg_test) {
	unsigned long long ts = 4565664464646454;
	char *topic = "test topic";
	size_t topic_len = strlen(topic);
	set_last_msg(&msg, ts, topic, topic_len);
	ck_assert_int_eq(msg.time_stamp, ts);
	ck_assert_mem_eq(msg.topic, topic, topic_len);
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("con_peer");

	TCase *basic_tc = tcase_create("basic");
	tcase_add_checked_fixture(basic_tc, setup, teardown);
	tcase_add_test(basic_tc, init_last_msg_test);
	tcase_add_test(basic_tc, set_last_msg_test);

	suite_add_tcase(suite, basic_tc);

	unittests_add_suite(suite);
}
