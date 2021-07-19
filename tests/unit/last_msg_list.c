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
#include <stdbool.h>

#include "../../proxy/last_msg_list.h"

static struct last_msg_list list;

static void setup() {
	init_last_msg_list(&list);
}

static void teardown() {
	destroy_last_msg_list(&list);
}

struct last_msg_data {
	unsigned long long ts;
	char *topic;
};

START_TEST(init_test) {
	ck_assert_uint_eq(list.alloc_size, LAST_MSG_LIST_DEFAULT_LEN);
	ck_assert_ptr_ne(list.messages, NULL);
}

START_TEST(update_test) {
	const struct last_msg_data const data[] = {
		{2122121211, "topic01"},
		{7987643, "topic02"},
		{31376874354, "topic03"},
		{497973144, "topic04"},
		{13234676, "topic05"},
		{3656469, "topic06"},
		{798139, "topic07"},
		{987979864646, "topic08"},
	};
	for (size_t i = 0; i < (sizeof(data) / sizeof(*data)); i++) {
		size_t t_len = strlen(data[i].topic);
		update_last_msg(&list, data[i].topic, t_len, data[i].ts);
		// find messages in the list
		bool is_there = false;
		size_t j = 0;
		for(; j < list.alloc_size; j++) {
			if (!strncmp(data[i].topic, list.messages[j].topic, t_len)) {
				is_there = true;
				break;
			}
		}
		if (is_there) {
			// check the last message
			ck_assert_uint_eq(list.messages[j].time_stamp, data[i].ts);
			ck_assert_mem_eq(list.messages[j].topic, data[i].topic, t_len);
		} else {
			ck_assert(false);
		}
	}
}

START_TEST(update_test1) {
	// To check that there is no new allocation when messages fits into list
	const struct last_msg_data const data[LAST_MSG_LIST_DEFAULT_LEN] = {
		{2122121211, "topic01"},
		{7987643, "topic02"},
		{31376874354, "topic03"},
		{497973144, "topic04"},
	};
	for(size_t i = 0; i < LAST_MSG_LIST_DEFAULT_LEN; i++)
		update_last_msg(&list,data[i].topic, strlen(data[i].topic), data[i].ts);

	ck_assert_uint_eq(list.alloc_size, LAST_MSG_LIST_DEFAULT_LEN);
}

START_TEST(update_test2) {
	// To check that the list expands memory when messages does NOT fit into it
#define LEN (LAST_MSG_LIST_DEFAULT_LEN + 1)
	const struct last_msg_data const data[LEN] = {
		{2122121211, "topic01"},
		{7987643, "topic02"},
		{31376874354, "topic03"},
		{497973144, "topic04"},
		{13234676, "topic05"},
	};
	for(size_t i = 0; i < LEN; i++)
		update_last_msg(&list, data[i].topic, strlen(data[i].topic), data[i].ts);

	ck_assert_uint_eq(list.alloc_size, LAST_MSG_LIST_DEFAULT_LEN * 2);

	for(size_t i = LEN; i < list.alloc_size; i++) {
		ck_assert_uint_eq(list.messages[i].time_stamp, 0);
		ck_assert_ptr_ne(list.messages[i].topic, NULL);
		ck_assert_str_eq(list.messages[i].topic, "");
	}
}

START_TEST(update_test3) {
	// check that time stamp is really updated
	const struct last_msg_data const data[] = {
		{2122121211, "topic"},
		{7987643, "topic1"},
		{31376874354, "topic"},
		{497973144, "topic1"},
		{13234676, "topic"},
		{3656469, "topic1"},
		{798139, "topic"},
		{987979864646, "topic1"},
	};
	for (size_t i = 0; i < (sizeof(data) / sizeof(*data)); i++) {
		size_t t_len = strlen(data[i].topic);
		update_last_msg(&list, data[i].topic, t_len, data[i].ts);
	}
	ck_assert_uint_eq(list.messages[0].time_stamp, 798139);
	ck_assert_str_eq(list.messages[0].topic, "topic");
	ck_assert_uint_eq(list.messages[1].time_stamp, 987979864646);
	ck_assert_str_eq(list.messages[1].topic, "topic1");
	ck_assert_uint_eq(list.alloc_size, LAST_MSG_LIST_DEFAULT_LEN);
	// the rest of the messages should be untouched
	for(size_t i = LAST_MSG_LIST_DEFAULT_LEN - 2; i < LAST_MSG_LIST_DEFAULT_LEN;
			i++) {
		ck_assert_uint_eq(list.messages[i].time_stamp, 0);
		ck_assert_str_eq(list.messages[i].topic, "");
	}
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("last_msg_list");

	TCase *basic_case = tcase_create("basic case");
	tcase_add_checked_fixture(basic_case, setup,
		teardown);

	tcase_add_test(basic_case, init_test);
	tcase_add_test(basic_case, update_test);
	tcase_add_test(basic_case, update_test1);
	tcase_add_test(basic_case, update_test2);
	tcase_add_test(basic_case, update_test3);

	suite_add_tcase(suite, basic_case);

	unittests_add_suite(suite);
}
