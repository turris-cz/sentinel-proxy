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

#include "../../proxy/con_peer_list.h"

static struct con_peer_list con_peer_list;

static void setup() {
	init_con_peer_list(&con_peer_list);
}

static void teardown() {
	destroy_con_peer_list(&con_peer_list);
}

struct peer {
	int fd;
	char *topic;
};

START_TEST(init_test) {
	ck_assert_int_eq(con_peer_list.alloc_size, CON_PERR_LIST_DEFAULT_LEN);
	ck_assert_ptr_ne(con_peer_list.peers, NULL);
}

const struct peer peers[] = {
	{1, "aadasds"},
	{2, "jljljlkjlkjlkj"},
	{3, "wqewrwerwer"},
	{4, "poipjljlfjsldjflsjdfk"},
	{5, "advavdnbavsndvansdvnasvd"},
	{6, "pibvzhwidqd,d"},
	{7, "g"},
	{8, "asds"},
	{9, "asdadajvb vdvzdsv"},
};

START_TEST(add_test) {
	for(size_t i = 0; i < (sizeof(peers) / sizeof(*peers)); i++) {
		// add peer 
		size_t t_len = strlen(peers[i].topic);
		add_peer(&con_peer_list, peers[i].fd, peers[i].topic, t_len);

		// find peer in the list
		bool is_there = false;
		size_t j = 0;
		for(; j < con_peer_list.alloc_size; j++) {
			if (peers[i].fd == con_peer_list.peers[j].fd) {
				is_there = true;
				break;
			}
		}
		if (is_there) {
			// check the peer
			ck_assert_int_eq(con_peer_list.peers[j].fd, peers[i].fd);
			ck_assert_mem_eq(con_peer_list.peers[j].topic, peers[i].topic, t_len);
		} else {
			ck_assert(false);
		}
	}
}

START_TEST(add_test2) {
	// To check that there is no new allocation when peers fits into list
	const struct peer peers[CON_PERR_LIST_DEFAULT_LEN] = {
		{1, "aadasds"},
		{2, "jljljlkjlkjlkj"},
		{3, "wqewrwerwer"},
		{4, "poipjljlfjsldjflsjdfk"},
	};
	for(size_t i = 0; i < CON_PERR_LIST_DEFAULT_LEN; i++)
		add_peer(&con_peer_list, peers[i].fd, peers[i].topic,
			strlen(peers[i].topic));

	ck_assert_uint_eq(con_peer_list.alloc_size, CON_PERR_LIST_DEFAULT_LEN);
}

START_TEST(add_test3) {
	// To check that the list expands memory when peers does NOT fit into it
#define LEN (CON_PERR_LIST_DEFAULT_LEN + 1)
	const struct peer peers[LEN] = {
		{1, "aadasds"},
		{2, "jljljlkjlkjlkj"},
		{3, "wqewrwerwer"},
		{4, "poipjljlfjsldjflsjdfk"},
		{5, "advavdnbavsndvansdvnasvd"},
	};
	for(size_t i = 0; i < LEN; i++)
		add_peer(&con_peer_list, peers[i].fd, peers[i].topic,
			strlen(peers[i].topic));

	ck_assert_uint_eq(con_peer_list.alloc_size, CON_PERR_LIST_DEFAULT_LEN * 2);

	for(size_t i = LEN; i < con_peer_list.alloc_size; i++) {
		ck_assert_int_eq(con_peer_list.peers[i].fd, -1);
		ck_assert_ptr_ne(con_peer_list.peers[i].topic, NULL);
	}
}

START_TEST(del_test) {
	// add peers
	for(size_t i = 0; i < (sizeof(peers) / sizeof(*peers)); i++)
		add_peer(&con_peer_list, peers[i].fd, peers[i].topic,
			strlen(peers[i].topic));
	// delete peers
	for(size_t i = 0; i < (sizeof(peers) / sizeof(*peers)); i++) {
		int fd = peers[i].fd;
		del_peer(&con_peer_list, fd);
		// check that fd is not in the list
		for(size_t j = 0; j < con_peer_list.alloc_size; j++)
			ck_assert_int_ne(fd, con_peer_list.peers[i].fd);
	}
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("con_peer_list");

	TCase *basic_case = tcase_create("basic case");
	tcase_add_checked_fixture(basic_case, setup,
		teardown);

	tcase_add_test(basic_case, init_test);
	tcase_add_test(basic_case, add_test);
	tcase_add_test(basic_case, add_test2);
	tcase_add_test(basic_case, add_test3);
	tcase_add_test(basic_case, del_test);

	suite_add_tcase(suite, basic_case);

	unittests_add_suite(suite);
}
