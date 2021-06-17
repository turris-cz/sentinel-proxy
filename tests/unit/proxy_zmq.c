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

#include "../../proxy/common.h"
#include "../../proxy/proxy_zmq.h"

struct msg {
	size_t frames;
	char *topic;
	size_t topic_len;
};

#define t1 TOPIC_PREFIX "a"
#define t2 TOPIC_PREFIX "gjahhiusjajshysygsgs"
#define t3 TOPIC_PREFIX "sadsdSfsSSd/fsdf/sdJfsdafsdafsdfbnhmjh/k6jhk435hk4545s4fd4h2s4d2sdshdcC as  A JCHS AsjcasasA S JHsJ /ASDA JDska SD shda AD Shd jalsd,asdkKLASKLaKLD2Y873D S A;;Ajs;lHALDH SKG AGjshg kHAGDJHGASJG DJKASGDJHG AJKSDGGJSDlkHLHd;l'afjdlasdfjhsdjf"

static struct msg valid_msgs[] = {
	{1, t1, strlen(t1)},
	{1, t2, strlen(t2)},
	{1, t3, strlen(t3)},
	{2, t1, strlen(t1)},
	{2, t2, strlen(t2)},
	{2, t3, strlen(t3)},
};

START_TEST(check_msg_test_valid) {
	ck_assert_int_eq(check_msg(valid_msgs[_i].frames,
		valid_msgs[_i].topic, valid_msgs[_i].topic_len), 0);
}

#define t_inv1 "sentinel/collect"
#define t_inv2 "axasfdgfh"
#define t_inv3 TOPIC_PREFIX "sadsddsdsSSd/fsdf/sdJfsdafsdafsdfbnhmjh/k6jhk435hk4545s4fd4h2s4d2sdshdcC as  A JCHS AsjcasasA S JHsJ /ASDA JDska SD shda AD Shd jalsd,asdkKLASKLaKLD2Y873D S A;;Ajs;lHALDH SKG AGjshg kHAGDJHGASJG DJKASGDJHG AJKSDGGJSDlkHLHd;l'afjdlasdfjhsdjf"

static struct msg invalid_msgs[] = {
	// wrong frames
	{0, t1, strlen(t1)},
	{3, t1, strlen(t1)},
	// wrong topic
	{1, TOPIC_PREFIX, strlen(TOPIC_PREFIX)},
	{1, t_inv1, strlen(t_inv1)},
	{1, t_inv2, strlen(t_inv2)},
	{1, NULL, 0},
	{2, t_inv3, strlen(t_inv3)},
};

START_TEST(check_msg_test_invalid) {
	ck_assert_int_eq(check_msg(invalid_msgs[_i].frames,
		invalid_msgs[_i].topic, invalid_msgs[_i].topic_len), -1);
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("proxy_zmq");
	
	TCase *check_msg_tc = tcase_create("check_msg");
	tcase_add_loop_test(check_msg_tc, check_msg_test_valid, 0,
		sizeof(valid_msgs) / sizeof(*valid_msgs));
	tcase_add_loop_test(check_msg_tc, check_msg_test_invalid, 0,
		sizeof(invalid_msgs) / sizeof(*invalid_msgs));
	suite_add_tcase(suite, check_msg_tc);

	unittests_add_suite(suite);
}

