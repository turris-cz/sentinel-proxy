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

START_TEST(recv_data_cb_test_welcome_msg_no_nul) {
	zsock_t *pull = zsock_new(ZMQ_PULL);
	zsock_t *push = zsock_new(ZMQ_PUSH);
	ck_assert_ptr_nonnull(pull);
	ck_assert_ptr_nonnull(push);
	int port = zsock_bind(pull, "tcp://127.0.0.1:*");
	ck_assert_int_gt(port, 0);
	ck_assert_int_eq(zsock_connect(push, "tcp://127.0.0.1:%d", port), 0);

	unsigned char topic[ZMQ_MAX_TOPIC_LEN];
	memcpy(topic, TOPIC_PREFIX, TOPIC_PREFIX_LEN);
	memset(topic + TOPIC_PREFIX_LEN, 'A',
		ZMQ_MAX_TOPIC_LEN - TOPIC_PREFIX_LEN);
	// whole topic must pass check_msg
	ck_assert_int_eq(check_msg(1, topic, sizeof(topic)), 0);

	zframe_t *frame = zframe_new(topic, sizeof(topic));
	ck_assert_ptr_nonnull(frame);
	ck_assert_int_eq(zframe_send(&frame, push, 0), 0);

	// For a single-frame (welcome) message the callback never dereferences
	// its arg, so NULL is safe here.
	ck_assert_int_eq(recv_data_cb(NULL, pull, NULL), 0);

	// The message must have been consumed by the callback - nothing
	// must be left in the socket queue (non-blocking poll returns NULL)
	zpoller_t *poller = zpoller_new(pull, NULL);
	ck_assert_ptr_nonnull(poller);
	ck_assert_ptr_null(zpoller_wait(poller, 0));
	zpoller_destroy(&poller);

	zsock_destroy(&pull);
	zsock_destroy(&push);
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

	TCase *recv_data_cb_tc = tcase_create("recv_data_cb");
	tcase_add_test(recv_data_cb_tc, recv_data_cb_test_welcome_msg_no_nul);
	suite_add_tcase(suite, recv_data_cb_tc);

	unittests_add_suite(suite);
}

