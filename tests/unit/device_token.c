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

#include <stdlib.h>
#include <check.h>
#include <device_token.h>

static char *t;

static void setup() {
	t = device_token_generate();
}

static void teardown() {
	free(t);
}

START_TEST(generate_test) {
	ck_assert_ptr_ne(t, NULL);
	ck_assert_uint_eq(strlen(t), DEVICE_TOKEN_LEN);
	for(size_t i = 0; i < DEVICE_TOKEN_LEN; i++)
		ck_assert(((t[i] >= '0') && (t[i] <= '9')) ||
					((t[i] >= 'a') && (t[i] <= 'f')));
}

START_TEST(verify_valid_test) {
	ck_assert_uint_eq(device_token_verify(t), DT_OK);
}

START_TEST(verify_failed_undefined_test) {
	ck_assert_uint_eq(device_token_verify(NULL), DT_UNDEF);
}


START_TEST(verify_failed_length_test1) {
	ck_assert_uint_eq(device_token_verify(""), DT_LENGTH);
}

START_TEST(verify_failed_length_test2) {
	ck_assert_uint_eq(device_token_verify("\0\t54"), DT_LENGTH);
}

START_TEST(verify_failed_length_test3) {
	// dt has invalid length
#define LEN (DEVICE_TOKEN_LEN + 1 + 1)
	char t[LEN];
	memset(t, 'a', LEN);
	t[LEN - 1] = '\0';
	ck_assert_uint_eq(device_token_verify(t), DT_LENGTH);
}

START_TEST(verify_failed_decode_test) {
	// dt has invalid character - allowed is 0-9 and a-f - ONLY LOWERCASE !!!
	t[1] = 'Q';
	ck_assert_uint_eq(device_token_verify(t), DT_DECODE);
}

START_TEST(verify_failed_crc_test1) {
	// dt string consist of random bytes and crc bytes 
	// this is valid device token
	char dt[] = "7308d293c4f8385976dc946588b7ae3ebf1b5dec0f4c4da3aee504a3ba5494f4";
	// here we tamper random bytes
	dt[0] = 'a';
	ck_assert_uint_eq(device_token_verify(dt), DT_CRC);

}

START_TEST(verify_failed_crc_test2) {
	// dt string consist of random bytes and crc bytes 
	// this is valid device token
	char dt[] = "7308d293c4f8385976dc946588b7ae3ebf1b5dec0f4c4da3aee504a3ba5494f4";
	// here we tamper crc bytes
	dt[DEVICE_TOKEN_LEN - 1] = '0';
	ck_assert_uint_eq(device_token_verify(dt), DT_CRC);
}

struct state_msg {
	enum dt_state s;
	const char *msg;
};

static const struct state_msg state_messages[DT_NUM_STATES] = {
	{DT_OK, "device_token check passed"},
	{DT_UNDEF, "device_token must be specified"},
	{DT_LENGTH, "device_token must be 64 characters long"},
	{DT_DECODE, "device_token must consist of lowercase hexachars"},
	{DT_CRC, "device_token crc check failed"},
};

START_TEST(get_state_message_valid_test) {
	ck_assert_str_eq(device_token_state_msg(state_messages[_i].s),
		state_messages[_i].msg);
}

static const int invalid_dt_states[] = {DT_OK - 5, DT_OK - 1, DT_NUM_STATES,
	DT_NUM_STATES + 5};

START_TEST(get_state_message_invalid_test) {
	ck_assert_ptr_eq(device_token_state_msg(invalid_dt_states[_i]), NULL);
}

void unittests_add_suite(Suite*);

__attribute__((constructor))
static void suite() {
	Suite *suite = suite_create("device_token");

	TCase *basic_tc = tcase_create("basic");
	tcase_add_checked_fixture(basic_tc, setup, teardown);

	tcase_add_test(basic_tc, generate_test);
	tcase_add_test(basic_tc, verify_valid_test);

	tcase_add_test(basic_tc, verify_failed_undefined_test);
	tcase_add_test(basic_tc, verify_failed_length_test1);
	tcase_add_test(basic_tc, verify_failed_length_test2);
	tcase_add_test(basic_tc, verify_failed_length_test3);
	tcase_add_test(basic_tc, verify_failed_decode_test);

	tcase_add_test(basic_tc, verify_failed_crc_test1);
	tcase_add_test(basic_tc, verify_failed_crc_test2);


	tcase_add_loop_test(basic_tc, get_state_message_valid_test, 0,
		sizeof(state_messages) / sizeof(*state_messages));

	tcase_add_loop_test(basic_tc, get_state_message_invalid_test, 0,
		sizeof(invalid_dt_states) / sizeof(*invalid_dt_states));

	suite_add_tcase(suite, basic_tc);

	unittests_add_suite(suite);
}
