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
#include <stdbool.h>

static Suite **suites = NULL;
static size_t suites_len = 0, suites_size = 1;

void unittests_add_suite(Suite *s) {
	if (suites == NULL || suites_len == suites_size)
		suites = realloc(suites, (suites_size *= 2) * sizeof *suites);
	suites[suites_len++] = s;
}

int main(void) {
	SRunner *runner = srunner_create(NULL);

	for (size_t i = 0; i < suites_len; i++)
		srunner_add_suite(runner, suites[i]);

	char *test_output_tap = getenv("TEST_OUTPUT_TAP");
	if (test_output_tap && *test_output_tap != '\0')
		srunner_set_tap(runner, test_output_tap);
	char *test_output_xml = getenv("TEST_OUTPUT_XML");
	if (test_output_xml && *test_output_xml != '\0')
		srunner_set_xml(runner, test_output_xml);
	srunner_set_fork_status(runner, CK_NOFORK);

	srunner_run_all(runner, CK_NORMAL);
	int failed = srunner_ntests_failed(runner);

	srunner_free(runner);
	return (bool)failed;
}
