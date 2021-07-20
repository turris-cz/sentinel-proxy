/*
 *  Turris:Sentinel Device Token - Sentinel Device Token CLI utility tool
 *  Copyright (C) 2020 - 2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <stdbool.h>
#include <stdlib.h>
#include <argp.h>
#include <device_token.h>

enum actions {
	NO_ACTION,
	CREATE,
	VALIDATE
};

struct conf {
	enum actions action;
	char *device_token;
	bool quiet;
};

static const char const *doc = "Sentinel Device Token - Device Token CLI utility"
	" tool\n\nDevice token is 64 hex character long string used to uniquely and "
	"anonymously identify a user of Turris Sentinel for purposes of following provided"
	" services.\n\nThis tool serves as generator and validator of a device token.";
static const struct argp_option options[] = {
	{"create", 'c', NULL, 0,
		"Create new device token and print it to stdout"},
	{"validate", 'v', "device_token", 0,
		"Validate passed device token. Return 0 on success and apropriate error"
		" code otherwise. Also print the validation status message to stdout"},
	{"quiet", 'q', NULL, 0,
		"Enable quiet mode - do NOT print validation status message"},
	{NULL}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct conf *c = (struct conf *)state->input;
	switch (key) {
		case 'c':
			c->action = CREATE;
			break;
		case 'v':
			c->action = VALIDATE;
			c->device_token = arg;
			break;
		case 'q':
			c->quiet = true;
			break;
		default:
		  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	struct conf conf = {
		.action = NO_ACTION
	};
	struct argp argp = {
		.options = options,
		.parser = parse_opt,
		.doc = doc
	};
	argp_parse(&argp, argc, argv, 0, 0, &conf);
	char *device_token;
	enum dt_state verification_status;
	switch(conf.action) {
		case CREATE:
			device_token = device_token_generate();
			printf("%s\n", device_token);
			free(device_token);
			break;
		case VALIDATE:
			verification_status = device_token_verify(conf.device_token);
			if (!conf.quiet)
				fprintf(stderr, "%s\n",
						device_token_state_msg(verification_status));
			return (int)verification_status;
	}
	return 0;
}
