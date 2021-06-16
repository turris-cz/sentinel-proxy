/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <device_token.h>

enum actions {
    NO_ACTION,
    CREATE,
    VALIDATE
};

struct conf {
    enum actions action;
    char device_token[DEVICE_TOKEN_LEN + 1];
    bool quite;
};

static struct conf conf = {
    .action = NO_ACTION,
    .device_token[0] = '\0',
    .quite = false
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'c':
            conf.action = CREATE;
            break;
        case 'v':
            if (conf.action) {
                fprintf(stderr, "Specify either token validation or creation\n");
                argp_usage(state);
            }
            conf.action = VALIDATE;
            strncpy(conf.device_token, arg, DEVICE_TOKEN_LEN + 1);
            break;
        case 'q':
            conf.quite = true;
            break;
        case ARGP_KEY_ARG:
          if (state->arg_num >= 1)
            /* Too many arguments. */
            argp_usage(state);
          break;

        default:
          return ARGP_ERR_UNKNOWN;
        }
    return 0;
}

void parse_args(int argc, char *argv[]) {
    /* Program documentation. */
    static char doc[] = "Sentinel:DeviceToken - Turris:Sentinel Device Token utility";

    static struct argp_option options[] = {
        {"create",   'c', 0,               0, "Create new device token and "
                                              "print it to stdout" },
        {"validate", 'v', "device_token",  0, "Validate existing device token. "
                                              "Return 0 on success. Also print "
                                              "the result to stdout" },
        {"quite",    'q', 0,               0, "Enable quite mode" },
        { 0 }
    };

    /* Our argp parser. */
    static struct argp argp = { options, parse_opt, 0, doc };
    argp_parse(&argp, argc, argv, 0, 0, NULL);
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    char *device_token;
    int verification_status;
    switch(conf.action) {
        case CREATE:
            device_token = device_token_generate();
            printf("%s\n", device_token);
            free(device_token);
            break;
        case VALIDATE:
            verification_status = device_token_verify(conf.device_token);
            if (!conf.quite)
                fprintf(stderr, "%s\n",
                        device_token_state_msg(verification_status));
            return verification_status;
    }
    return 0;
}
