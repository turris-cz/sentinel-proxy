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

#include "proxy_conf.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "default.h"


void verify_exists(const char *filename) {
    struct stat tmp;
    if (stat(filename, &tmp) != 0) {
        fprintf(stderr, "%s does not exist\n", filename);
        exit(EXIT_FAILURE);
    }
}

static struct proxy_conf proxy_conf = {
    .upstream_srv = DEFAULT_UPSTREAM_SRV,
    .local_socket = DEFAULT_LOCAL_SOCKET,
    .ca_file = DEFAULT_CA_FILE,
    .client_cert_file = DEFAULT_CERT_FILE,
    .client_key_file = DEFAULT_KEY_FILE,
    .config_file = DEFAULT_CONFIG_FILE,
    .custom_conf_file = false
};

void load_cli_opts(int argc, char *argv[], struct proxy_conf *conf) {
    char opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"server", required_argument, 0, 'S'},
        {"local_socket", required_argument, 0, 's'},
        {"ca", required_argument, 0, 'c'},
        {"cert", required_argument, 0, 'C'},
        {"key", required_argument, 0, 'K'},
        {0, 0, 0, 0}};
    while ((opt = getopt_long(argc, argv, "S:s:", long_options,
                              &option_index)) != (char)-1) {
        switch (opt) {
            case 'S':
                conf->upstream_srv = optarg;
                break;
            case 's':
                conf->local_socket = optarg;
                break;
            case 'c':
                conf->ca_file = optarg;
                break;
            case 'C':
                conf->client_cert_file = optarg;
                break;
            case 'K':
                conf->client_key_file = optarg;
                break;
            default:
                fprintf(
                    stderr,
                    "Usage: %s [-S server] [-s local_socket] [--ca CA_file] "
                    "[--cert cert_file] [--key key_file]\n",
                    argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    fprintf(stderr,
            "CA certificate %s, client certificate %s, client private key %s\n",
            ca_file, client_cert_file, client_key_file);
}

const struct proxy_conf *load_conf(int argc, char *argv[]) {
    // We load cli params first (to get config file path most notably) Then we
    // load config file if exists end is readable. If that is succesfull we have
    // to load cli params once more - since they have higher priority.
    load_cli_opts(argc, argv, &proxy_conf);
    if (is_accessible(proxy_conf.config_file)) {
        load_config_file(proxy_conf.config_file, &proxy_conf);
        load_cli_opts(argc, argv, &proxy_conf);
    } else {
        fprintf(stderr, "WARN: config file %s can't be accessed\n",
                proxy_conf.config_file);
    }

    verify_exists(proxy_conf.ca_file);
    verify_exists(proxy_conf.client_cert_file);
    verify_exists(proxy_conf.client_key_file);

    fprintf(
        stderr,
        "Using CA cert: %s, client cert: %s, client private key: %s\n",
        proxy_conf.ca_file,
        proxy_conf.client_cert_file,
        proxy_conf.client_key_file
    );

	return &proxy_conf;
}
