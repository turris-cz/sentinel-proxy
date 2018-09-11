/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <czmq.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <strings.h>
#include <zlib.h>
#include "MQTTClient.h"

#include "const.h"
#include "default.h"

// buffer for compressed data
// zlib doc: "Upon entry, destLen is the total size of the destination
// buffer, which must be at least 0.1% larger than sourceLen plus 12 bytes."
#define COMPRESS_BUF_SIZE ((MAX_MSG_SIZE * 1001) / 1000 + 12 + 1)

#define CHECK_ERR_FATAL(CMD, ...)         \
    do {                                  \
        if (CMD) {                        \
            fprintf(stderr, __VA_ARGS__); \
            exit(EXIT_FAILURE);           \
        }                                 \
    } while (0)

#define CHECK_ERR(CMD, ...)               \
    do {                                  \
        if (CMD) {                        \
            fprintf(stderr, __VA_ARGS__); \
            return;                       \
        }                                 \
    } while (0)

#define MAX_NAME_LEN 64

char *get_name_from_cert(const char *filename) {
    // get common name from subject of X509 certificate
    // this function must return valid name or exit the program
    X509 *cert = NULL;
    FILE *fp = fopen(filename, "r");
    CHECK_ERR_FATAL(!fp, "cannot open certificate file\n");
    PEM_read_X509(fp, &cert, NULL, NULL);
    fclose(fp);
    CHECK_ERR_FATAL(!cert, "cannot read X509 certificate\n");
    // TODO: maybe do some aditional checks if it's sentinel CA? check issuer?
    char *ret = malloc(MAX_NAME_LEN);
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
                              ret, MAX_NAME_LEN);
    X509_free(cert);
    return ret;
}

void verify_exists(const char *filename) {
    struct stat tmp;
    if (stat(filename, &tmp) != 0) {
        fprintf(stderr, "%s does not exist\n", filename);
        exit(EXIT_FAILURE);
    }
}

void mqtt_setup(MQTTClient_connectOptions *conn_opts, const char *server_cert,
                const char *client_cert, const char *client_key) {
    conn_opts->retryInterval = 5;
    conn_opts->keepAliveInterval = MQTT_KEEPALIVE_INTERVAL;
    conn_opts->reliable = 0;
    conn_opts->cleansession = 1;
    conn_opts->ssl->enableServerCertAuth = 1;
    conn_opts->ssl->trustStore = server_cert;
    conn_opts->ssl->keyStore = client_cert;
    conn_opts->ssl->privateKey = client_key;
}

void mqtt_reconnect(MQTTClient client, MQTTClient_connectOptions *conn_opts) {
    int wait_time = 1;
    fprintf(stderr, "not connected to server, reconnecting...\n");
    MQTTClient_connect(&client, conn_opts);
    while (!MQTTClient_isConnected(client)) {
        fprintf(stderr, "...next try in %d seconds...\n", wait_time);
        sleep(wait_time);
        MQTTClient_connect(client, conn_opts);
        if (wait_time <= 1024)
            wait_time *= 2;
    }
    fprintf(stderr, "reconnected\n");
}

void handle_message(MQTTClient client, zmsg_t *msg, char *topic_buf,
                    unsigned topic_prefix_len) {
    static unsigned char compress_buf[COMPRESS_BUF_SIZE];
    CHECK_ERR(zmsg_size(msg) != 2, "ignoring mallformed message (%ld parts)\n",
              zmsg_size(msg));
    zframe_t *topic = zmsg_first(msg);
    unsigned topic_len = zframe_size(topic);
    char *topic_data = (char *)zframe_data(topic);
    zframe_t *payload = zmsg_last(msg);
    CHECK_ERR(topic_len < strlen(TOPIC_PREFIX) ||
                  strncmp(TOPIC_PREFIX, topic_data, TOPIC_PREFIX_LEN) != 0,
              "ignoring invalid topic %.*s\n", topic_len, topic_data);
    CHECK_ERR(topic_len >= MAX_TOPIC_LEN, "ignoring too long topic %.*s\n",
              topic_len, topic_data);
    char *topic_buf_pos = topic_buf + topic_prefix_len;
    strncpy(topic_buf_pos, topic_data + TOPIC_PREFIX_LEN, topic_len);
    topic_buf_pos[topic_len] = 0;
    unsigned long compress_len = COMPRESS_BUF_SIZE;
    int rc = compress2(compress_buf, &compress_len, zframe_data(payload),
                       zframe_size(payload), COMPRESS_LEVEL);
    CHECK_ERR(rc != Z_OK, "compress2 error - result: %d\n", rc);
    MQTTClient_publish(client, topic_buf, compress_len, (char *)compress_buf,
                       MQTT_QOS, 0, NULL);
}

void run_proxy(const char *upstream_srv, const char *local_socket,
               const char *ca_file, const char *client_cert_file,
               const char *client_key_file) {
    // get name from certificate
    char *cert_name = get_name_from_cert(client_cert_file);
    assert(cert_name);
    // TODO: cert_name length should be checked (once its format is fixed)
    fprintf(stderr, "got name from certificate: %s\n", cert_name);
    // prepare topic
    // topic to send is topic_prefix+cert_name+'/'+msg_topic e.g., if
    // topic_prefix is "sentinel/collect/", cert_name is "user" and msg_topic
    // is "flow", topic should be "sentinel/collect/user/flow" we prepare the
    // fixed part (topic_prefix+cert_name+'/') here, just the msg_topic is
    // copied in handle_message.
    unsigned topic_prefix_len = TOPIC_PREFIX_LEN + strlen(cert_name) + 1;
    char *topic_to_send = malloc(topic_prefix_len + MAX_TOPIC_LEN);
    strncpy(topic_to_send, TOPIC_PREFIX, TOPIC_PREFIX_LEN);
    strcpy(topic_to_send + TOPIC_PREFIX_LEN, cert_name);
    topic_to_send[TOPIC_PREFIX_LEN + strlen(cert_name)] = '/';
    topic_to_send[TOPIC_PREFIX_LEN + strlen(cert_name) + 1] = 0;
    // MQTT initialization
    fprintf(stderr, "connecting to %s, listening on %s\n", upstream_srv,
            local_socket);
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
    conn_opts.ssl = &ssl_opts;
    mqtt_setup(&conn_opts, ca_file, client_cert_file, client_key_file);
    MQTTClient_create(&client, upstream_srv, cert_name,
                      MQTTCLIENT_PERSISTENCE_NONE, NULL);
    MQTTClient_connect(client, &conn_opts);
    // ZMQ initialization
    zsock_t *receiver = zsock_new(ZMQ_PULL);
    assert(receiver);
    zsock_set_maxmsgsize(receiver, MAX_MSG_SIZE);
    zsock_set_rcvhwm(receiver, MAX_WAITING_MESSAGES);
    zsock_bind(receiver, "%s", local_socket);
    zpoller_t *poller = zpoller_new(receiver, NULL);
    assert(poller);
    while (true) {
        zpoller_wait(poller, (MQTT_KEEPALIVE_INTERVAL + 1) * 1000);
        if (zpoller_terminated(poller))
            break;
        MQTTClient_yield();
        if (zpoller_expired(poller))
            continue;
        zmsg_t *msg = zmsg_recv(receiver);
        if (!msg)
            continue;
        if (!MQTTClient_isConnected(client))
            mqtt_reconnect(client, &conn_opts);
        handle_message(client, msg, topic_to_send, topic_prefix_len);
        zmsg_destroy(&msg);
    }
    MQTTClient_disconnect(client, 0);
    MQTTClient_destroy(&client);
    zsock_destroy(&receiver);
    zpoller_destroy(&poller);
    free(topic_to_send);
    free(cert_name);
}

int main(int argc, char *argv[]) {
    const char *upstream_srv = DEFAULT_UPSTREAM_SRV;
    const char *local_socket = DEFAULT_LOCAL_SOCKET;
    const char *ca_file = DEFAULT_CA_FILE;
    const char *client_cert_file = DEFAULT_CERT_FILE;
    const char *client_key_file = DEFAULT_KEY_FILE;
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
                upstream_srv = optarg;
                break;
            case 's':
                local_socket = optarg;
                break;
            case 'c':
                ca_file = optarg;
                break;
            case 'C':
                client_cert_file = optarg;
                break;
            case 'K':
                client_key_file = optarg;
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
    verify_exists(ca_file);
    verify_exists(client_cert_file);
    verify_exists(client_key_file);
    run_proxy(upstream_srv, local_socket, ca_file, client_cert_file,
              client_key_file);
    return 0;
}
