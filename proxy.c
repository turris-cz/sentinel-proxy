#include <stdio.h>
#include <czmq.h>
#include "zlib.h"
#include <strings.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include "MQTTClient.h"
#include "MQTTClientPersistence.h"


#define MAX_TOPIC_LEN 256
#define MAX_MSG_SIZE 1024*1024*2
#define MAX_WAITING_MESSAGES 50
//mandatory prefix, that each ZMQ msg (topic) must have (is discarded elsewhere)
#define ZMQ_TOPIC_PREFIX "sentinel/collect/"
//0 is no compression, 1 is lowest (fastest) compression, 9 is biggest (slowest) compression, 6 is default
#define COMPRESS_LEVEL 9
//QoS levels - see here: https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS 0
#define MQTT_KEEPALIVE_INTERVAL 60 //seconds

char * get_name_from_cert(const char * filename){
    //get alternative name from X509 certificate
    //this code is ugly, I admit it - but if somebody know how to write not ugly OpenSSL code - I would like to hear it
    X509 *cert = NULL;
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    PEM_read_X509(fp, &cert, NULL, NULL);
    fclose(fp);
    //maybe do some aditional checks if it's sentinel CA? check issuer?
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    san_names = X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
    if (!san_names) return NULL;
    int san_names_nb = sk_GENERAL_NAME_num(san_names);
    if (san_names_nb!=1) return NULL; //we don't expect more than 1 subject alternative name
    const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, 0);
    char * ret=strdup((const char*)ASN1_STRING_data(current_name->d.dNSName));
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    X509_free(cert);
    return ret;
}

void compress_input(const char * in_buf, unsigned long in_len, unsigned char * out_buf, unsigned long * out_len){
    int rc = compress2(out_buf, out_len, (const unsigned char*)in_buf, in_len, COMPRESS_LEVEL);
    if (rc != Z_OK){
        fprintf(stderr, "compress return code: %d\n", rc);
        *out_len=0;
    }
}

void verify_exists (const char * filename) {
    struct stat tmp;
    if (stat (filename, &tmp) != 0){
        fprintf(stderr, "%s does not exist\n", filename);
        exit(1);
    }
}

void mqtt_setup(MQTTClient_connectOptions * conn_opts, const char * server_cert, const char * client_cert, const char * client_key){
    verify_exists(server_cert);
    verify_exists(client_cert);
    verify_exists(client_key);
    conn_opts->retryInterval = 5;
    conn_opts->keepAliveInterval = MQTT_KEEPALIVE_INTERVAL;
    conn_opts->reliable = 0;
    conn_opts->cleansession = 1;
    conn_opts->ssl->enableServerCertAuth = 1;
    conn_opts->ssl->trustStore = server_cert;
    conn_opts->ssl->keyStore = client_cert;
    conn_opts->ssl->privateKey = client_key;
}

int main(int argc, char* argv[]){
    const char * upstream_srv = (argc>1)?argv[1]:"ssl://sentinel.turris.cz:1883";
    const char * local_socket = (argc>2)?argv[2]:"ipc:///tmp/sentinel_pull.sock";
    const char * server_cert_file = (argc>3)?argv[3]:"/etc/sentinel/keys/ca.crt";
    const char * client_cert_file = (argc>4)?argv[4]:"/etc/sentinel/keys/router.crt";
    const char * client_priv_key_file = (argc>5)?argv[5]:"/etc/sentinel/keys/router.key";
    fprintf(stderr, "connecting to %s, listening on %s\n", upstream_srv, local_socket);
    fprintf(stderr, "server certificate %s, client certificate %s, client private key %s\n", server_cert_file, client_cert_file, client_priv_key_file);
    //get name from certificate
    char * cert_name=get_name_from_cert(client_cert_file);
    //TODO: cert_name length should be checked (once its format is fixed)
    if (!cert_name) {
        fprintf(stderr, "can't get name from the certificate - or file not found\n");
        return 1;
    }
    fprintf(stderr, "got name from certificate: %s\n", cert_name);
    //prepare topic - topic to send is topic_to_check+cert_name+'/'+msg_topic
    //e.g., if topic_to_check is "sentinel/collect/", cert_name is "user" and msg_topic is "flow", topic should be "sentinel/collect/user/flow"
    //we prepare the fixed part (topic_to_check+cert_name+'/') here, just the msg_topic is copied by the recv_handler.
    const char * topic_to_check=ZMQ_TOPIC_PREFIX;
    char topic_to_send[MAX_TOPIC_LEN];
    strcpy(topic_to_send, topic_to_check);
    strcpy(topic_to_send+strlen(topic_to_check), cert_name);
    topic_to_send[strlen(topic_to_check)+strlen(cert_name)]='/';
    topic_to_send[MAX_TOPIC_LEN-1]=0;
    unsigned int topic_to_send_prefix_len=strlen(topic_to_check)+strlen(cert_name)+1; //index where the msg_topic shall be appended
    char * topic_to_send_pos = topic_to_send+topic_to_send_prefix_len;
    //prepare buffer for compressed data - it's quite big, so we allocate it beforehand
    //zlib doc: "Upon entry, destLen is the total size of the destination buffer, which must be at least 0.1% larger than sourceLen plus 12 bytes."
    const size_t compressed_buf_size=((MAX_MSG_SIZE*1001)/1000+12+1);
    unsigned char * compressed_buf=(unsigned char*)malloc(compressed_buf_size);
    //MQTT initialization
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
    conn_opts.ssl = &ssl_opts;
    mqtt_setup(&conn_opts, server_cert_file, client_cert_file, client_priv_key_file);
    MQTTClient_create(&client, upstream_srv, cert_name, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    MQTTClient_connect(client, &conn_opts);
    int mqtt_reconnect_wait = 0;
    //ZMQ initialization
    zsock_t * receiver = zsock_new (ZMQ_PULL);
    assert(receiver);
    zsock_set_maxmsgsize(receiver, MAX_MSG_SIZE);
    zsock_set_rcvhwm(receiver, MAX_WAITING_MESSAGES);
    zsock_bind(receiver, "%s", local_socket);
    zpoller_t * poller = zpoller_new(receiver, NULL);
    assert (poller);
    for(;;){
        zmq_pollitem_t items [] = {{ receiver, 0, ZMQ_POLLIN, 0}};
        zpoller_wait(poller, (MQTT_KEEPALIVE_INTERVAL+1)*1000);
        if (zpoller_terminated(poller)) break;
        if (zpoller_expired(poller)) {
            MQTTClient_yield();
            continue;
        }
        zmsg_t * msg = zmsg_recv(receiver);
        if (!msg) {
            fprintf(stderr, "no msg\n");
            continue;
        }
        if (zmsg_size(msg)!=2){
            fprintf(stderr, "received mallformed ZMQ message (expected 2 parts, got %d parts) -> ignoring it\n", zmsg_size(msg));
            goto recv_end;
        }
        zframe_t * msg_topic = zmsg_first(msg);
        zframe_t * msg_payload = zmsg_last(msg);
        if (zframe_size(msg_topic)<strlen(topic_to_check) || strncmp(topic_to_check, zframe_data(msg_topic), strlen(topic_to_check))!=0) {
            fprintf(stderr, "topic prefix %.*s doesn't match, ignoring the message -> ignoring it\n", (int)zframe_size(msg_topic), zframe_data(msg_topic));
            goto recv_end;
        }
        if (zframe_size(msg_topic) >= MAX_TOPIC_LEN-topic_to_send_prefix_len-1){
            fprintf(stderr, "topic too long -> ignoring it\n");
            goto recv_end;
        }
        strncpy(topic_to_send_pos, zframe_data(msg_topic)+strlen(topic_to_check), zframe_size(msg_topic)-strlen(topic_to_check));
        topic_to_send_pos[zframe_size(msg_topic)-strlen(topic_to_check)]=0;
        unsigned long compressed_len = compressed_buf_size;
        compress_input(zframe_data(msg_payload), zframe_size(msg_payload), compressed_buf, &compressed_len);
        if (!compressed_len) {
            fprintf(stderr, "compress produced 0 bytes\n");
            goto recv_end;
        }
        MQTTClient_yield(); //necessary to notice disconnect
        while (!MQTTClient_isConnected(client)){
            fprintf(stderr, "not connected to server, reconnecting...\n");
            sleep(1+mqtt_reconnect_wait);
            MQTTClient_connect(client, &conn_opts);
            if (MQTTClient_isConnected(client)) mqtt_reconnect_wait=0;
            else if(mqtt_reconnect_wait<=1024) mqtt_reconnect_wait*=2;
        }
        int res=MQTTClient_publish(client, topic_to_send, compressed_len, (char*)compressed_buf, MQTT_QOS, 0, NULL);
        printf("publishing with topic %s - res %d\n", topic_to_send, res);
        recv_end:
            zmsg_destroy(&msg);
    }
    MQTTClient_disconnect(client, 0);
    MQTTClient_destroy(&client);
    zsock_destroy(&receiver);
    zpoller_destroy(&poller);
    free(cert_name);
    free(compressed_buf);
    return 0;
}
