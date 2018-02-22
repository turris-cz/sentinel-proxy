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
//0 is no compression, 1 is lowest (fastest) compression, 9 is biggest (slowest) compression, 6 is default
#define COMPRESS_LEVEL 9
//QoS levels - see here: https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels
#define MQTT_QOS 0

MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
int mqtt_reconnect_wait = 0;

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

void mqtt_setup(const char * server_cert, const char * client_cert, const char * client_key){
    conn_opts.keepAliveInterval = 60;
    conn_opts.reliable = 0;
    conn_opts.cleansession = 1;
    ssl_opts.enableServerCertAuth = 1;
    ssl_opts.trustStore = server_cert;
    ssl_opts.keyStore = client_cert;
    ssl_opts.privateKey = client_key;
    conn_opts.ssl = &ssl_opts;
}

void mqtt_try_reconnect(MQTTClient * client){
    sleep(1+mqtt_reconnect_wait);
    MQTTClient_connect(*client, &conn_opts);
    if (MQTTClient_isConnected(*client)) mqtt_reconnect_wait=0;
    else if(mqtt_reconnect_wait<=1024) mqtt_reconnect_wait*=2;
}

int main(int argc, char* argv[]){
    //TODO: default values must be adjusted
    const char * upstream_srv = (argc>1)?argv[1]:"ssl://sentinel.turris.cz:1883";
    const char * local_socket = (argc>2)?argv[2]:"ipc:///tmp/sentinel_pull.sock";
    const char * server_cert_file = (argc>3)?argv[3]:"dev-ca/keys/ca.crt";
    const char * client_cert_file = (argc>4)?argv[4]:"dev-ca/keys/dev-martin-petracek.crt";
    const char * client_priv_key_file = (argc>5)?argv[5]:"dev-ca/keys/dev-martin-petracek.key";
    printf("connecting to %s, listening on %s\n", upstream_srv, local_socket);
    printf("server certificate %s, client certificate %s, client private key %s\n", server_cert_file, client_cert_file, client_priv_key_file);
    char * cert_name=get_name_from_cert(client_cert_file);
    if (!cert_name) {
        fprintf(stderr, "can't get name from the certificate - or file not found\n");
        return 1;
    }
    printf("got name from certificate: %s\n", cert_name);
    MQTTClient client;
    mqtt_setup(server_cert_file, client_cert_file, client_priv_key_file);
    MQTTClient_create(&client, upstream_srv, cert_name, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    zsock_t *receiver = zsock_new (ZMQ_PULL);
    zsock_set_maxmsgsize(receiver, MAX_MSG_SIZE);
    zsock_set_rcvhwm(receiver, MAX_WAITING_MESSAGES);
    zsock_bind(receiver, "%s", local_socket);
    const char * topic_to_check="sentinel/collect/";
    //zlib doc: "Upon entry, destLen is the total size of the destination buffer, which must be at least 0.1% larger than sourceLen plus 12 bytes."
    const unsigned int compressed_buf_len = MAX_MSG_SIZE*1.001+12+1;
    unsigned char * compressed_buf=(unsigned char*)malloc(compressed_buf_len);
    const unsigned int topic_buf_len = MAX_TOPIC_LEN;
    char * topic_buf=(char*)malloc(topic_buf_len);
    strcpy(topic_buf, topic_to_check);
    strcpy(topic_buf+strlen(topic_to_check), cert_name);
    topic_buf[strlen(topic_to_check)+strlen(cert_name)]='/';
    const unsigned int topic_prefix_len=strlen(topic_to_check)+strlen(cert_name)+1;
    topic_buf[MAX_TOPIC_LEN-1]=0;
    char * topic_buf_pos = topic_buf+topic_prefix_len;
    MQTTClient_connect(client, &conn_opts);
    for(;;){
        unsigned long compressed_len;
        zmsg_t * msg = zmsg_recv (receiver);
        if (!msg) break;
        zframe_t * msg_topic = zmsg_first(msg);
        zframe_t * msg_payload = zmsg_last(msg);
        if (!msg_topic || !msg_payload){
            fprintf(stderr, "received ZMQ message with less parts then expected (expected 2) -> ignoring it\n");
            goto loop_end;
        }
        if (zframe_size(msg_topic)<strlen(topic_to_check) || strncmp(topic_to_check, zframe_data(msg_topic), strlen(topic_to_check))!=0) {
            fprintf(stderr, "topic prefix %.*s doesn't match, ignoring the message -> ignoring it\n", (int)zframe_size(msg_topic), zframe_data(msg_topic));
            goto loop_end;
        }
        if (zframe_size(msg_topic) >= MAX_TOPIC_LEN-topic_prefix_len-1){
            fprintf(stderr, "topic too long -> ignoring it\n");
            goto loop_end;
        }
        strncpy(topic_buf_pos, zframe_data(msg_topic)+strlen(topic_to_check), zframe_size(msg_topic)-strlen(topic_to_check));
        topic_buf_pos[zframe_size(msg_topic)-strlen(topic_to_check)]=0;
        while (!MQTTClient_isConnected(client)){
            fprintf(stderr, "not connected to server, reconnecting...\n");
            mqtt_try_reconnect(&client);
        }
        compressed_len = compressed_buf_len;
        compress_input(zframe_data(msg_payload), zframe_size(msg_payload), compressed_buf, &compressed_len);
        if (!compressed_len) {
            fprintf(stderr, "compress produced 0 bytes\n");
            continue;
        }
        MQTTClient_publish(client, topic_buf, compressed_len, (char*)compressed_buf, MQTT_QOS, 0, NULL);
        printf("publishing with topic %s\n", topic_buf);
    loop_end:
        zmsg_destroy(&msg);
    }
    MQTTClient_disconnect(client, 0);
    MQTTClient_destroy(&client);
    zsock_destroy (&receiver);
    free(compressed_buf);
    free(topic_buf);
    free(cert_name);
    return 0;
}
