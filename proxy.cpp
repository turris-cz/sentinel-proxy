#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstring>
#include "zmq.hpp"
#include "zlib.h"
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include "mqtt.hpp"

#define MAX_MSG_SIZE 1024*1024*2
#define MAX_WAITING_MESSAGES 50
//0 is no compression, 1 is lowest (fastest) compression, 9 is biggest (slowest) compression, 6 is default
#define COMPRESS_LEVEL 9

using namespace std;

string get_name_from_cert(const char * filename){
    //get alternative name from X509 certificate
    //this code is ugly, I admit it - but if somebody know how to write not ugly OpenSSL code - I would like to hear it
    string ret;
    X509 *cert = NULL;
    FILE *fp = fopen(filename, "r");
    if (!fp) return ret;
    PEM_read_X509(fp, &cert, NULL, NULL);
    fclose(fp);
    //maybe do some aditional checks if it's sentinel CA? check issuer?
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    san_names = (stack_st_GENERAL_NAME*)X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) return ret;
    int san_names_nb = sk_GENERAL_NAME_num(san_names);
    if (san_names_nb!=1) return ret; //we don't expect more than 1 subject alternative name
    const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, 0);
    ret.assign((const char*)ASN1_STRING_data(current_name->d.dNSName));
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    X509_free(cert);
    return ret;
}

bool zmq_msg_has_more_parts(zmq::socket_t& sock){
    int more;
    size_t size = sizeof(int);
    sock.getsockopt(ZMQ_RCVMORE, &more, &size);
    return (more!=0);
}

bool is_prefix(const string & prefix, const string & str){
    auto res = mismatch(prefix.begin(), prefix.end(), str.begin());
    if (res.first == prefix.end()) return true;
    return false;
}

void compress_input(const char * in_buf, unsigned long in_len, unsigned char * out_buf, unsigned long & out_len){
    int rc = compress2(out_buf, &out_len, (const unsigned char*)in_buf, in_len, COMPRESS_LEVEL);
    if (rc != Z_OK){
        cerr << "compress return code: " << rc << endl;
        out_len=0;
    }
}

int main(int argc, char* argv[]){
    //TODO: default values must be adjusted
    const char * upstream_srv = (argc>1)?argv[1]:"ssl://sentinel.turris.cz:1883";
    const char * local_socket = (argc>2)?argv[2]:"ipc:///tmp/sentinel_pull.sock";
    const char * server_cert_file = (argc>3)?argv[3]:"dev-ca/keys/ca.crt";
    const char * client_cert_file = (argc>4)?argv[4]:"dev-ca/keys/dev-martin-petracek.crt";
    const char * client_priv_key_file = (argc>5)?argv[5]:"dev-ca/keys/dev-martin-petracek.key";
    cerr << "connecting to " << upstream_srv << ", listening on " << local_socket << endl;
    cerr << "server certificate " << server_cert_file << ", client certificate" << client_cert_file << ", client private key " << client_priv_key_file << endl;
    const string cert_name=get_name_from_cert(client_cert_file);
    if (cert_name.empty()) {
        cerr << "can't get name from the certificate - or file not found" << endl;
        return 1;
    }
    cerr << "got name from certificate: " << cert_name << endl;
    zmq::context_t context(1);
    zmq::socket_t receiver(context,ZMQ_PULL);
    const int64_t max_size=MAX_MSG_SIZE;
    receiver.setsockopt(ZMQ_MAXMSGSIZE, &max_size, sizeof(max_size));
    const int max_waiting_messages=MAX_WAITING_MESSAGES;
    receiver.setsockopt(ZMQ_RCVHWM, &max_waiting_messages, sizeof(max_waiting_messages));
    receiver.bind(local_socket);
    MqttTlsClient client(upstream_srv, cert_name.c_str(), server_cert_file, client_cert_file, client_priv_key_file);
    const string topic_to_check="sentinel/collect/";
    const string topic_to_send=topic_to_check+cert_name+'/';
    //zlib doc: "Upon entry, destLen is the total size of the destination buffer, which must be at least 0.1% larger than sourceLen plus 12 bytes."
    const size_t compressed_buf_len = MAX_MSG_SIZE*1.001+12+1;
    unsigned char * compressed_buf=new unsigned char[compressed_buf_len];
    client.connect();
    fprintf(stderr, "connected\n");
    for(;;){
        zmq::message_t msg_topic;
        receiver.recv(&msg_topic);
        if (!zmq_msg_has_more_parts(receiver)) {
            cerr << "received ZMQ message consisting of just one part, ignoring it" << endl;
            continue;
        }
        zmq::message_t msg_payload;
        receiver.recv(&msg_payload);
        if (!msg_payload.size()) continue;
        string t_recvd((char*)msg_topic.data(), msg_topic.size());
        if (!is_prefix(topic_to_check, t_recvd)) {
            cerr << "topic prefix doesn't match, ignoring the message" << endl;
            continue;
        }
        string t = topic_to_send;
        t.append(t_recvd, topic_to_check.size(), string::npos);
        while (!client.is_connected()){
            cerr << "not connected to server, reconnecting..." << endl;
            client.reconnect();
        }
        unsigned long compressed_len = compressed_buf_len;
        compress_input((char*)msg_payload.data(), msg_payload.size(), compressed_buf, compressed_len);
        if (!compressed_len) continue;
        client.publish(t.c_str(), (char*)compressed_buf, compressed_len);
        cout << "publishing with topic " << t.c_str() << endl;
        cout << "received size " << msg_payload.size() << ", compressed size "<< compressed_len << endl;
    }
    client.disconnect();
    delete [] compressed_buf;
    return 0;
}
