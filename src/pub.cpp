#include <iostream>
#include <cstdlib>
#include <string>
#include <chrono>
#include <algorithm>
#include <cstring>
#include "mqtt/client.h"
#include <zmq.hpp>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

using namespace std;

class callback : public virtual mqtt::callback
{
public:
    void connected(const std::string& cause) override {
        //TODO
    }
    void connection_lost(const std::string& cause) override {
        //TODO
    }
};

std::string get_name_from_cert(const char * filename){
    //get alternative name from X509 certificate
    //this code is ugly, I admit it - but if somebody know how to write not ugly OpenSSL code - I would like to hear it
    std::string ret;
    X509 *cert = NULL;
    FILE *fp = fopen(filename, "r");
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

bool is_prefix(const std::string & prefix, const char * str){
    auto res = std::mismatch(prefix.begin(), prefix.end(), str);
    if (res.first == prefix.end()) return true;
    return false;
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
    const std::string cert_name=get_name_from_cert(client_cert_file);
    if (cert_name.empty()) return 1; //no name in the certificate
    cerr << "got name from certificate: " << cert_name << endl;
    zmq::context_t context(1);
    zmq::socket_t receiver(context,ZMQ_PULL);
    receiver.bind(local_socket);
    mqtt::client client(upstream_srv, cert_name.c_str());
    callback cb;
    client.set_callback(cb);
    mqtt::connect_options connopts;
    mqtt::ssl_options sslopts(server_cert_file, client_cert_file, client_priv_key_file, "", "ALL", true);
    connopts.set_ssl(sslopts);
    const std::string topic_to_check="sentinel/collect/";
    const std::string topic_to_send=topic_to_check+cert_name+'/';
    try {
        client.connect(connopts);
    } catch (const mqtt::exception& exc) {
        cerr << exc.what() << endl;
        return 1;
    }
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
        if (!is_prefix(topic_to_check, (char*)msg_topic.data())) {
            cerr << "topic prefix doesn't match, ignoring the message" << endl;
            continue;
        }
        std::string t = topic_to_send;
        t.append((char*)msg_topic.data()+topic_to_check.size());
        try {
            mqtt::message_ptr pubmsg = mqtt::make_message(t.c_str(), (char*)msg_payload.data(), msg_payload.size());
            pubmsg->set_qos(2);
            client.publish(pubmsg);
        } catch (const mqtt::exception& exc) {
            cerr << "exception when sending message to MQTT: " << exc.what() << ", ignoring the message" << endl;
            continue;
        }
    }
    client.disconnect();
    return 0;
}
