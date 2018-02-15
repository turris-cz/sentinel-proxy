/* Copyright (C) 2018 CZ.NIC, z.s.p.o.
*
* This is free software, licensed under the GNU General Public License v2.
*
* 
* Just a very thin C++ wrapper of C-style paho.mqtt.c functions.
* We didn't want to use paho.mqtt.cpp - it's another package and another shared library and it doesn't provide much extra...
*/

#ifndef __INCLUDE_MQTT_HPP__
#define __INCLUDE_MQTT_HPP__

#include <unistd.h>
#include "MQTTClient.h"
#include "MQTTClientPersistence.h"

#define DEFAULT_QOS 0

class MqttTlsClient{
public:
    MqttTlsClient(const char * server, const char * user_id, const char * server_cert, const char * client_cert, const char * client_key){
        conn_opts = MQTTClient_connectOptions_initializer;
        ssl_opts = MQTTClient_SSLOptions_initializer;
        conn_opts.keepAliveInterval = 60;
        conn_opts.reliable = 0;
        conn_opts.cleansession = 1;
        ssl_opts.enableServerCertAuth = 1;
        ssl_opts.trustStore = server_cert;
        ssl_opts.keyStore = client_cert;
        ssl_opts.privateKey = client_key;
        conn_opts.ssl = &ssl_opts;
        MQTTClient_create(&client, server, user_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
        reconnect_wait=0;
    }
    ~MqttTlsClient(){
        MQTTClient_destroy(&client);
    }
    void connect(){
        MQTTClient_connect(client, &conn_opts);
    }
    void disconnect(){
        MQTTClient_disconnect(client, 0);
    }
    bool is_connected(){
        return MQTTClient_isConnected(client);
    }
    void reconnect(void){
        sleep(1+reconnect_wait);
        connect();
        if (is_connected()) reconnect_wait=0;
        else if(reconnect_wait<=1024) reconnect_wait*=2;
    }
    void publish(const char * topic, char * buffer, size_t buffer_len, int qos=DEFAULT_QOS){
        MQTTClient_publish(client, topic, buffer_len, buffer, qos, 0, NULL);
    }
private:
    MQTTClient client;
    MQTTClient_connectOptions conn_opts;
    MQTTClient_SSLOptions ssl_opts;
    int reconnect_wait;
};

#endif /*__INCLUDE_MQTT_HPP__*/
