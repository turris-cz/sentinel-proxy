#!/usr/bin/env python3

import argparse
import ssl
import paho.mqtt.client as paho
import msgpack


def my_argparser(argparser):
    argparser.add_argument("-H", "--hostname",
                           dest="hostname",
                           required=True,
                           type=str,
                           help="Hostname of server to connect to",
                           )
    argparser.add_argument("-p", "--port",
                           dest="port",
                           required=True,
                           type=int,
                           help="Port of server to connect to",
                           )
    argparser.add_argument("-t", "--topic",
                           dest="topic",
                           required=True,
                           type=str,
                           help="Topic to subscribe to",
                           )
    argparser.add_argument("-c", "--cert-file",
                           dest="cert_file",
                           required=True,
                           type=str,
                           help="File with certificate for TLS connection",
                           )
    argparser.add_argument("-k", "--key-file",
                           dest="key_file",
                           required=True,
                           type=str,
                           help="File with key for TLS connection",
                           )

    return argparser


def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT broker")
    client.subscribe(userdata["topic"])


def on_subscribe(client, userdata, mid, granted_qos):
    print("Subscribed to %s topic", userdata["topic"])


def on_disconnect(client, userdata, rc):
    print("Client was disconnected\nReconnecting")
    client.reconnect()


def on_message(client, userdata, msg):
    try:
        data = msgpack.unpackb(msg.payload)
    except (msgpack.exceptions.UnpackException, msgpack.exceptions.ExtraData):
        data = msg.payload
    print(f"On topic:\n{msg.topic}\nReceived:\n{data}")


def main():
    parser = my_argparser(argparse.ArgumentParser())
    options = parser.parse_args()
    client_data = {"topic": options.topic}

    client = paho.Client(client_id="Output capture of Sentinel Proxy")
    client.tls_set(cert_reqs=ssl.CERT_NONE, certfile=options.cert_file,
                   keyfile=options.key_file)
    client.user_data_set(client_data)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    client.connect(options.hostname, options.port)
    client.loop_forever()


if __name__ == "__main__":
    main()
