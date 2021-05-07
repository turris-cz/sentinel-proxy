#!/usr/bin/env python3

import argparse
import zmq
import time
import random
import string


def run(socket, topic):
    with zmq.Context() as context, context.socket(zmq.PUSH) as zmq_sock:
        zmq_sock.connect(socket)
        zmq_sock.send_multipart([topic])
        while True:
            data = bytes([random.choice(string.ascii_letters.encode())
                          for _ in range(random.randint(5, 15))])
            print(f"sending message: {topic}, {data}")
            zmq_sock.send_multipart([topic, data])
            time.sleep(3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--socket",
        dest="socket_path",
        required=True,
        type=str,
        help="Path to ZMQ output socket"
    )
    parser.add_argument(
        "-t", "--topic",
        dest="topic",
        required=True,
        type=str,
        help="topic of generated data"
    )
    options = parser.parse_args()
    print(f"Data collector running on socket: {options.socket_path}")
    print(f"with topic: {options.topic}")
    run(options.socket_path, options.topic.encode())


if __name__ == "__main__":
    main()
