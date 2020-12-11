#!/usr/bin/env python3

import argparse
import msgpack
import zmq


def parse_msg(msg):
    msg_type = str(msg[0], encoding="UTF-8")
    msg_payload = msgpack.unpackb(msg[1], raw=False)
    return msg_type, msg_payload


def run(socket):
    with zmq.Context() as context, context.socket(zmq.PULL) as zmq_sock:
        zmq_sock.bind(socket)
        while True:
            msg_type, msg_payload = parse_msg(zmq_sock.recv_multipart())
            print(f"{msg_type}: {msg_payload}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--socket", dest="socket_path",
        default="ipc:///tmp/sentinel_pull.sock",
        type=str, help="set the socket path"
    )
    options = parser.parse_args()
    print("Dev proxy running on socket: ", options.socket_path)
    run(options.socket_path)


if __name__ == "__main__":
    main()
