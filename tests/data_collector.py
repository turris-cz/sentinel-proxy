#!/usr/bin/env python3

import argparse
import zmq
import time
import random
import string


def run(socket):
    with zmq.Context() as context, context.socket(zmq.PUSH) as zmq_sock:
        zmq_sock.connect(socket)
        while True:
            # first = bytes([random.choice(string.ascii_letters.encode()) for _ in range(5)])
            first = b"sentinel/collect/data-collector-01"
            second = bytes([random.choice(string.ascii_letters.encode()) for _ in range(5)])
            print(f"sending data: {first}, {second}")
            zmq_sock.send_multipart([first, second])
            time.sleep(3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--socket", dest="socket_path",
        default="ipc:///tmp/sentinel_pull.sock",
        type=str, help="set the socket path"
    )
    options = parser.parse_args()
    print("Data collector running on socket: ", options.socket_path)
    run(options.socket_path)


if __name__ == "__main__":
    main()
