#!/bin/sh

topic="sentinel/collect/generator$$"
socket="ipc:///tmp/proxy_input.sock"

./input_generator.py \
	--socket $socket \
	--topic $topic
