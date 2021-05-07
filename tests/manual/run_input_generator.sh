#!/bin/sh
topic="sentinel/collect/generator$$"
./input_generator.py \
	--socket ipc:///tmp/sentinel_pull.sock \
	--topic $topic
