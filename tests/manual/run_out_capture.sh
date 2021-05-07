#!/bin/sh
./output_capture.py \
	--hostname \
	localhost \
	`#mosquitto.lan` \
	--cert-file \
	./smash-cert-ca1.pem \
	`#./smash-cert-ca2.pem` \
	--topic sentinel/collect/+/+/+ \
	--port 9099 \
	--key-file ./smash-key.pem
