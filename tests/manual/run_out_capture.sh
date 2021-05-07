#!/bin/sh

host="localhost"
cert_file="self_sign_certs/smash.pem"
# cert_file="ca1_certs/smash.pem"
# cert_file="ca2_certs/smash.pem"
topic="sentinel/collect/+/+/+"
port="9099"
key="keys/smash.pem"

./output_capture.py \
	--hostname $host \
	--cert-file $cert_file \
	--topic $topic \
	--port $port \
	--key-file $key
