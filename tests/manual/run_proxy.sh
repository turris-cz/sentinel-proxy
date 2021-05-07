#!/bin/sh

device_token="c1da24cf9063bf444d66271eb6c2c1b2ae364697ce07d05a8a60d3df08c93f50"
server="localhost"
# NOTE: to run mosquitto.lan as localhost change /etc/hotsts
# server="mosquitto.lan"
port="9099"
zmq_socket_path="ipc:///tmp/proxy_input.sock"
client_cert_file="self_sign_certs/proxy.pem"
# client_cert_file="ca1_certs/proxy.pem"
# client_cert_file="ca2_certs/proxy.pem"
client_key_file="keys/proxy.pem"
ca_cert_file="ca1_certs/ca1.pem"
# ca_cert_file="ca2_certs/ca2.pem"

valgrind \
	--leak-check=full \
	--show-leak-kinds=definite,indirect,possible \
	--track-fds=yes \
	--track-origins=yes \
	--error-exitcode=1 \
	--show-leak-kinds=definite,indirect,possible --track-fds=yes \
	--error-exitcode=1 --track-origins=yes \
../../sentinel-proxy \
	--log-level=-5 \
	--token $device_token \
	--server $server \
	--port $port \
	--zmq-sock $zmq_socket_path \
	--cl-cert $client_cert_file \
	--cl-key $client_key_file \
	--ca-cert $ca_cert_file \
	--disable-serv-check
