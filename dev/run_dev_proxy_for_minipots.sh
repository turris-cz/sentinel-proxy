#!/bin/bash

minipot_type="$1"

case "$minipot_type" in
	"f")
		minipot_mesg="ftp"
		socket_arg="ipc:///tmp/sentinel_pull1.sock"
		;;
	"h")
		minipot_mesg="http"
		socket_arg="ipc:///tmp/sentinel_pull2.sock"
		;;
	"s")
		minipot_mesg="smtp"
		socket_arg="ipc:///tmp/sentinel_pull3.sock"
		;;
	"t")
		minipot_mesg="telnet"
		socket_arg="ipc:///tmp/sentinel_pull4.sock"
		;;
	"T")
		minipot_mesg="throughput testing"
		socket_arg="ipc:///tmp/sentinel_pull10.sock"
		;;
	*)
		echo "Minipot type $minipot_type is invlaid."
		exit 1
		;;
esac

echo "$minipot_mesg"
echo "------------------------------------------------------------"

./dev_proxy.py -s "$socket_arg"
