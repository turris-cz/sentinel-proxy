MY_DIR = %reldir%/generated

gen-test-certs:
	rm -rf $(MY_DIR)
	mkdir -p $(MY_DIR)/{keys,self_signed_certs,sign-reqs,ca1/{db,newcerts},ca2/{db,newcerts},ca1_certs,ca2_certs}

	openssl ecparam -genkey -name secp384r1 -out $(MY_DIR)/keys/ca1.pem

	openssl req -new -x509 -config %reldir%/conf/ca1.cnf -days 3650 \
		-key $(MY_DIR)/keys/ca1.pem -out $(MY_DIR)/ca1_certs/ca1.pem
	touch $(MY_DIR)/ca1/db/index.txt
	echo 01 > $(MY_DIR)/ca1/db/serial

	openssl ecparam -genkey -name secp384r1 -out $(MY_DIR)/keys/ca2.pem
	openssl req -new -x509 -config %reldir%/conf/ca2.cnf -days 3650 \
		-key $(MY_DIR)/keys/ca2.pem -out $(MY_DIR)/ca2_certs/ca2.pem
	touch $(MY_DIR)/ca2/db/index.txt
	echo 01 > $(MY_DIR)/ca2/db/serial

	openssl ecparam -genkey -name prime256v1 -out $(MY_DIR)/keys/mosquitto.pem
	openssl req -new -batch -subj '/CN=mosquitto.lan' \
		-key $(MY_DIR)/keys/mosquitto.pem \
		-out $(MY_DIR)/sign-reqs/mosquitto.pem
	openssl ca -config %reldir%/conf/ca1.cnf -batch -extensions server_ext \
		-in $(MY_DIR)/sign-reqs/mosquitto.pem \
		-out $(MY_DIR)/ca1_certs/mosquitto.pem
	openssl ca -config %reldir%/conf/ca2.cnf -batch -extensions server_ext \
		-in $(MY_DIR)/sign-reqs/mosquitto.pem \
		-out $(MY_DIR)/ca2_certs/mosquitto.pem
	openssl x509 -signkey $(MY_DIR)/keys/mosquitto.pem \
		-in $(MY_DIR)/sign-reqs/mosquitto.pem -req -days 365 \
		-out $(MY_DIR)/self_signed_certs/mosquitto.pem

	openssl ecparam -genkey -name prime256v1 -out $(MY_DIR)/keys/proxy.pem
	openssl req -new -batch -subj '/CN=proxy' \
		-key $(MY_DIR)/keys/proxy.pem -out $(MY_DIR)/sign-reqs/proxy.pem
	openssl ca -config %reldir%/conf/ca1.cnf -batch -extensions client_ext \
		-in $(MY_DIR)/sign-reqs/proxy.pem -out $(MY_DIR)/ca1_certs/proxy.pem
	openssl ca -config %reldir%/conf/ca2.cnf -batch -extensions client_ext \
		-in $(MY_DIR)/sign-reqs/proxy.pem -out $(MY_DIR)/ca2_certs/proxy.pem
	openssl x509 -signkey $(MY_DIR)/keys/proxy.pem \
		-in $(MY_DIR)/sign-reqs/proxy.pem -req -days 365 \
		-out $(MY_DIR)/self_signed_certs/proxy.pem

	openssl ecparam -genkey -name prime256v1 -out $(MY_DIR)/keys/smash.pem
	openssl req -new -batch -subj '/CN=smash' \
		-key $(MY_DIR)/keys/smash.pem -out $(MY_DIR)/sign-reqs/smash.pem
	openssl ca -config %reldir%/conf/ca1.cnf -batch -extensions client_ext \
		-in $(MY_DIR)/sign-reqs/smash.pem -out $(MY_DIR)/ca1_certs/smash.pem
	openssl ca -config %reldir%/conf/ca2.cnf -batch -extensions client_ext \
		-in $(MY_DIR)/sign-reqs/smash.pem -out $(MY_DIR)/ca2_certs/smash.pem
	openssl x509 -signkey $(MY_DIR)/keys/smash.pem \
		-in $(MY_DIR)/sign-reqs/smash.pem -req -days 365 \
		-out $(MY_DIR)/self_signed_certs/smash.pem

	rm -rf $(MY_DIR)/{ca1,ca2,sign-reqs}
