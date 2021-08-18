# NOTE: paths must match CAs configurations in folder ./ca_conf/ 
CONF_DIR = %reldir%/ca_conf
KEYS_DIR = %reldir%/keys
SELF_SIGNED_CERT_DIR = %reldir%/self_sign_certs
CA1_CERTS_DIR = %reldir%/ca1_certs
CA2_CERTS_DIR = %reldir%/ca2_certs
SIGN_REQS_DIR = %reldir%/sign_reqs
CA1_DIR = %reldir%/ca1
CA2_DIR = %reldir%/ca2

clean-test-certs:
	rm -rf $(KEYS_DIR) $(SELF_SIGNED_CERT_DIR) $(CA1_CERTS_DIR) \
		$(CA2_CERTS_DIR) $(CA1_DIR) $(CA2_DIR) $(SIGN_REQS_DIR) 

clean-local: clean-test-certs

gen-test-certs: clean-test-certs
	mkdir -p $(KEYS_DIR) $(SELF_SIGNED_CERT_DIR) $(CA1_CERTS_DIR) \
		$(CA2_CERTS_DIR)  $(SIGN_REQS_DIR) $(CA1_DIR)/{db,newcerts} \
		$(CA2_DIR)/{db,newcerts}

	openssl ecparam -genkey -name secp384r1 -out $(KEYS_DIR)/ca1.pem
	openssl req -new -x509 -config $(CONF_DIR)/ca1.cnf -days 365 \
		-key $(KEYS_DIR)/ca1.pem -out $(CA1_CERTS_DIR)/ca1.pem
	touch $(CA1_DIR)/db/index.txt
	echo 01 > $(CA1_DIR)/db/serial

	openssl ecparam -genkey -name secp384r1 -out $(KEYS_DIR)/ca2.pem
	openssl req -new -x509 -config $(CONF_DIR)/ca2.cnf -days 365 \
		-key $(KEYS_DIR)/ca2.pem -out $(CA2_CERTS_DIR)/ca2.pem
	touch $(CA2_DIR)/db/index.txt
	echo 01 > $(CA2_DIR)/db/serial

	openssl ecparam -genkey -name prime256v1 -out $(KEYS_DIR)/mosquitto.pem
	openssl req -new -batch -subj '/CN=mosquitto.lan' \
		-key $(KEYS_DIR)/mosquitto.pem -out $(SIGN_REQS_DIR)/mosquitto.pem
	openssl ca -config $(CONF_DIR)/ca1.cnf -batch -extensions server_ext \
		-in $(SIGN_REQS_DIR)/mosquitto.pem -out $(CA1_CERTS_DIR)/mosquitto.pem
	openssl ca -config $(CONF_DIR)/ca2.cnf -batch -extensions server_ext \
		-in $(SIGN_REQS_DIR)/mosquitto.pem -out $(CA2_CERTS_DIR)/mosquitto.pem
	openssl x509 -req -days 365 -signkey $(KEYS_DIR)/mosquitto.pem \
		-in $(SIGN_REQS_DIR)/mosquitto.pem \
		-out $(SELF_SIGNED_CERT_DIR)/mosquitto.pem

	openssl ecparam -genkey -name prime256v1 -out $(KEYS_DIR)/proxy.pem
	openssl req -new -batch -subj '/CN=proxy' \
		-key $(KEYS_DIR)/proxy.pem -out $(SIGN_REQS_DIR)//proxy.pem
	openssl ca -config $(CONF_DIR)/ca1.cnf -batch -extensions client_ext \
		-in $(SIGN_REQS_DIR)/proxy.pem -out $(CA1_CERTS_DIR)/proxy.pem
	openssl ca -config $(CONF_DIR)/ca2.cnf -batch -extensions client_ext \
		-in $(SIGN_REQS_DIR)/proxy.pem -out $(CA2_CERTS_DIR)/proxy.pem
	openssl x509 -req -days 365 -signkey $(KEYS_DIR)/proxy.pem \
		-in $(SIGN_REQS_DIR)/proxy.pem -out $(SELF_SIGNED_CERT_DIR)/proxy.pem

	openssl ecparam -genkey -name prime256v1 -out $(KEYS_DIR)/smash.pem
	openssl req -new -batch -subj '/CN=smash' \
		-key $(KEYS_DIR)/smash.pem -out $(SIGN_REQS_DIR)//smash.pem
	openssl ca -config $(CONF_DIR)/ca1.cnf -batch -extensions client_ext \
		-in $(SIGN_REQS_DIR)/smash.pem -out $(CA1_CERTS_DIR)/smash.pem
	openssl ca -config $(CONF_DIR)/ca2.cnf -batch -extensions client_ext \
		-in $(SIGN_REQS_DIR)/smash.pem -out $(CA2_CERTS_DIR)/smash.pem
	openssl x509 -req -days 365 -signkey $(KEYS_DIR)/smash.pem \
		-in $(SIGN_REQS_DIR)/smash.pem -out $(SELF_SIGNED_CERT_DIR)/smash.pem
	
	rm -rf $(CA1_DIR) $(CA2_DIR) $(SIGN_REQS_DIR) $(KEYS_DIR)/{ca1.pem,ca2.pem}
