TESTS += %reldir%/unittests

check_PROGRAMS += %reldir%/unittests

%canon_reldir%_unittests_SOURCES = \
	${proxy_sources} \
	%reldir%/unittests.c \
	%reldir%/con_peer.c \
	%reldir%/con_peer_list.c \
	%reldir%/proxy_conf.c \
	%reldir%/proxy_zmq.c \
	%reldir%/proxy_mqtt.c

%canon_reldir%_unittests_CFLAGS = \
	$(sentinel_proxy_CFLAGS) \
	$(check_CFLAGS)
%canon_reldir%_unittests_LDFLAGS = \
	$(sentinel_proxy_LDFLAGS) \
	$(check_LIBS)
%canon_reldir%_unittests_LDADD = \
	$(sentinel_proxy_LDADD)

AM_TESTS_ENVIRONMENT = export DATA_DIR="$(abs_top_srcdir)/tests/unit";

dist-hook:
	cp -rf "%reldir%/test_cert.pem" "$(distdir)/%reldir%/"
	cp -rf "%reldir%/test_config.cfg" "$(distdir)/%reldir%/"
