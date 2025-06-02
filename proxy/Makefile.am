bin_PROGRAMS += sentinel-proxy


proxy_sources = \
	%reldir%/common.h \
	%reldir%/log.h \
	%reldir%/log.c \
	%reldir%/proxy_conf.h \
	%reldir%/proxy_conf.c \
	%reldir%/proxy_mqtt.h \
	%reldir%/proxy_mqtt.c \
	%reldir%/proxy_zmq.h \
	%reldir%/proxy_zmq.c \
	%reldir%/last_msg_list.c \
	%reldir%/last_msg_list.h

sentinel_proxy_SOURCES = \
	%reldir%/sentinel_proxy.c \
	${proxy_sources}
sentinel_proxy_CFLAGS = \
	-isystem "$(srcdir)/include" \
	${libcrypto_CFLAGS} \
	${libczmq_CFLAGFS} \
	${libconfig_CFLAGS} \
	${msgpack_CFLAGS} \
	${logc_CFLAGS} \
	${logc_czmq_CFLAGS} \
	${CODE_COVERAGE_CFLAGS}
sentinel_proxy_LDFLAGS = \
	${libconfig_LIBS} \
	${libcrypto_LIBS} \
	${libczmq_LIBS} \
	${msgpack_LIBS} \
	${logc_LIBS} \
	${logc_czmq_LIBS} \
	${CODE_COVERAGE_LIBS}
sentinel_proxy_LDADD = \
	libsentinel-device-token.la


linted_files += ${sentinel_proxy_SOURCES}
