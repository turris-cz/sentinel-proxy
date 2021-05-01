bin_PROGRAMS = \
	sentinel-proxy \
	sentinel-device-token

lib_LTLIBRARIES = \
	libsentinel-device-token.la

libsentineldir = $(includedir)/sentinel
libsentinel_HEADERS = \
	device_token.h

libsentinel_device_token_la_SOURCES = \
	device_token.c
libsentinel_device_token_la_CFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(ZLIB_CFLAGS)
libsentinel_device_token_la_LDFLAGS = \
	$(LIBCRYPTO_LIBS) \
	$(ZLIB_LIBS) \
	-version-info 1:0:0

sentinel_proxy_SOURCES = \
	sentinel_proxy.c \
	proxy_conf.c \
	proxy_zmq.c \
	proxy_zmq_msg.c \
	proxy_mqtt.c \
	log.c
sentinel_proxy_CFLAGS = \
	$(LIBCONFIG_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBZMQ_CFLAGFS) \
	$(LIBEVENT_CFLAGS) \
	$(logc_CFLAGS) \
	$(logc_argp_CFLAGS)
sentinel_proxy_LDFLAGS = \
	$(LIBCONFIG_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBZMQ_LIBS) \
	$(LIBEVENT_LIBS) \
	$(logc_LIBS) \
	$(logc_argp_LIBS)
sentinel_proxy_LDADD = \
	libsentinel-device-token.la


sentinel_device_token_SOURCES = \
	sentinel_device_token.c
sentinel_device_token_LDADD = \
	libsentinel-device-token.la
