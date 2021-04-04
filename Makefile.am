lib_LTLIBRARIES = \
	libsentinel-device-token.la
libsentinel_device_token_la_LDFLAGS = -version-info 1:0:0

libsentineldir = $(includedir)/sentinel
libsentinel_HEADERS = \
	device_token.h


bin_PROGRAMS = \
	sentinel-proxy \
	sentinel-device-token

sentinel_proxy_SOURCES = \
	sentinel_proxy.c \
	proxy_conf.c \
	proxy_zmq.c \
	proxy_zmq_msg.c\
	log.c
sentinel_device_token_SOURCES = \
	sentinel_device_token.c
libsentinel_device_token_la_SOURCES = \
	device_token.c

sentinel_proxy_CFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(ZLIB_CFLAGS) \
	$(LIBZMQ_CFLAGFS) \
	$(LIBCONFIG_CFLAGS) \
	$(LIBEVENT_CFLAGS) \
	$(logc_CFLAGS) \
	$(logc_argp_CFLAGS)
sentinel_proxy_LDFLAGS = \
	$(LIBCRYPTO_LIBS) \
	$(ZLIB_LIBS) \
	$(LIBZMQ_LIBS) \
	$(LIBCONFIG_LIBS) \
	$(LIBEVENT_LIBS) \
	$(logc_LIBS) \
	$(logc_argp_LIBS)
sentinel_proxy_LDADD = \
	libsentinel-device-token.la
sentinel_device_token_CFLAGS = \
	$(ZLIB_CFLAGS)
sentinel_device_token_LDFLAGS = \
	$(ZLIB_LIBS)
sentinel_device_token_LDADD = \
	libsentinel-device-token.la
