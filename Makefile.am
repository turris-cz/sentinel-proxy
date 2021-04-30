bin_PROGRAMS = \
	sentinel-proxy \
	sentinel-device-token
lib_LTLIBRARIES = \
	libsentinel-device-token.la

libsentineldir = $(includedir)/sentinel
libsentinel_HEADERS = \
	device_token.h

sentinel_proxy_SOURCES = \
	sentinel_proxy.c \
	proxy_conf.c
sentinel_device_token_SOURCES = \
	sentinel_device_token.c
libsentinel_device_token_la_SOURCES = \
	device_token.c


libsentinel_device_token_la_CFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(ZLIB_CFLAGS)
libsentinel_device_token_la_LDFLAGS = \
	$(LIBCRYPTO_LIBS) \
	$(ZLIB_LIBS) \
	-version-info 1:0:0

sentinel_proxy_CFLAGS = \
	$(LIBCZMQ_CFLAGFS) \
	$(LIBCONFIG_CFLAGS) \
	$(libsentinel_device_token_la_CFLAGS)
sentinel_proxy_LDFLAGS = \
	$(LIBCZMQ_LIBS) \
	$(LIBCONFIG_LIBS)
sentinel_proxy_LDADD = \
	libsentinel-device-token.la

sentinel_device_token_CFLAGS = \
	$(libsentinel_device_token_la_CFLAGS)
sentinel_device_token_LDADD = \
	libsentinel-device-token.la
