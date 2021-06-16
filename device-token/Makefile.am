bin_PROGRAMS += sentinel-device-token
lib_LTLIBRARIES += libsentinel-device-token.la


sentinel_device_token_SOURCES = \
	%reldir%/sentinel_device_token.c
sentinel_device_token_CFLAGS = \
	-isystem "$(srcdir)/include"
sentinel_device_token_LDADD = \
	libsentinel-device-token.la


libsentineldir = $(includedir)/sentinel
libsentinel_HEADERS = \
	include/device_token.h
libsentinel_device_token_la_SOURCES = \
	%reldir%/device_token.c
libsentinel_device_token_la_CFLAGS = \
	-isystem "$(srcdir)/include" \
	${libcrypto_CFLAGS} \
	${zlib_CFLAGS} \
	${CODE_COVERAGE_CFLAGS}
libsentinel_device_token_la_LDFLAGS = \
	${libcrypto_LIBS} \
	${zlib_LIBS} \
	${CODE_COVERAGE_LIBS} \
	-version-info 1:0:0


linted_files += \
	${sentinel_device_token_SOURCES} \
	${libsentinel_device_token_la_SOURCES}
