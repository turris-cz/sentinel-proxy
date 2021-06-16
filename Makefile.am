bin_PROGRAMS =
lib_LTLIBRARIES =
EXTRA_DIST =
linted_files =


include proxy/Makefile.am
include device-token/Makefile.am


if ENABLE_LINTERS
include lint.am
endif

if ENABLE_TESTS
DISTCHECK_CONFIGURE_FLAGS = --enable-tests
include tests/Makefile.am
endif
