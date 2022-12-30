bin_PROGRAMS =
lib_LTLIBRARIES =
pkgconfig_DATA =
EXTRA_DIST =
linted_files =

ACLOCAL_AMFLAGS=-I .m4 -I m4

VALGRIND_EXTRA_ENVIRONMENT = export CK_FORK=no;

include proxy/Makefile.am
include device-token/Makefile.am


if ENABLE_LINTERS
include lint.am
endif

if ENABLE_TESTS
DISTCHECK_CONFIGURE_FLAGS = --enable-tests
include tests/Makefile.am
endif
