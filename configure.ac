AC_INIT([sentinel-proxy], [1.2.1], [])

AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])
AC_PROG_CC
AM_PROG_AR
LT_INIT

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
PKG_CHECK_MODULES([ZLIB], [zlib])
PKG_CHECK_MODULES([LIBCZMQ], [libczmq])
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
AC_CHECK_LIB(paho-mqtt3cs, MQTTClient_create, , AC_MSG_ERROR([Cannot find libpaho-mqtt]))

dnl Check if we have argp available from our libc otherwise check for standalone version
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([#include <argp.h>], [argp_parse(0,1,NULL,0,0,0);])],,
	AC_CHECK_LIB([argp], [argp_parse], , [echo "Cannot find libargp"; exit -1])
)

# set default options
AC_ARG_VAR([defconfig], [default path to the configuration file])
AS_IF([test -z "${defconfig}"], [defconfig="/tmp/etc/sentinel-proxy.cfg"])
AC_DEFINE_UNQUOTED([DEFAULT_CONFIG_FILE], ["${defconfig}"],
	[Default path to the configuration file])


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
