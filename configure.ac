AC_INIT([sentinel-proxy], [1.3.1], [])

AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])
AC_PROG_CC
AM_PROG_AR
LT_INIT

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
PKG_CHECK_MODULES([ZLIB], [zlib])
PKG_CHECK_MODULES([LIBZMQ], [libzmq])
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
PKG_CHECK_MODULES([msgpack], [msgpack])
PKG_CHECK_MODULES([LIBEVENT], [libevent])
PKG_CHECK_MODULES([logc], [logc logc_argp])
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

AC_ARG_VAR([defserver], [default Sentinel server])
AS_IF([test -z "${defserver}"], [defserver="ssl://sentinel.turris.cz:1883"])
AC_DEFINE_UNQUOTED([DEFAULT_SERVER], ["${defserver}"],
	[Default Sentinel server])

AC_ARG_VAR([defsocket], [default path to local socket])
AS_IF([test -z "${defsocket}"], [defsocket="ipc:///tmp/sentinel_pull.sock"])
AC_DEFINE_UNQUOTED([DEFAULT_LOCAL_SOCKET], ["${defsocket}"],
	[Default path to local socket])

AC_ARG_VAR([defca], [default path to CA certificate file])
AS_IF([test -z "${defca}"], [defca="/etc/sentinel/ca.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_CA_FILE], ["${defca}"],
	[Default path to CA certificate file])

AC_ARG_VAR([defcert], [default path to client certificate file])
AS_IF([test -z "${defcert}"], [defcert="/etc/sentinel/mqtt_cert.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_CERT_FILE], ["${defcert}"],
	[Default path to client certificate file])

AC_ARG_VAR([defkey], [default path to client key file])
AS_IF([test -z "${defkey}"], [defkey="/etc/sentinel/mqtt_key.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_KEY_FILE], ["${defkey}"],
	[Default path to client key file])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
