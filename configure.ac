AC_INIT([sentinel-proxy], [1.4], [tech.support@turris.cz])
AC_CONFIG_MACRO_DIRS([.m4])
AC_CONFIG_AUX_DIR([.aux])

AM_INIT_AUTOMAKE([
  foreign silent-rules subdir-objects
  -Wall -Wno-portability
  dist-zip dist-xz
])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_GNU_SOURCE
AM_PROG_AR
LT_INIT
PKG_INSTALLDIR

AX_CHECK_COMPILE_FLAG([-std=c11], , AC_MSG_ERROR([Compiler with C11 standard support is required]))
AX_APPEND_FLAG([-std=c11])

PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([zlib], [zlib])
PKG_CHECK_MODULES([libczmq], [libczmq])
PKG_CHECK_MODULES([libconfig], [libconfig])
PKG_CHECK_MODULES([msgpack], [msgpack])
PKG_CHECK_MODULES([logc], [logc >= 0.3.0 logc_argp])
PKG_CHECK_MODULES([logc_czmq], [libczmq_logc])
AC_CHECK_LIB(paho-mqtt3cs, MQTTClient_create, , AC_MSG_ERROR([Cannot find libpaho-mqtt]))
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <argp.h>],[argp_parse(0,1,NULL,0,0,0);])],,
  [argp_standalone_required="yes"]
)
AS_IF([test "$argp_standalone_required" = "yes"],
  AC_CHECK_LIB([argp], [argp_parse], , AC_MSG_ERROR([Unable to find libargp])))


dnl Options from environment
AC_ARG_VAR([defconfigfile], [default path to the configuration file])
AS_IF([test -z "${defconfigfile}"],
  [defconfigfile="/tmp/etc/sentinel-proxy.cfg"])
AC_DEFINE_UNQUOTED([DEFAULT_CONFIG_FILE], ["${defconfigfile}"],
  [Default path to the configuration file])

AC_ARG_VAR([defserver], [default Sentinel server address])
AS_IF([test -z "${defserver}"], [defserver="sentinel.turris.cz"])
AC_DEFINE_UNQUOTED([DEFAULT_SERVER], ["${defserver}"],
	[Default Sentinel server adress])

AC_ARG_VAR([defport], [default Sentinel server port])
AS_IF([test -z "${defport}"], [defport=1883])
AC_DEFINE_UNQUOTED([DEFAULT_PORT], [${defport}],
	[Default Sentinel server port])

AC_ARG_VAR([defzmqsockpath], [default path to ZMQ socket])
AS_IF([test -z "${defzmqsockpath}"],
  [defzmqsockpath="ipc:///tmp/sentinel_pull.sock"])
AC_DEFINE_UNQUOTED([DEFAULT_ZMQ_SOCK_PATH], ["${defzmqsockpath}"],
  [Default path to local socket])

AC_ARG_VAR([defcacertfile], [default path to CA certificate file])
AS_IF([test -z "${defcacertfile}"], [defcacertfile="/etc/sentinel/ca.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_CA_CERT_FILE], ["${defcacertfile}"],
  [Default path to CA certificate file])

AC_ARG_VAR([defmqttclientcertfile], [default path to MQTT client certificate file])
AS_IF([test -z "${defmqttclientcertfile}"],
  [defmqttclientcertfile="/etc/sentinel/mqtt_cert.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_MQTT_CLIENT_CERT_FILE], ["${defmqttclientcertfile}"],
  [Default path to client certificate file])

AC_ARG_VAR([defmqttclientkeyfile], [default path to client key file])
AS_IF([test -z "${defmqttclientkeyfile}"],
  [defmqttclientkeyfile="/etc/sentinel/mqtt_key.pem"])
AC_DEFINE_UNQUOTED([DEFAULT_MQTT_CLIENT_KEY_FILE], ["${defmqttclientkeyfile}"],
  [Default path to client key file])


dnl Tests
AC_ARG_ENABLE([tests], AC_HELP_STRING([--enable-tests], [Whether to enable unit tests]))
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])
AS_IF([test "x$enable_tests" = "xyes"], [
  PKG_CHECK_MODULES([check], [check >= 0.11])
  AC_REQUIRE_AUX_FILE([tap-driver.sh])
])
AX_VALGRIND_CHECK

dnl Linters
AC_ARG_ENABLE([linters], AC_HELP_STRING([--enable-linters], [Whether to enable code linting support (cppcheck)]))
AM_CONDITIONAL([ENABLE_LINTERS], [test "x$enable_linters" = "xyes"])
AS_IF([test "x$enable_linters" = "xyes"], [
  AC_PATH_PROG([CPPCHECK], [cppcheck])
  AS_IF([test -z "$CPPCHECK" ], AC_MSG_ERROR([Missing linter cppcheck]))
])

dnl Coverage
AX_CODE_COVERAGE

AC_CONFIG_FILES([Makefile device-token/libsentinel-device-token.pc])

AC_OUTPUT
