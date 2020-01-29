AC_INIT([sentinel-proxy], [1.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
		  Makefile
		   ])
AC_CHECK_LIB(crypto, PEM_read_X509, , [echo "Cannot find libcrypto"; exit -1])
AC_CHECK_LIB(z, compress2, , [echo "Cannot find libz"; exit -1])
AC_CHECK_LIB(czmq, zsock_new, , [echo "Cannot find libczmq"; exit -1])
AC_CHECK_LIB(paho-mqtt3cs, MQTTClient_create, , [echo "Cannot find libpaho-mqtt"; exit -1])

dnl Check if we have argp available from our libc otherwise check for standalone version
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([#include <argp.h>], [argp_parse(0,1,NULL,0,0,0);])],,
	AC_CHECK_LIB([argp], [argp_parse], , [echo "Cannot find libargp"; exit -1])
)

AC_OUTPUT
