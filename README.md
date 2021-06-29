# Sentinel-proxy

It relays messages received over ZMQ to Sentinel server over MQTT.

## Dependencies

 - [libcrypto](https://github.com/openssl/openssl)
 - [libz](https://github.com/madler/zlib)
 - [czmq](https://github.com/zeromq/czmq)
 - [libconfig](https://github.com/hyperrealm/libconfig)
 - [libpaho-mqtt](https://github.com/eclipse/paho.mqtt.c)
 - [msgpack](https://github.com/msgpack/msgpack-c)
 - [logc](https://gitlab.nic.cz/turris/logc)
 - On non-glibc [argp-standalone](http://www.lysator.liu.se/~nisse/misc)

For build:
 - [autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)
 - [autoconf-archive](https://www.gnu.org/software/autoconf-archive/Introduction.html)
 - [libtool](https://www.gnu.org/software/libtool/)
 - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)

For tests:
 - [check](https://libcheck.github.io/check)
 - Optionally [valgrind](http://www.valgrind.org)

For linting:
 - [cppcheck](https://github.com/danmar/cppcheck)

For code coverage:
 - [lcov](http://ltp.sourceforge.net/coverage/lcov.php)

## Build instructions for Autotools

```
./configure
make
```
Use `./configure --help` to see all configure options

Subsequent installation can be done with `make install`.

When you do not use distribution archive then you have to run initially
```
./bootstrap
```

## Running tests

### Unit

Unit tests are in directory `tests/unit` . To run all tests you can just simply run:
`make check`

You can also run tests with Valgrind:
`make check-valgrind`

To run checks with just one specific Valgrind test such as memtest you can run:
`make check-valgrind-memcheck`

Source code of project can be also linted with cppcheck by running:
`make lint`

There is also possibility to generate code coverage for test cases. To do so you
can run:
`make check-code-coverage`

### Manual
For overall not yet automated tests go to `test/manual` and see `README.md`.

## Running and configuration

```
sentinel-proxy [--ca-cert=ca_cert_file] [--cl-cert=client_cert_file]
[--config=config_file] [--cl-key=client_key_file] [--port=port]
[--zmq-sock=zmq_socket_path] [--server=server]
[--token=device_token] 
```

All parameters except device token have default values.
These values can be overridden by values loaded from config file and CLI options. 
Device token can be only specified either by CLI option or in configuration file.
For information about device token and how to generate it please see next section.  
The priorities of configuration are following:
CLI options > configuration file > default values.
CLI options have higher priority than conf. file, which has in turn higher
priority than default configuration.

Configuration file absence is silently ignored until it is explicitly passed as
a CLI option. In such a case it's absence would end up in error state.

# Sentinel-device-token

It is a library and a small CLI utility which purpose is to generate and validate
device token. Device token is 64 hex character long string used to uniquely
and anonymously identify a user of Sentinel for purposes of following provided
services.

To generate a new device token and print it to standard output run:
```
sentinel-device-token -c
```

To validate a device token run:
```
sentinel-device-token -v paste_here_your_token
```
