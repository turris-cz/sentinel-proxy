# Sentinel-proxy

Sentinel-proxy sends messages received over ZMQ to Sentinel server (over MQTT).

## Dependencies

 - [czmq](https://github.com/zeromq/czmq)
 - [libz](https://github.com/madler/zlib)
 - [libcrypto](https://github.com/openssl/openssl)
 - [libpaho-mqtt](https://github.com/eclipse/paho.mqtt.c)
 - [libconfig](https://github.com/hyperrealm/libconfig)

## Build dependencies

 - autotools
 - [libtool](https://www.gnu.org/software/libtool/)
 - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)

## Build instructions for Autotools

```
./bootstrap
./cofigure
make
# optionally:
make install
```

Use `./configure --help` to see all configure options

## Run

```
sentinel_proxy [-S server] [-s local_socket] [--ca CA_file] [--cert cert_file] \
[--key key_file] [--token device_token] [--config config_file]
```
All parameters except device token have default values. These values can be
overridden by values loaded from config file and subsequently by cli options.

Config file absence is silently ignored until it is explicitly passed as a
cli option. In such a case it's absence would end up in error state.
