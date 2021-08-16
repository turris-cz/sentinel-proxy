# Wee need unstable for now because of check version
FROM debian:bullseye

ENV HOME /root

RUN \
  apt-get update && \
  apt-get -y upgrade && \
  apt-get -y install --no-install-recommends \
    autoconf autoconf-archive automake libtool cmake \
    make pkg-config gcc gperf \
    git ca-certificates \
    libssl-dev zlib1g-dev libczmq-dev libconfig-dev libmsgpack-dev \
    check cppcheck valgrind lcov \
    zip xz-utils \
    && \
  apt-get clean

# Compile paho-mqtt
RUN \
  git clone --branch "v1.3.9" https://github.com/eclipse/paho.mqtt.c.git && \
  cd paho.mqtt.c && \
  cmake -Bbuild -H. -DPAHO_WITH_SSL=ON && \
  cmake --build build/ --target install && ldconfig && \
  cd .. && \
  rm -rf paho.mqtt.c

# Compile logc
RUN \
  git clone --branch "v0.2.1" "https://gitlab.nic.cz/turris/logc.git" && \
  cd logc && \
  ./bootstrap && ./configure --prefix=/usr && \
  make install && \
  cd .. && \
  rm -rf logc



CMD [ "bash" ]

# vim: ft=dockerfile
