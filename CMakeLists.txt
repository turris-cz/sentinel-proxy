cmake_minimum_required(VERSION 2.4.0)

project(sentinel-proxy)

file(GLOB SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

find_library(PAHOMQTTPP3 paho-mqttpp3)
find_library(PAHOMQTT3AS paho-mqtt3as)
find_library(ZMQ zmq)
find_package(OpenSSL)
target_link_libraries(${PROJECT_NAME} ${PAHOMQTTPP3})
target_link_libraries(${PROJECT_NAME} ${PAHOMQTT3AS})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${PROJECT_NAME} ${ZMQ})
