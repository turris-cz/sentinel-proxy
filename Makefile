all: proxy.cpp
	$(CXX) proxy.cpp -g --std=c++11 $(CXXFLAGS) $(LDFLAGS) -lpaho-mqtt3cs -lzmq -lssl -lcrypto -lz -o sentinel-proxy

clean:
	rm -f sentinel-proxy
