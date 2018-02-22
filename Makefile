all: proxy.c
	$(CC) proxy.c $(CXXFLAGS) $(LDFLAGS) -lpaho-mqtt3cs -lczmq -lz -lssl -lcrypto -o sentinel-proxy

clean:
	rm -f sentinel-proxy
