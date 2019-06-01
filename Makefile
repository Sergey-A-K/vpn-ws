VERSION=0.2

SHARED_OBJECTS=src/error.o src/tuntap.o src/memory.o src/bits.o src/base64.o src/exec.o src/websocket.o src/utils.o
OBJECTS=src/main.o $(SHARED_OBJECTS) src/socket.o src/event.o src/io.o src/uwsgi.o src/sha1.o src/macmap.o

CFLAGS+= -O3
LIBS+=-lcrypto -lgnutls

# -Werror

all: vpn-ws vpn-ws-client

src/%.o: src/%.c src/vpn-ws.h
	$(CC) $(CFLAGS) -Wall  -g -c -o $@ $<

vpn-ws: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall  -g -o vpn-ws $(OBJECTS) $(SERVER_LIBS)

vpn-ws-static: $(OBJECTS)
	$(CC) -static $(CFLAGS) $(LDFLAGS) -Wall  -g -o vpn-ws $(OBJECTS) $(SERVER_LIBS)

vpn-ws-client: src/client.o src/ssl.o $(SHARED_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall  -g -o vpn-ws-client src/client.o src/ssl.o $(SHARED_OBJECTS) $(LIBS)

linux-tarball: vpn-ws-static
	tar zcvf vpn-ws-$(VERSION)-linux-$(shell uname -m).tar.gz vpn-ws

osxpkg: vpn-ws vpn-ws-client
	mkdir -p dist/usr/bin
	cp vpn-ws vpn-ws-client dist/usr/bin
	pkgbuild --root dist --identifier it.unbit.vpn-ws vpn-ws-$(VERSION)-osx.pkg

clean:
	rm -rf src/*.o vpn-ws vpn-ws-client
